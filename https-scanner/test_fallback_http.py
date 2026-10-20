"""Local-only integration tests: no public hosts, proxies, DNS, or Docker required."""
import asyncio
from contextlib import redirect_stdout, suppress
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived
from h2.exceptions import ProtocolError
from hyperframe.frame import DataFrame

import fallback_http as f


class H3Server(QuicConnectionProtocol):
    seen = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        for e in self.http.handle_event(event):
            if isinstance(e, HeadersReceived):
                self.seen.append(dict(e.headers))
                self.http.send_headers(e.stream_id, [(b":status", b"103"), (b"link", b"</x>; rel=preload")])
                self.http.send_headers(e.stream_id, [(b":status", b"403"), (b"set-cookie", b"a=1"),
                    (b"set-cookie", b"b=2"), (b"server", b"local-h3")], end_stream=True)
                self.transmit()


class FallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.servers = []
        self.handlers = set()
        key = ec.generate_private_key(ec.SECP256R1())
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local CA")])
        self.ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=5))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
        # Intentionally expired and for another hostname.
        self.cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong.invalid")]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(2)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=4))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("wrong.invalid")]), critical=False)
            .sign(key, hashes.SHA256()))
        self.cert_path, self.key_path = self.root / "server.pem", self.root / "server.key"
        self.cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM) + self.ca.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.c = f.Config(output=self.root / "cert_http", failures_output=self.root / "failures",
                          rate=0, timeout=2, connect_timeout=.3, tls_timeout=.4, header_timeout=.5)
        self.task = f.Task(1, "_measurement_.invalid", ["127.0.0.1"])
        self.sni = []
        self.seen = []

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            if hasattr(server, "wait_closed"):
                await server.wait_closed()
        for handler in self.handlers:
            handler.cancel()
        if self.handlers:
            await asyncio.gather(*self.handlers, return_exceptions=True)
        await asyncio.sleep(.02)

    async def tcp_server(self, mode="http1", host="127.0.0.1"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_path, self.key_path)
        context.set_alpn_protocols(["h2"] if mode != "http1" else ["http/1.1"])
        context.set_servername_callback(lambda connection, name, _: self.sni.append(name))

        async def handler(reader, writer):
            self.handlers.add(asyncio.current_task())
            try:
                if mode == "http1":
                    data = await reader.readuntil(b"\r\n\r\n")
                    self.seen.append(data)
                    writer.write(b"HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\n"
                        b"HTTP/1.1 302 Found\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nLocation: https://elsewhere.invalid/\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                elif mode == "bad_h2":
                    await reader.read(4096)
                    server = H2Connection(config=H2Configuration(client_side=False))
                    server.initiate_connection()
                    frame = DataFrame(1)
                    frame.data = b"bad body before headers"
                    writer.write(server.data_to_send() + frame.serialize())
                    await writer.drain()
                elif mode == "no_headers":
                    await reader.read(4096)
                elif mode == "timeout":
                    await asyncio.sleep(2)
                else:
                    server = H2Connection(config=H2Configuration(client_side=False, header_encoding=None))
                    server.initiate_connection()
                    writer.write(server.data_to_send())
                    await writer.drain()
                    while True:
                        data = await reader.read(65536)
                        if not data:
                            return
                        for event in server.receive_data(data):
                            if isinstance(event, RequestReceived):
                                self.seen.append(dict(event.headers))
                                server.send_headers(event.stream_id, [(b":status", b"103"), (b"link", b"</x>")])
                                server.send_headers(event.stream_id, [(b":status", b"404"),
                                    (b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")], end_stream=True)
                        writer.write(server.data_to_send())
                        await writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, ProtocolError):
                pass
            finally:
                writer.transport.abort()

        server = await asyncio.start_server(handler, host, 0, ssl=context)
        self.servers.append(server)
        self.c.port = server.sockets[0].getsockname()[1]
        return server

    async def quic_server(self):
        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(self.cert_path, self.key_path)
        H3Server.seen = []
        server = await serve("127.0.0.1", 0, configuration=config, create_protocol=H3Server)
        self.servers.append(server)
        self.c.port = server._transport.get_extra_info("sockname")[1]

    async def test_http1_capture_sni_headers_chain_no_dns_no_validation(self):
        await self.tcp_server()
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", side_effect=AssertionError("DNS used")):
            o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/1.1", self.c, f.RateGate(0))
        self.assertTrue(o.http["success"], o.http)
        self.assertEqual(o.http["response"]["status_code"], 302)
        self.assertEqual(o.http["response"]["headers"]["set-cookie"], ["a=1", "b=2"])
        self.assertIn("Set-Cookie: a=1", o.http["response"]["raw_headers"])
        self.assertEqual(o.http["informational_responses"][0]["status_code"], 103)
        self.assertEqual(o.http["certificate_count"], 2)
        self.assertFalse(o.tls["verification_performed"])
        self.assertEqual(self.sni, [self.task.domain])
        self.assertIn(f"Host: {self.task.domain}:{self.c.port}".encode(), self.seen[0])

    async def test_http2_independent_stack(self):
        await self.tcp_server("http2")
        o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/2", self.c, f.RateGate(0))
        self.assertTrue(o.http["success"], o.http)
        self.assertEqual(o.http["response"]["protocol"], "HTTP/2.0")
        self.assertEqual(o.http["response"]["headers"]["set-cookie"], ["a=1", "b=2"])
        self.assertEqual(o.http["certificate_count"], 2)

    async def test_bad_http2_retains_certificate_without_final_headers(self):
        await self.tcp_server("bad_h2")
        o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/2", self.c, f.RateGate(0))
        self.assertFalse(o.http["success"])
        self.assertEqual(o.http["status"], "HTTP_PROTOCOL_ERROR", o.http)
        self.assertNotIn("response", o.http)
        self.assertEqual(o.http["certificate_count"], 2)
        self.assertTrue(o.leaf)

    async def test_http3_direct_udp_capture(self):
        await self.quic_server()
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", side_effect=AssertionError("DNS used")):
            o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/3", self.c, f.RateGate(0))
        self.assertTrue(o.http["success"], o.http)
        self.assertEqual(o.http["response"]["protocol"], "HTTP/3")
        self.assertEqual(o.http["response"]["status_code"], 403)
        self.assertEqual(o.http["response"]["headers"]["set-cookie"], ["a=1", "b=2"])
        self.assertEqual(o.http["certificate_count"], 2)
        self.assertEqual(H3Server.seen[0][b":authority"], f"{self.task.domain}:{self.c.port}".encode())

    async def test_tcp_refused_still_tries_quic_and_promotes_then_skips(self):
        await self.quic_server()  # Same port has a UDP server and no TCP listener.
        directory = f.target_dir(self.c.output, self.task)
        directory.mkdir(parents=True)
        old = {"success": False, "status": "CONNECTION_REFUSED"}
        f.write_json(directory / "http.json", old)
        failure = f.target_dir(self.c.failures_output, self.task)
        f.write_json(failure / "errors.json", old)
        status, attempts = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertEqual(status, "OK", attempts)
        self.assertEqual([a["protocol"] for a in attempts], ["HTTP/1.1", "HTTP/3"])
        self.assertEqual(f.read_json(directory / "go_original/http.json"), old)
        self.assertEqual(f.read_json(directory / "http.json")["response"]["protocol"], "HTTP/3")
        self.assertFalse((failure / "errors.json").exists())
        with patch.object(f, "probe_attempt", side_effect=AssertionError("reconnected")):
            status, _ = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertEqual(status, "SKIPPED_SUCCESS")

    async def test_ip_fallback_and_stop_before_later_ip(self):
        await self.tcp_server()
        self.task.ips = ["127.0.0.2", "127.0.0.1", "127.0.0.3"]
        self.c.tls_timeout = .08
        status, attempts = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertEqual(status, "OK", attempts)
        self.assertEqual([a["protocol"] for a in attempts], ["HTTP/1.1", "HTTP/3", "HTTP/1.1"])
        self.assertNotIn("127.0.0.3", [a["ip"] for a in attempts])

    async def test_http2_fallback_after_http1_failure(self):
        await self.tcp_server("http2")
        status, attempts = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertEqual(status, "OK", attempts)
        self.assertEqual([a["protocol"] for a in attempts], ["HTTP/1.1", "HTTP/2"])

    async def test_partial_go_certificate_preserved_and_failures_resume(self):
        await self.tcp_server("no_headers")
        self.c.tls_timeout = .08
        directory = f.target_dir(self.c.output, self.task)
        directory.mkdir(parents=True)
        (directory / "certificate.pem").write_bytes(b"original-go-cert")
        status, attempts = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertNotEqual(status, "OK")
        self.assertEqual((directory / "certificate.pem").read_bytes(), b"original-go-cert")
        self.assertTrue((directory / "python_fallback/certificate.pem").stat().st_size)
        failure = f.target_dir(self.c.failures_output, self.task) / "errors_python.json"
        self.assertTrue(f.read_json(failure)["certificate_obtained"])
        with patch.object(f, "probe_attempt", side_effect=AssertionError("reconnected")):
            result, _ = await f.probe_domain(self.task, self.c, f.RateGate(0))
        self.assertEqual(result, "SKIPPED_FAILURE")

    async def test_timeout_status_and_partial_certificate(self):
        await self.tcp_server("timeout")
        self.c.header_timeout = .05
        o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/1.1", self.c, f.RateGate(0))
        self.assertEqual(o.http["status"], "TIMEOUT")
        self.assertTrue(o.leaf)

    async def test_ipv6(self):
        try:
            await self.tcp_server(host="::1")
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        o = await f.probe_attempt(self.task, "::1", "HTTP/1.1", self.c, f.RateGate(0))
        self.assertTrue(o.http["success"], o.http)

    async def test_cancellation_does_not_mark_domain_complete(self):
        await self.tcp_server("timeout")
        task = asyncio.create_task(f.probe_domain(self.task, self.c, f.RateGate(0)))
        await asyncio.sleep(.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        directory = f.target_dir(self.c.output, self.task)
        self.assertFalse((directory / "python_fallback/fallback.json").exists())
        self.assertTrue(list((directory / "python_fallback").glob("interrupted-*/certificate.pem")))

    async def test_run_summary_and_success_skip(self):
        await self.tcp_server()
        o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/1.1", self.c, f.RateGate(0))
        f.save_observation(f.target_dir(self.c.output, self.task), o)
        self.c.input = self.root / "input.jsonl"
        self.c.input.write_text(json.dumps({"rank": 1, "domain": self.task.domain, "ips": self.task.ips})
            + "\n" + json.dumps({"rank": 2, "domain": "second.invalid", "ip": "127.0.0.1"}) + "\n")
        with redirect_stdout(io.StringIO()):
            result = await f.run(self.c)
        self.assertEqual(result, 0)
        summary_path = next((self.c.output / "_runs").glob("python-*/summary.json"))
        summary = f.read_json(summary_path)
        self.assertEqual(summary["domain_status_counts"], {"SKIPPED_SUCCESS": 1, "OK": 1})
        self.assertEqual(summary["attempt_status_counts"], {"HTTP/1.1:OK": 1})
        self.assertEqual(len(self.seen), 2)

    async def test_header_limit_keeps_certificate(self):
        await self.tcp_server()
        self.c.max_header_bytes = 30  # Lower than CLI minimum to exercise parser guard.
        o = await f.probe_attempt(self.task, "127.0.0.1", "HTTP/1.1", self.c, f.RateGate(0))
        self.assertEqual(o.http["status"], "HEADER_LIMIT", o.http)
        self.assertTrue(o.leaf)

    def test_certificate_metadata_error_does_not_drop_collection(self):
        o = f.new_observation(self.task, self.task.ips[0], "HTTP/3", self.c)
        with patch.object(f, "metadata", side_effect=ValueError("unusual metadata")):
            o.certificates([self.cert])
        self.assertTrue(o.leaf)
        self.assertEqual(o.http["certificate_count"], 1)
        self.assertIn("metadata_error", o.tls["certificates"][0])

    async def test_quic_preferred_address_not_followed(self):
        class Transport:
            def sendto(self, data, addr):
                raise AssertionError("sent a packet to another endpoint")
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        protocol = f.H3Client(f.QuicConnection(configuration=config),
                             f.new_observation(self.task, "127.0.0.1", "HTTP/3", self.c), self.c)
        f.FixedPeerTransport(Transport(), protocol).sendto(b"test", ("127.0.0.2", self.c.port))
        self.assertEqual(protocol.response_ready.result().status, "QUIC_ERROR")

    def test_input_grouping_validation_and_shards(self):
        path = self.root / "input.jsonl"
        rows = [{"rank": 10001, "domain": "_TEST_.invalid.", "ips": ["127.0.0.1"]},
                {"rank": 10001, "domain": "_test_.invalid", "ip": "::1"},
                {"rank": 10001, "domain": "other.invalid", "ip": "127.0.0.1"},
                {"rank": 1, "domain": "../escape", "ip": "127.0.0.1"}]
        path.write_text("\n".join(json.dumps(x) for x in rows))
        errors = io.StringIO()
        tasks = f.read_tasks(path, errors)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].ips, ["127.0.0.1", "::1"])
        self.assertEqual(len(errors.getvalue().splitlines()), 2)
        self.assertEqual(f.target_dir(self.root, tasks[0]).parent.name, "001")


if __name__ == "__main__":
    unittest.main()
