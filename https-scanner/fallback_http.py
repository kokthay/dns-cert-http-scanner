"""Retry incomplete Go observations using independent HTTP/1.1, /2 and /3 clients.

No certificate verification, name resolution, redirects, or body collection.
Run after the Go scanner has stopped; never run writers on the same output concurrently.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
import json
import logging
import math
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import sys
import tempfile
import time

import h11
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (ConnectionTerminated as H2Terminated,
                       InformationalResponseReceived, ResponseReceived, StreamReset)
from h2.exceptions import ProtocolError as H2ProtocolError
from h2.settings import SettingCodes
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamReset as QuicReset
from cryptography import x509
from cryptography.hazmat.primitives import serialization

SCHEMA = "https-python-fallback-v1"
PROTOCOLS = ("HTTP/1.1", "HTTP/2", "HTTP/3")
FILES = ("http.json", "tls.json", "certificate.pem", "chain.pem")


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Config:
    input: Path = Path("/work/results/websites_ips.jsonl")
    output: Path = Path("/work/results/cert_http")
    failures_output: Path = Path("/work/results/failures_certHTTP")
    workers: int = 50
    rate: float = 25
    timeout: float = 20
    connect_timeout: float = 5
    tls_timeout: float = 5
    header_timeout: float = 10
    max_header_bytes: int = 1048576
    port: int = 443
    limit: int = 0
    user_agent: str = "ResearchHTTPSScanner/1.0"
    retry_failed: bool = False
    progress_every: float = 10


@dataclass
class Task:
    rank: int
    domain: str
    ips: list[str] = field(default_factory=list)


class ProbeError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class RateGate:
    def __init__(self, rate):
        self.interval = 1 / rate if rate else 0
        self.next = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self.lock:
            await asyncio.sleep(max(0, self.next - time.monotonic()))
            self.next = time.monotonic() + self.interval


def target_dir(root, task):
    name = f"{task.rank:07d}-{task.domain}"
    if len(name) > 255:
        digest = hashlib.sha256(task.domain.encode()).hexdigest()[:16]
        name = f"{task.rank:07d}-{task.domain[:220]}-{digest}"
    return root / f"{(task.rank - 1) // 10000:03d}" / name


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".python-scan-", delete=False) as f:
        temporary = Path(f.name)
        try:
            f.write(data)
            f.flush()
            temporary.chmod(0o644)
            f.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode())


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def classify(error, stage):
    if isinstance(error, ProbeError):
        return error.status
    if isinstance(error, TimeoutError):
        return "TIMEOUT"
    if "header list" in str(error).lower() and "larger" in str(error).lower():
        return "HEADER_LIMIT"
    if isinstance(error, (h11.RemoteProtocolError, H2ProtocolError)):
        return "HTTP_PROTOCOL_ERROR"
    if isinstance(error, asyncio.LimitOverrunError):
        return "HEADER_LIMIT"
    if isinstance(error, (EOFError, asyncio.IncompleteReadError)):
        return "CONNECTION_CLOSED"
    if isinstance(error, OSError):
        mapping = {errno.ECONNREFUSED: "CONNECTION_REFUSED", errno.ECONNRESET: "CONNECTION_RESET",
                   errno.ENETUNREACH: "NETWORK_UNREACHABLE", errno.EHOSTUNREACH: "HOST_UNREACHABLE",
                   errno.EADDRNOTAVAIL: "ADDRESS_UNAVAILABLE", errno.EAFNOSUPPORT: "ADDRESS_UNAVAILABLE",
                   errno.EPIPE: "CONNECTION_CLOSED"}
        if error.errno in mapping:
            return mapping[error.errno]
    if "application protocol" in str(error).lower():
        return "ALPN_UNSUPPORTED"
    if stage in ("tls", "quic_handshake"):
        return "TLS_HANDSHAKE_ERROR"
    return "CONNECTION_ERROR" if stage == "tcp" else "HTTP_ERROR"


def metadata(cert, index):
    def extension(kind):
        try:
            return cert.extensions.get_extension_for_class(kind).value
        except x509.ExtensionNotFound:
            return None
    san = extension(x509.SubjectAlternativeName)
    basic = extension(x509.BasicConstraints)
    policies = extension(x509.CertificatePolicies)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"index": index, "sha256": hashlib.sha256(der).hexdigest(),
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial_number_hex": format(cert.serial_number, "x"),
            "dns_names": san.get_values_for_type(x509.DNSName) if san else [],
            "ip_addresses": [str(x) for x in san.get_values_for_type(x509.IPAddress)] if san else [],
            "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
            "is_ca": bool(basic and basic.ca),
            "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
            "public_key_algorithm": type(cert.public_key()).__name__,
            "policy_oids": [p.policy_identifier.dotted_string for p in policies] if policies else []}


@dataclass
class Observation:
    http: dict
    tls: dict
    leaf: bytes = b""
    chain: bytes = b""

    def certificates(self, certs):
        pems = [c.public_bytes(serialization.Encoding.PEM) for c in certs]
        self.leaf = pems[0] if pems else b""
        self.chain = b"".join(pems)
        self.http["certificate_count"] = len(certs)
        self.tls["certificates"] = []
        for i, cert in enumerate(certs):
            try:
                item = metadata(cert, i)
            except Exception as error:
                # Unusual certificate metadata must never discard the PEM or block HTTP.
                item = {"index": i, "sha256": hashlib.sha256(cert.public_bytes(
                    serialization.Encoding.DER)).hexdigest(), "metadata_error": str(error)}
            self.tls["certificates"].append(item)


def new_observation(task, ip, protocol, c):
    authority = task.domain if c.port == 443 else f"{task.domain}:{c.port}"
    base = {"rank": task.rank, "domain": task.domain, "ip": ip}
    h = dict(base, schema=SCHEMA, complete=False, port=c.port, url=f"https://{authority}/",
             sni=task.domain, host=authority, user_agent=c.user_agent, started_at=now(),
             success=False, status="INCOMPLETE", stage="rate_limit", certificate_count=0,
             tls_handshake_complete=False, attempted_protocol=protocol, informational_responses=[])
    return Observation(h, dict(base, sni=task.domain, handshake_complete=False,
                              verification_performed=False, certificates=[], alpn=""))


def capture_tcp_certificates(o, ssl_object):
    # Python 3.13 exposes this publicly. 3.12 testing uses CPython's same underlying method.
    getter = getattr(ssl_object, "get_unverified_chain", None)
    certs = []
    if getter is not None:
        certs = [x509.load_der_x509_certificate(b) for b in getter()]
    else:
        internal = getattr(ssl_object, "_sslobj", None)
        getter = getattr(internal, "get_unverified_chain", None)
        if getter:
            for cert in getter():
                value = cert.public_bytes()
                if isinstance(value, str):
                    value = value.encode()
                certs.append(x509.load_pem_x509_certificate(value))
        else:
            certs = [x509.load_der_x509_certificate(ssl_object.getpeercert(binary_form=True))]
    o.certificates(certs)
    cipher = ssl_object.cipher()
    o.tls.update(version=ssl_object.version(), cipher_suite=cipher[0] if cipher else "",
                 alpn=ssl_object.selected_alpn_protocol() or "", handshake_complete=True)
    o.http["tls_handshake_complete"] = True


def decoded_response(pairs, protocol, max_bytes):
    if sum(len(k) + len(v) + 32 for k, v in pairs) > max_bytes:
        raise ProbeError("HEADER_LIMIT", "decoded response headers exceed limit")
    statuses = [v for k, v in pairs if k == b":status"]
    if len(statuses) != 1 or not re.fullmatch(rb"[1-5][0-9][0-9]", statuses[0]):
        raise ProbeError("HTTP_PROTOCOL_ERROR", "missing or invalid :status")
    status = int(statuses[0])
    headers = defaultdict(list)
    for key, value in pairs:
        if not key.startswith(b":"):
            headers[key.decode("ascii")].append(value.decode("latin1"))
    return {"status_code": status, "status": str(status), "protocol": protocol,
            "headers": dict(headers),
            "header_fields": [[k.decode("ascii"), v.decode("latin1")] for k, v in pairs]}


def accept_response(o, response, used, c):
    used += sum(len(k) + len(v) + 32 for k, vs in response["headers"].items() for v in vs)
    if used > c.max_header_bytes:
        raise ProbeError("HEADER_LIMIT", "cumulative response headers exceed limit")
    code = response["status_code"]
    if 100 <= code < 200 and code != 101:
        o.http["informational_responses"].append(response)
        if len(o.http["informational_responses"]) > 15:
            raise ProbeError("HEADER_LIMIT", "too many informational responses")
    else:
        o.http["response"] = response
    return used


async def http1(reader, writer, o, c):
    connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=c.max_header_bytes)
    writer.write(connection.send(h11.Request(method=b"GET", target=b"/", headers=[
        (b"Host", o.http["host"].encode()), (b"User-Agent", c.user_agent.encode()),
        (b"Accept", b"*/*"), (b"Accept-Encoding", b"identity"), (b"Connection", b"close")])))
    writer.write(connection.send(h11.EndOfMessage()))
    await writer.drain()
    o.http["stage"] = "http_headers"
    used = 0
    while "response" not in o.http:
        raw = await reader.readuntil(b"\r\n\r\n")
        used += len(raw)
        if used > c.max_header_bytes:
            raise ProbeError("HEADER_LIMIT", "response headers exceed limit")
        connection.receive_data(raw)
        event = connection.next_event()
        if not isinstance(event, (h11.Response, h11.InformationalResponse)):
            raise ProbeError("HTTP_PROTOCOL_ERROR", "expected HTTP response headers")
        headers = defaultdict(list)
        for k, v in event.headers.raw_items():
            headers[k.decode("ascii").lower()].append(v.decode("latin1"))
        response = {"status_code": event.status_code,
                    "status": f"{event.status_code} {event.reason.decode('latin1')}",
                    "protocol": "HTTP/" + event.http_version.decode("ascii"),
                    "headers": dict(headers), "raw_headers": raw.decode("latin1")}
        # Raw bytes already provide the size bound for HTTP/1.1.
        accept_response(o, response, 0, c)


async def http2(reader, writer, o, c):
    connection = H2Connection(config=H2Configuration(client_side=True, header_encoding=None))
    connection.decoder.max_header_list_size = c.max_header_bytes
    connection.initiate_connection()
    connection.update_settings({SettingCodes.MAX_HEADER_LIST_SIZE: c.max_header_bytes,
                                SettingCodes.ENABLE_PUSH: 0})
    connection.send_headers(1, [(b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", o.http["host"].encode()), (b":path", b"/"),
        (b"user-agent", c.user_agent.encode()), (b"accept", b"*/*"),
        (b"accept-encoding", b"identity")], end_stream=True)
    writer.write(connection.data_to_send())
    await writer.drain()
    o.http["stage"] = "http_headers"
    used = wire = 0
    while "response" not in o.http:
        data = await reader.read(65536)
        if not data:
            raise EOFError("connection closed before final HTTP/2 headers")
        wire += len(data)
        if wire > 4 * c.max_header_bytes + 65536:
            raise ProbeError("HEADER_LIMIT", "HTTP/2 pre-header wire limit")
        for event in connection.receive_data(data):
            if isinstance(event, (ResponseReceived, InformationalResponseReceived)) and event.stream_id == 1:
                response = decoded_response(event.headers, "HTTP/2.0", c.max_header_bytes)
                used = accept_response(o, response, used, c)
                if "response" in o.http:
                    return
            if isinstance(event, (H2Terminated, StreamReset)):
                raise ProbeError("HTTP_PROTOCOL_ERROR", repr(event))
        writer.write(connection.data_to_send())
        await writer.drain()


async def tcp_attempt(o, protocol, c):
    writer = None
    o.http["stage"] = "tcp"
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            o.http["ip"], c.port, family=socket.AF_INET6 if ":" in o.http["ip"] else socket.AF_INET,
            limit=c.max_header_bytes), c.connect_timeout)
        o.http["stage"] = "tls"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["h2" if protocol == "HTTP/2" else "http/1.1"])
        await writer.start_tls(context, server_hostname=o.http["domain"],
                               ssl_handshake_timeout=c.tls_timeout)
        capture_tcp_certificates(o, writer.get_extra_info("ssl_object"))
        if protocol == "HTTP/2" and o.tls["alpn"] != "h2":
            raise ProbeError("ALPN_UNSUPPORTED", "server did not negotiate h2")
        o.http["stage"] = "http_write"
        handler = http2 if protocol == "HTTP/2" else http1
        await asyncio.wait_for(handler(reader, writer, o, c), c.header_timeout)
    finally:
        if writer:
            # No response body is read; abort makes cleanup independent of peer behavior.
            writer.transport.abort()


class FixedPeerTransport:
    """Keep an observation on the supplied IP/port if a server advertises migration."""
    def __init__(self, transport, protocol):
        self.transport, self.protocol = transport, protocol

    def sendto(self, data, addr):
        if not self.protocol.allowed_peer(addr):
            self.protocol.fail(ProbeError("QUIC_ERROR", "server preferred-address migration not followed"))
            return
        self.transport.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class H3Client(QuicConnectionProtocol):
    def __init__(self, quic, observation, config):
        super().__init__(quic)
        self.observation, self.config = observation, config
        self.http3 = H3Connection(quic)
        self.response_ready = asyncio.get_running_loop().create_future()
        self.stream_id = None
        self.header_bytes = self.wire_bytes = 0

    def allowed_peer(self, addr):
        return (ipaddress.ip_address(addr[0]) == ipaddress.ip_address(self.observation.http["ip"])
                and addr[1] == self.config.port)

    def connection_made(self, transport):
        super().connection_made(FixedPeerTransport(transport, self))

    def fail(self, error):
        if not self.response_ready.done():
            self.response_ready.set_result(error)

    def capture_certificates(self):
        # aioquic 1.7.0 has no public peer-chain accessor; version pinned and tested.
        tls = getattr(self._quic, "tls", None)
        leaf = getattr(tls, "_peer_certificate", None)
        if leaf is not None:
            self.observation.certificates([leaf] + list(tls._peer_certificate_chain))

    def datagram_received(self, data, addr):
        if not self.allowed_peer(addr):
            return
        self.wire_bytes += len(data)
        if self.wire_bytes > 4 * self.config.max_header_bytes + 65536:
            self.fail(ProbeError("HEADER_LIMIT", "HTTP/3 pre-header wire limit"))
            return
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        try:
            if isinstance(event, HandshakeCompleted):
                self.capture_certificates()
                self.observation.tls.update(handshake_complete=True, version="TLSv1.3",
                                             alpn=event.alpn_protocol or "")
                self.observation.http["tls_handshake_complete"] = True
                if event.alpn_protocol not in H3_ALPN:
                    self.fail(ProbeError("ALPN_UNSUPPORTED", "server did not negotiate h3"))
            if isinstance(event, ConnectionTerminated):
                self.capture_certificates()
                status = "ALPN_UNSUPPORTED" if event.error_code == 0x178 else "QUIC_ERROR"
                self.fail(ProbeError(status, f"QUIC code={event.error_code}: {event.reason_phrase}"))
            if isinstance(event, QuicReset) and event.stream_id == self.stream_id:
                self.fail(ProbeError("HTTP_PROTOCOL_ERROR", f"HTTP/3 stream reset: {event.error_code}"))
            for http_event in self.http3.handle_event(event):
                if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.stream_id:
                    response = decoded_response(http_event.headers, "HTTP/3", self.config.max_header_bytes)
                    self.header_bytes = accept_response(self.observation, response, self.header_bytes, self.config)
                    if "response" in self.observation.http and not self.response_ready.done():
                        self.response_ready.set_result(None)
        except Exception as error:
            self.fail(error)

    async def request(self):
        self.stream_id = self._quic.get_next_available_stream_id()
        self.observation.http["stage"] = "http_headers"
        self.http3.send_headers(self.stream_id, [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", self.observation.http["host"].encode()), (b":path", b"/"),
            (b"user-agent", self.config.user_agent.encode()), (b"accept", b"*/*"),
            (b"accept-encoding", b"identity")], end_stream=True)
        self.transmit()
        error = await self.response_ready
        if error is not None:
            raise error


async def quic_attempt(o, c):
    o.http["stage"] = "quic_handshake"
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
        server_name=o.http["domain"], verify_mode=ssl.CERT_NONE, idle_timeout=c.timeout,
        max_data=2 * c.max_header_bytes, max_stream_data=c.max_header_bytes)
    family = socket.AF_INET6 if ":" in o.http["ip"] else socket.AF_INET
    # A numeric destination and family-specific UDP socket avoid DNS and dual-stack requirements.
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    transport = protocol = None
    try:
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: H3Client(QuicConnection(configuration=config), o, c), sock=sock)
        address = (o.http["ip"], c.port, 0, 0) if family == socket.AF_INET6 else (o.http["ip"], c.port)
        protocol.connect(address)
        try:
            await asyncio.wait_for(protocol.wait_connected(), c.tls_timeout)
        except ConnectionError:
            if protocol.response_ready.done() and protocol.response_ready.result() is not None:
                raise protocol.response_ready.result()
            raise
        protocol.capture_certificates()
        await asyncio.wait_for(protocol.request(), c.header_timeout)
    finally:
        if protocol:
            protocol.capture_certificates()
            protocol.close()
            # Bound QUIC closing time even if UDP is silently filtered.
            with suppress(TimeoutError, ConnectionError):
                await asyncio.wait_for(protocol.wait_closed(), 0.25)
            if protocol._timer is not None:
                protocol._timer.cancel()
        if transport:
            transport.close()
        else:
            sock.close()


async def probe_attempt(task, ip, protocol, c, gate):
    o = new_observation(task, ip, protocol, c)
    started = time.monotonic()
    try:
        await gate.wait()
        async with asyncio.timeout(c.timeout):
            if protocol == "HTTP/3":
                await quic_attempt(o, c)
            else:
                await tcp_attempt(o, protocol, c)
        if not o.leaf:
            raise ProbeError("NO_CERTIFICATE", "HTTP headers received without a peer certificate")
        if "response" not in o.http:
            raise ProbeError("HTTP_ERROR", "no final HTTP response")
        o.http.update(success=True, status="OK", stage="complete", complete=True)
    except asyncio.CancelledError:
        o.http.update(status="CANCELED", error="scan interrupted", complete=False)
        # Keep certificates obtained before interruption; no completion marker is created.
        name = f"interrupted-{ip.replace(':', '_')}-http{PROTOCOLS.index(protocol) + 1}"
        save_observation(target_dir(c.output, task) / "python_fallback" / name, o)
        raise
    except Exception as error:
        o.http.update(status=classify(error, o.http["stage"]), error=str(error) or type(error).__name__, complete=True)
    finally:
        o.http.update(finished_at=now(), duration_ms=int((time.monotonic() - started) * 1000))
    return o


def save_observation(directory, o):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "http.json").unlink(missing_ok=True)
    for name, data in (("certificate.pem", o.leaf), ("chain.pem", o.chain)):
        if data:
            atomic_write(directory / name, data)
        else:
            (directory / name).unlink(missing_ok=True)
    write_json(directory / "tls.json", o.tls)
    write_json(directory / "http.json", o.http)  # Completion marker, written last.


def is_success(directory, task, c):
    h = read_json(directory / "http.json")
    tls = read_json(directory / "tls.json")
    return (h.get("rank") == task.rank and h.get("domain") == task.domain
        and h.get("ip") in task.ips and h.get("port") == c.port
        and h.get("user_agent") == c.user_agent and h.get("complete") and h.get("success")
        and h.get("response", {}).get("status_code", 0) >= 100 and h.get("certificate_count", 0) > 0
        and tls.get("ip") == h.get("ip")
        and all((directory / name).is_file() and (directory / name).stat().st_size > 0
                for name in ("certificate.pem", "chain.pem")))


def promote(directory, o):
    # Keep the original Go main files and its attempts directory for provenance.
    backup = directory / "go_original"
    backup.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        if (directory / name).exists() and not (backup / name).exists():
            shutil.copy2(directory / name, backup / name)
    save_observation(directory, o)


async def probe_domain(task, c, gate):
    directory = target_dir(c.output, task)
    fallback_dir = directory / "python_fallback"
    signature = {"ips": task.ips, "port": c.port, "user_agent": c.user_agent}
    if is_success(directory, task, c):
        failure_dir = target_dir(c.failures_output, task)
        for name in ("errors.json", "errors_python.json"):
            (failure_dir / name).unlink(missing_ok=True)
        return "SKIPPED_SUCCESS", []
    cached = read_json(fallback_dir / "fallback.json")
    if (cached.get("success") and cached.get("signature") == signature
            and is_success(fallback_dir, task, c)):
        h = read_json(fallback_dir / "http.json")
        o = Observation(h, read_json(fallback_dir / "tls.json"),
                        (fallback_dir / "certificate.pem").read_bytes(),
                        (fallback_dir / "chain.pem").read_bytes())
        promote(directory, o)
        for name in ("errors.json", "errors_python.json"):
            (target_dir(c.failures_output, task) / name).unlink(missing_ok=True)
        return "SKIPPED_SUCCESS", []
    if not c.retry_failed and cached.get("complete") and not cached.get("success") and cached.get("signature") == signature:
        write_json(target_dir(c.failures_output, task) / "errors_python.json", cached)
        return "SKIPPED_FAILURE", []
    attempts = []
    best = None
    success = False
    for ip in task.ips:
        tcp_failed = False
        for protocol in PROTOCOLS:
            if protocol == "HTTP/2" and tcp_failed:
                continue
            o = await probe_attempt(task, ip, protocol, c, gate)
            tcp_failed = o.http["stage"] == "tcp"
            name = f"{len(attempts) + 1:04d}-{ip.replace(':', '_')}-http{PROTOCOLS.index(protocol) + 1}"
            save_observation(fallback_dir / "attempts" / name, o)
            attempt = {k: o.http.get(k) for k in ("ip", "status", "stage", "error", "certificate_count")}
            attempt.update(protocol=protocol, directory=f"python_fallback/attempts/{name}",
                           http_status_code=o.http.get("response", {}).get("status_code", 0))
            attempts.append(attempt)
            if best is None or o.leaf or not best.leaf:
                best = o
            if o.http["success"]:
                best, success = o, True
                break
        if success:
            break
    best.http.update(input_ips=task.ips, attempts=attempts, collected_by="python_fallback")
    save_observation(fallback_dir, best)
    failure_dir = target_dir(c.failures_output, task)
    final = dict(rank=task.rank, domain=task.domain, signature=signature, complete=True,
                 success=success, status=best.http["status"], attempts=attempts,
                 certificate_obtained=bool(best.leaf), http_obtained="response" in best.http,
                 observed_at=now())
    if success:
        promote(directory, best)
        for name in ("errors.json", "errors_python.json"):
            (failure_dir / name).unlink(missing_ok=True)
    else:
        write_json(failure_dir / "errors_python.json", final)
    write_json(fallback_dir / "fallback.json", final)
    return best.http["status"], attempts


def read_tasks(path, errors):
    tasks = {}
    with path.open() as source:
        for line_number, raw in enumerate(source, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
                rank, domain = row["rank"], row["domain"]
                if isinstance(rank, bool) or not isinstance(rank, int) or rank <= 0:
                    raise ValueError("rank must be a positive integer")
                if not isinstance(domain, str):
                    raise ValueError("domain must be a string")
                domain = domain.removesuffix(".").lower()
                if len(domain) > 253 or not domain or any(not re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in domain.split(".")):
                    raise ValueError("invalid ASCII DNS name")
                ips = row.get("ips", [])
                if not isinstance(ips, list):
                    raise ValueError("ips must be a list")
                if row.get("ip"):
                    ips = [row["ip"]] + ips
                if not ips:
                    raise ValueError("missing IP addresses")
                normalized = []
                for value in ips:
                    if not isinstance(value, str):
                        raise ValueError("IP addresses must be strings")
                    address = ipaddress.ip_address(value)
                    if getattr(address, "scope_id", None):
                        raise ValueError("scoped IP addresses unsupported")
                    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                        address = address.ipv4_mapped
                    normalized.append(str(address))
                if rank in tasks and tasks[rank].domain != domain:
                    raise ValueError("same rank assigned to different domains")
                task = tasks.setdefault(rank, Task(rank, domain))
                for ip in normalized:
                    if ip not in task.ips:
                        task.ips.append(ip)
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                errors.write(json.dumps({"line": line_number, "status": "INVALID_INPUT", "error": str(error), "input": raw.rstrip()}) + "\n")
    return list(tasks.values())


async def run(c):
    run_dir = c.output / "_runs" / ("python-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    run_dir.mkdir(parents=True)
    with (run_dir / "input_errors.jsonl").open("w") as errors:
        tasks = read_tasks(c.input, errors)
    if c.limit:
        tasks = tasks[:c.limit]
    gate = RateGate(c.rate)
    counts, attempt_counts = Counter(), Counter()
    queue = asyncio.Queue(maxsize=2 * c.workers)
    failures = (run_dir / "errors.jsonl").open("w")
    started = time.monotonic()

    async def producer():
        for task in tasks:
            await queue.put(task)
        for _ in range(c.workers):
            await queue.put(None)

    async def worker():
        while True:
            task = await queue.get()
            if task is None:
                return
            try:
                status, attempts = await probe_domain(task, c, gate)
                counts[status] += 1
                for a in attempts:
                    attempt_counts[a["protocol"] + ":" + a["status"]] += 1
                if status not in ("OK", "SKIPPED_SUCCESS"):
                    failures.write(json.dumps({"rank": task.rank, "domain": task.domain, "status": status}) + "\n")
                    failures.flush()
            except OSError as error:
                counts["WRITE_ERROR"] += 1
                failures.write(json.dumps({"rank": task.rank, "domain": task.domain, "status": "WRITE_ERROR", "error": str(error)}) + "\n")
                failures.flush()

    async def progress():
        while True:
            await asyncio.sleep(c.progress_every)
            print(f"python_fallback finished={sum(counts.values())}/{len(tasks)} statuses={dict(counts)} elapsed={time.monotonic()-started:.0f}s", flush=True)

    interrupted = False
    progress_task = asyncio.create_task(progress())
    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(producer())
            for _ in range(c.workers):
                group.create_task(worker())
    except asyncio.CancelledError:
        interrupted = True
        raise
    finally:
        progress_task.cancel()
        with suppress(asyncio.CancelledError):
            await progress_task
        failures.close()
        summary = {"schema": SCHEMA, "finished_at": now(), "interrupted": interrupted,
                   "elapsed_seconds": time.monotonic() - started, "domain_status_counts": dict(counts),
                   "attempt_status_counts": dict(attempt_counts), "input": str(c.input),
                   "workers": c.workers, "rate": c.rate}
        write_json(run_dir / "summary.json", summary)
        print(json.dumps(summary), flush=True)
    return 1 if counts["WRITE_ERROR"] else 0


def duration(value):
    return float(value.removesuffix("s"))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    defaults = Config()
    for name in ("input", "output", "failures_output"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, default=getattr(defaults, name))
    for name in ("workers", "port", "limit", "max_header_bytes"):
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=getattr(defaults, name))
    for name in ("rate", "timeout", "connect_timeout", "tls_timeout", "header_timeout", "progress_every"):
        parser.add_argument("--" + name.replace("_", "-"), type=duration, default=getattr(defaults, name))
    parser.add_argument("--user-agent", default=defaults.user_agent)
    parser.add_argument("--retry-failed", action="store_true")
    args = parser.parse_args()
    c = Config(**vars(args))
    if (c.workers < 1 or not 1 <= c.port <= 65535 or c.limit < 0 or c.max_header_bytes < 1024
        or any(not math.isfinite(getattr(c, name)) or getattr(c, name) <= 0 for name in
               ("timeout", "connect_timeout", "tls_timeout", "header_timeout", "progress_every"))
        or not math.isfinite(c.rate) or c.rate < 0 or "\r" in c.user_agent or "\n" in c.user_agent
        or not c.user_agent.isascii()):
        parser.error("invalid concurrency, limits, timeout, port, rate, or User-Agent")
    return c


async def main(c):
    loop = asyncio.get_running_loop()
    current = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, current.cancel)
    return await run(c)


if __name__ == "__main__":
    logging.getLogger("quic").setLevel(logging.ERROR)
    try:
        sys.exit(asyncio.run(main(parse_args())))
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(130)
