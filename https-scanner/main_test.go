package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Workers: 3, Port: 443, Timeout: time.Second, ConnectTimeout: time.Second, TLSTimeout: time.Second, HeaderTimeout: time.Second, ProgressEvery: time.Hour, MaxHeaderBytes: 1024 * 1024, Resume: true, UserAgent: "ScannerTest/1.0"}
}

func TestPythonRecoveredHTTP3Resume(t *testing.T) {
	c := testConfig()
	target := Target{Rank: 1, IP: "127.0.0.1", Domain: "probe.invalid"}
	task := DomainTask{Rank: 1, Domain: target.Domain, IPs: []string{target.IP}}
	h := HTTPResult{Target: target, Schema: pythonProfile, Complete: true, Success: true,
		Port: c.Port, UserAgent: c.UserAgent, CertificateCount: 1, Status: "OK",
		Response: &Response{StatusCode: 403, Protocol: "HTTP/3"}}
	tlsResult := TLSResult{Target: target, VerificationPerformed: false}
	dir := targetDir(t.TempDir(), target)
	if err := saveFiles(dir, h, tlsResult, []byte("test-leaf"), []byte("test-chain")); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCompleted(dir, task, c); !ok {
		t.Fatal("Python HTTP/3 collection must be reusable without reconnecting")
	}
	h.Success = false
	if err := writeJSON(filepath.Join(dir, "http.json"), h); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCompleted(dir, task, c); ok {
		t.Fatal("Python failure must not replace Go retry behavior")
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(122), Subject: pkix.Name{CommonName: "Test issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "probe.invalid"}, DNSNames: []string{"probe.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	return tls.Certificate{Certificate: [][]byte{der, issuerDER}, PrivateKey: key, Leaf: cert}, roots
}

// A controlled TLS endpoint avoids all public-network dependencies in tests.
func fixture(t *testing.T, handler func(net.Conn, *http.Request)) (int, *x509.CertPool) {
	t.Helper()
	cert, roots := testCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err == nil {
					handler(conn, req)
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	return ln.Addr().(*net.TCPAddr).Port, roots
}

func TestHTTP1SuccessStopsIPsAndDoesNotVerify(t *testing.T) {
	var dns atomic.Int64
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dns.Add(1)
		return nil, errors.New("DNS forbidden")
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:9")
	seen := make(chan [2]string, 1)
	port, _ := fixture(t, func(conn net.Conn, r *http.Request) {
		seen <- [2]string{r.Host, conn.(*tls.Conn).ConnectionState().ServerName}
		_, _ = io.WriteString(conn, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 302 Found\r\nLocation: https://unresolved.invalid/\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nTransfer-Encoding: chunked\r\nx-CaSe: raw\r\n\r\n")
	})
	c := testConfig()
	c.Port = port
	task := DomainTask{1, "_wildcard_.ph", []string{"127.0.0.1", "127.0.0.2"}}
	e := probeEndpoint(context.Background(), task, c, nil)
	if !e.HTTP.Success || e.HTTP.Status != "OK" || len(e.HTTP.Attempts) != 1 || e.HTTP.CertificateCount != 2 || e.TLS.VerificationPerformed {
		t.Fatalf("not collection-only or failed to stop: %+v", e.HTTP)
	}
	if len(e.HTTP.Response.Headers["Set-Cookie"]) != 2 || len(e.HTTP.Informational) != 1 || e.HTTP.Response.Headers["Transfer-Encoding"][0] != "chunked" || !strings.Contains(e.HTTP.Response.RawHeaders, "x-CaSe: raw") {
		t.Fatal("lost headers")
	}
	got := <-seen
	if got[0] != net.JoinHostPort(task.Domain, strconv.Itoa(port)) || got[1] != task.Domain || dns.Load() != 0 {
		t.Fatalf("wrong routing: %v DNS=%d", got, dns.Load())
	}
	root := t.TempDir()
	dir := targetDir(root, e.HTTP.Target)
	if err := saveEndpoint(dir, e); err != nil {
		t.Fatal(err)
	}
	if record, err := syncFailure(filepath.Join(root, "failures"), dir, e); record != nil || err != nil {
		t.Fatal("certificate mismatch became a failure")
	}
	b, err := os.ReadFile(filepath.Join(dir, "tls.json"))
	if err != nil || strings.Contains(string(b), "hostname_valid") || strings.Contains(string(b), "chain_error") {
		t.Fatal("validation fields remain")
	}
	if strings.Count(string(e.ChainPEM), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("lost provided chain")
	}
}

func h2Fixture(t *testing.T, onlyH2 bool) (int, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Location", "https://unresolved.invalid/")
		w.WriteHeader(307)
	}))
	s.EnableHTTP2 = true
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	if onlyH2 {
		s.TLS = &tls.Config{NextProtos: []string{"h2"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !contains(hello.SupportedProtos, "h2") {
				return nil, errors.New("h2 required")
			}
			return nil, nil
		}}
	} else {
		s.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().(*net.TCPAddr).Port, &requests
}

func TestHTTP2Fallback(t *testing.T) {
	for _, only := range []bool{true, false} {
		t.Run(strconv.FormatBool(only), func(t *testing.T) {
			port, requests := h2Fixture(t, only)
			c := testConfig()
			c.Port = port
			e := probeEndpoint(context.Background(), DomainTask{1, "wrong.invalid", []string{"127.0.0.1", "127.0.0.2"}}, c, nil)
			if !e.HTTP.Success || len(e.HTTP.Attempts) != 2 || e.HTTP.Attempts[0].Status == "OK" || e.HTTP.Attempts[1].Status != "OK" || e.HTTP.Response.Protocol != "HTTP/2.0" || e.TLS.ALPN != "h2" {
				t.Fatalf("HTTP/2 fallback failed: %+v", e.HTTP)
			}
			if len(e.HTTP.Response.Headers["Set-Cookie"]) != 2 || e.HTTP.Response.StatusCode != 307 || e.HTTP.Response.RawHeaders != "" {
				t.Fatal("bad HTTP/2 header representation")
			}
			want := int64(2)
			if only {
				want = 1
			}
			if requests.Load() != want {
				t.Fatalf("unexpected requests: %d", requests.Load())
			}
			root := t.TempDir()
			dir := targetDir(root, e.HTTP.Target)
			if err := saveEndpoint(dir, e); err != nil {
				t.Fatal(err)
			}
			if !only {
				p := filepath.Join(dir, e.HTTP.Attempts[0].Directory, "certificate.pem")
				if _, err := os.Stat(p); err != nil {
					t.Fatal("failed HTTP/1 attempt certificate lost")
				}
			}
			if record, err := syncFailure(filepath.Join(root, "failures"), dir, e); record != nil || err != nil {
				t.Fatal("recovered HTTP/1 failure logged as domain failure")
			}
		})
	}
}

func TestConnectionRefusedTriesNextIP(t *testing.T) {
	port, _ := fixture(t, func(conn net.Conn, _ *http.Request) {
		_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	})
	c := testConfig()
	c.Port = port
	e := probeEndpoint(context.Background(), DomainTask{1, "123example.com", []string{"127.0.0.2", "127.0.0.1", "127.0.0.3"}}, c, nil)
	if !e.HTTP.Success || e.HTTP.IP != "127.0.0.1" || len(e.HTTP.Attempts) != 2 || e.HTTP.Attempts[0].Status != "CONNECTION_REFUSED" || e.HTTP.Attempts[1].Protocol != "HTTP/1.1" {
		t.Fatalf("bad sequential IP fallback: %+v", e.HTTP)
	}
}

func TestBothProtocolsFailKeepCertificateAndShortStatus(t *testing.T) {
	port, _ := fixture(t, func(net.Conn, *http.Request) {})
	c := testConfig()
	c.Port = port
	task := DomainTask{10001, "probe.invalid", []string{"127.0.0.1"}}
	e := probeEndpoint(context.Background(), task, c, nil)
	if e.HTTP.Success || e.HTTP.Status != "CONNECTION_CLOSED" || len(e.HTTP.Attempts) != 2 || e.HTTP.CertificateCount != 2 {
		t.Fatalf("lost partial evidence or short status: %+v", e.HTTP)
	}
	root := t.TempDir()
	if err := saveEndpoint(targetDir(root, e.HTTP.Target), e); err != nil {
		t.Fatal(err)
	}
	rec, err := syncFailure(root, "result-dir", e)
	if err != nil || rec == nil || rec.Status != "CONNECTION_CLOSED" || !rec.CertificateObtained || rec.HTTPObtained {
		t.Fatalf("bad failure: %+v %v", rec, err)
	}
	e.HTTP.Success = true
	e.HTTP.Status = "OK"
	if rec, err := syncFailure(root, "result-dir", e); err != nil || rec != nil {
		t.Fatal("failed to clear recovered error")
	}
	if _, err := os.Stat(filepath.Join(targetDir(root, e.HTTP.Target), "errors.json")); !os.IsNotExist(err) {
		t.Fatal("stale failure survived")
	}
}

func TestTimeoutAndHeaderLimit(t *testing.T) {
	port, _ := fixture(t, func(conn net.Conn, _ *http.Request) { _, _ = io.Copy(io.Discard, conn) })
	c := testConfig()
	c.Port = port
	c.HeaderTimeout = 30 * time.Millisecond
	e := probeEndpoint(context.Background(), DomainTask{1, "probe.invalid", []string{"127.0.0.1"}}, c, nil)
	if e.HTTP.Status != "TIMEOUT" || e.HTTP.CertificateCount != 2 {
		t.Fatalf("bad timeout: %+v", e.HTTP)
	}
	port, _ = fixture(t, func(conn net.Conn, _ *http.Request) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("a", 2048)+"\r\n\r\n")
	})
	c.Port = port
	c.MaxHeaderBytes = 1024
	e = probeEndpoint(context.Background(), DomainTask{1, "probe.invalid", []string{"127.0.0.1"}}, c, nil)
	if e.HTTP.Status != "HEADER_LIMIT" {
		t.Fatalf("header limit not enforced: %+v", e.HTTP)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e = probeEndpoint(ctx, DomainTask{1, "probe.invalid", []string{"127.0.0.1"}}, c, nil)
	if e.HTTP.Complete || e.HTTP.Status != "CANCELED" || len(e.HTTP.Attempts) != 1 {
		t.Fatal("cancellation not resumable")
	}
}

func TestIPv6Literal(t *testing.T) {
	cert, _ := testCertificate(t)
	ln, err := tls.Listen("tcp6", "[::1]:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	}()
	defer func() { _ = ln.Close(); <-done }()
	c := testConfig()
	c.Port = ln.Addr().(*net.TCPAddr).Port
	e := probeEndpoint(context.Background(), DomainTask{1, "probe.invalid", []string{"::1"}}, c, nil)
	if !e.HTTP.Success {
		t.Fatalf("IPv6 failed: %+v", e.HTTP)
	}
}

func TestRunMergesIPsAndResumes(t *testing.T) {
	var requests atomic.Int64
	port, _ := fixture(t, func(conn net.Conn, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	root := t.TempDir()
	input := filepath.Join(root, "input.jsonl")
	rows := []string{`{"rank":1,"domain":"probe.invalid","ips":["127.0.0.2"]}`, `{"rank":1,"domain":"probe.invalid","ips":["127.0.0.1","127.0.0.1","::ffff:127.0.0.1"]}`, `{"rank":10001,"domain":"probe.invalid","ips":["127.0.0.2"]}`, `{"rank":2,"domain":"_wildcard_.ph","ips":["bad-ip","127.0.0.1"]}`, `not-json`, `{"rank":1,"domain":"other.invalid","ip":"127.0.0.1"}`}
	if err := os.WriteFile(input, []byte(strings.Join(rows, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.Port = port
	c.Input = input
	c.Output = filepath.Join(root, "cert_http")
	c.FailuresOutput = filepath.Join(root, "failures_certHTTP")
	for i := 0; i < 2; i++ {
		if err := run(context.Background(), c); err == nil || !strings.Contains(err.Error(), "3 invalid") {
			t.Fatalf("input errors missing: %v", err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("resumed connections: %d", requests.Load())
	}
	paths, _ := filepath.Glob(filepath.Join(c.Output, "_runs", "*", "summary.json"))
	if len(paths) != 2 {
		t.Fatal("summaries missing")
	}
	b, _ := os.ReadFile(paths[1])
	var summary struct {
		Counters map[string]int64 `json:"counters"`
		Statuses map[string]int64 `json:"domain_status_counts"`
	}
	if err := json.Unmarshal(b, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Counters["resume_skipped"] != 3 || summary.Counters["probed"] != 0 || summary.Counters["duplicate_ips_skipped"] != 2 || summary.Statuses["OK"] != 2 || summary.Statuses["CONNECTION_REFUSED"] != 1 {
		t.Fatalf("bad summary: %s", b)
	}
	errorsPath := filepath.Join(targetDir(c.FailuresOutput, Target{Rank: 10001, Domain: "probe.invalid"}), "errors.json")
	b, _ = os.ReadFile(errorsPath)
	if !strings.Contains(string(b), `"status": "CONNECTION_REFUSED"`) {
		t.Fatal("short status absent")
	}
	goodErrorPath := filepath.Join(targetDir(c.FailuresOutput, Target{Rank: 2, Domain: "_wildcard_.ph"}), "errors.json")
	if _, err := os.Stat(goodErrorPath); !os.IsNotExist(err) {
		t.Fatal("mismatching certificate was logged")
	}
	c.RetryFailed = true
	if err := run(context.Background(), c); err == nil {
		t.Fatal("invalid input errors disappeared")
	}
	if requests.Load() != 2 {
		t.Fatal("retry-failed re-probed good domains")
	}
}

func TestLegacyImportDoesNotReconnectOrValidate(t *testing.T) {
	var requests atomic.Int64
	port, _ := fixture(t, func(conn net.Conn, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	c := testConfig()
	c.Port = port
	target := Target{1, "127.0.0.1", "wrong.invalid"}
	a := probeAttempt(context.Background(), target, c, "HTTP/1.1", nil)
	a.HTTP.Schema = "https-direct-ip-http1-v1"
	a.HTTP.Status = ""
	root := t.TempDir()
	c.Output = filepath.Join(root, "cert_http")
	c.FailuresOutput = filepath.Join(root, "failures_certHTTP")
	c.Input = filepath.Join(root, "input.jsonl")
	dir := targetDir(c.Output, target)
	if err := saveFiles(dir, a.HTTP, a.TLS, a.LeafPEM, a.ChainPEM); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(a.TLS)
	var oldTLS map[string]any
	_ = json.Unmarshal(b, &oldTLS)
	oldTLS["hostname_error"] = "old mismatch"
	oldTLS["chain_error"] = "old unknown issuer"
	if err := writeJSON(filepath.Join(dir, "tls.json"), oldTLS); err != nil {
		t.Fatal(err)
	}
	oldErr := filepath.Join(targetDir(c.FailuresOutput, target), "errors.json")
	_ = os.MkdirAll(filepath.Dir(oldErr), 0755)
	_ = os.WriteFile(oldErr, []byte(`{"errors":[{"stage":"certificate_hostname"}]}`), 0644)
	_ = os.WriteFile(c.Input, []byte(`{"rank":1,"domain":"wrong.invalid","ips":["127.0.0.1"]}`+"\n"), 0644)
	if err := run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("legacy success reconnected")
	}
	b, _ = os.ReadFile(filepath.Join(dir, "http.json"))
	var h HTTPResult
	_ = json.Unmarshal(b, &h)
	if h.Schema != profile || h.Status != "OK" || h.ImportedFrom != "legacy_http1" {
		t.Fatalf("bad import: %s", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "tls.json"))
	if strings.Contains(string(b), "hostname_error") || strings.Contains(string(b), "chain_error") {
		t.Fatal("legacy validation fields retained")
	}
	if _, err := os.Stat(oldErr); !os.IsNotExist(err) {
		t.Fatal("legacy validation failure retained")
	}
}

func TestErrorClassificationAndPaths(t *testing.T) {
	for _, pair := range []struct {
		e error
		s string
	}{{context.DeadlineExceeded, "TIMEOUT"}, {context.Canceled, "CANCELED"}, {&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "CONNECTION_REFUSED"}, {syscall.ENETUNREACH, "NETWORK_UNREACHABLE"}, {syscall.EHOSTUNREACH, "HOST_UNREACHABLE"}, {io.EOF, "CONNECTION_CLOSED"}} {
		if got := classify("tcp", pair.e); got != pair.s {
			t.Fatalf("%v: %s", pair.e, got)
		}
	}
	for rank, shard := range map[int]string{1: "000", 10000: "000", 10001: "001", 1000000: "099"} {
		if filepath.Base(filepath.Dir(targetDir("root", Target{Rank: rank, Domain: "x.com"}))) != shard {
			t.Fatal("wrong shard")
		}
	}
	for _, name := range []string{"../x", "x/y.com", "a\nb.com", "a b.com", "x..com"} {
		target := Target{1, "127.0.0.1", name}
		if normalize(&target) == nil {
			t.Fatal("accepted unsafe name")
		}
	}
}

func TestHTTP2HeaderTimeoutAndLimit(t *testing.T) {
	for _, limit := range []bool{false, true} {
		t.Run(strconv.FormatBool(limit), func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
					return
				}
				if limit {
					w.Header().Set("X-Large", strings.Repeat("a", 700))
					w.Header().Set("X-Other", strings.Repeat("b", 700))
					w.WriteHeader(200)
					return
				}
				<-r.Context().Done()
			}))
			s.EnableHTTP2 = true
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.StartTLS()
			defer s.Close()
			c := testConfig()
			c.Port = s.Listener.Addr().(*net.TCPAddr).Port
			c.HeaderTimeout = 50 * time.Millisecond
			if limit {
				c.MaxHeaderBytes = 1024
			}
			e := probeEndpoint(context.Background(), DomainTask{1, "probe.invalid", []string{"127.0.0.1"}}, c, nil)
			want := "TIMEOUT"
			if limit {
				want = "HEADER_LIMIT"
			}
			if e.HTTP.Success || len(e.HTTP.Attempts) != 2 || e.HTTP.Attempts[1].Status != want {
				t.Fatalf("HTTP/2 limit/timeout classification: %+v", e.HTTP)
			}
		})
	}
}
