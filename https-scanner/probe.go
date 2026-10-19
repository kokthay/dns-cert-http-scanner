package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func deadline(ctx context.Context, d time.Duration) time.Time {
	end := time.Now().Add(d)
	if t, ok := ctx.Deadline(); ok && t.Before(end) {
		return t
	}
	return end
}
func readHeaderBlock(r *bufio.Reader, limit *io.LimitedReader) (Response, error) {
	var raw bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		raw.WriteString(line)
		if err != nil {
			if limit.N == 0 {
				return Response{}, &codedError{"HEADER_LIMIT", "response headers exceed max-header-bytes"}
			}
			return Response{}, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw.Bytes())), nil)
	if err != nil {
		return Response{}, codeError("HTTP_PARSE_ERROR", err)
	}
	p := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw.Bytes())))
	if _, err = p.ReadLine(); err != nil {
		return Response{}, err
	}
	h, err := p.ReadMIMEHeader()
	if err != nil {
		return Response{}, codeError("HTTP_PARSE_ERROR", err)
	}
	return Response{StatusCode: resp.StatusCode, Status: resp.Status, Protocol: resp.Proto, Headers: h, RawHeaders: raw.String()}, nil
}

func collectTLS(o *Observation, s tls.ConnectionState) {
	o.TLS.ALPN = s.NegotiatedProtocol
	if s.Version != 0 {
		o.TLS.Version = tls.VersionName(s.Version)
	}
	if s.CipherSuite != 0 {
		o.TLS.CipherSuite = tls.CipherSuiteName(s.CipherSuite)
	}
	for i, cert := range s.PeerCertificates {
		b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		o.ChainPEM = append(o.ChainPEM, b...)
		if i == 0 {
			o.LeafPEM = b
		}
		h := sha256.Sum256(cert.Raw)
		ci := CertificateInfo{Index: i, SHA256: hex.EncodeToString(h[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16), DNSNames: cert.DNSNames, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IsCA: cert.IsCA, SignatureAlgorithm: cert.SignatureAlgorithm.String(), PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String()}
		for _, ip := range cert.IPAddresses {
			ci.IPAddresses = append(ci.IPAddresses, ip.String())
		}
		for _, oid := range cert.Policies {
			ci.PolicyOIDs = append(ci.PolicyOIDs, oid.String())
		}
		o.TLS.Certificates = append(o.TLS.Certificates, ci)
	}
	o.HTTP.CertificateCount = len(s.PeerCertificates)
}

func probeAttempt(parent context.Context, t Target, c Config, protocol string, gate func(context.Context) error) (o Observation) {
	started := time.Now().UTC()
	host := t.Domain
	if c.Port != 443 {
		host = net.JoinHostPort(t.Domain, strconv.Itoa(c.Port))
	}
	o.Protocol = protocol
	o.HTTP = HTTPResult{Target: t, Schema: profile, Port: c.Port, URL: "https://" + host + "/", Host: host, SNI: t.Domain, UserAgent: c.UserAgent, StartedAt: started, Stage: "rate_limit"}
	o.TLS = TLSResult{Target: t, SNI: t.Domain, Certificates: []CertificateInfo{}, VerificationPerformed: false}
	defer func() {
		o.HTTP.FinishedAt = time.Now().UTC()
		o.HTTP.DurationMS = time.Since(started).Milliseconds()
		o.HTTP.Complete = parent.Err() == nil
		o.HTTP.Status = classify(o.HTTP.Stage, o.Err)
		if o.Err != nil {
			o.HTTP.Error = o.Err.Error()
		}
	}()
	if gate != nil {
		if o.Err = gate(parent); o.Err != nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	o.HTTP.Stage = "tcp"
	// The only socket dial always uses the supplied IP literal, never a name.
	raw, err := (&net.Dialer{Timeout: c.ConnectTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(t.IP, strconv.Itoa(c.Port)))
	if err != nil {
		o.Err = err
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(deadline(ctx, c.Timeout))
	o.HTTP.Stage = "tls"
	alpn := "http/1.1"
	if protocol == "HTTP/2" {
		alpn = "h2"
	}
	conn := tls.Client(raw, &tls.Config{ServerName: t.Domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{alpn}, ClientSessionCache: nil})
	hc, hcancel := context.WithTimeout(ctx, c.TLSTimeout)
	err = conn.HandshakeContext(hc)
	hcancel()
	state := conn.ConnectionState()
	collectTLS(&o, state)
	if err != nil {
		o.Err = err
		o.TLS.HandshakeError = err.Error()
		return
	}
	o.TLS.HandshakeComplete = true
	o.HTTP.TLSHandshakeComplete = true
	if protocol == "HTTP/2" && state.NegotiatedProtocol != "h2" {
		o.Err = &codedError{"ALPN_UNSUPPORTED", "server did not negotiate h2"}
		return
	}
	_ = conn.SetDeadline(deadline(ctx, c.HeaderTimeout))
	o.HTTP.Stage = "http_write"
	req, err := http.NewRequestWithContext(ctx, "GET", o.HTTP.URL, nil)
	if err != nil {
		o.Err = err
		return
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	if protocol == "HTTP/1.1" {
		req.Close = true
		if err = req.Write(conn); err != nil {
			o.Err = err
			return
		}
		o.HTTP.Stage = "http_headers"
		limited := &io.LimitedReader{R: conn, N: c.MaxHeaderBytes}
		reader := bufio.NewReader(limited)
		for n := 0; n < 16; n++ {
			resp, e := readHeaderBlock(reader, limited)
			if e != nil {
				o.Err = e
				return
			}
			if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != 101 {
				o.HTTP.Informational = append(o.HTTP.Informational, resp)
				continue
			}
			o.HTTP.Response = &resp
			break
		}
		if o.HTTP.Response == nil {
			o.Err = &codedError{"HTTP_PARSE_ERROR", "too many informational responses"}
			return
		}
	} else {
		o.HTTP.Stage = "http_headers"
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true)
		var used atomic.Bool
		tr := &http.Transport{Proxy: nil, Protocols: protocols, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: c.MaxHeaderBytes, ResponseHeaderTimeout: c.HeaderTimeout,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unexpected plain dial blocked")
			},
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if !used.CompareAndSwap(false, true) {
					return nil, errors.New("additional transport dial blocked")
				}
				return conn, nil
			},
		}
		defer tr.CloseIdleConnections()
		var infoBytes int64
		trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			infoBytes += headerSize(h)
			if len(o.HTTP.Informational) >= 15 || infoBytes > c.MaxHeaderBytes {
				return &codedError{"HEADER_LIMIT", "informational response header limit exceeded"}
			}
			o.HTTP.Informational = append(o.HTTP.Informational, Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), Protocol: "HTTP/2.0", Headers: http.Header(h).Clone()})
			return nil
		}}
		req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
		resp, e := tr.RoundTrip(req)
		if e != nil {
			o.Err = e
			return
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			o.Err = &codedError{"HTTP_ERROR", "HTTP/2 attempt returned another protocol"}
			return
		}
		if infoBytes+headerSize(resp.Header) > c.MaxHeaderBytes {
			o.Err = &codedError{"HEADER_LIMIT", "response headers exceed max-header-bytes"}
			return
		}
		o.HTTP.Response = &Response{StatusCode: resp.StatusCode, Status: resp.Status, Protocol: resp.Proto, Headers: resp.Header.Clone()}
	}
	if o.HTTP.CertificateCount == 0 {
		o.Err = &codedError{"NO_CERTIFICATE", "HTTP response received without peer certificate"}
		return
	}
	o.HTTP.Success = true
	o.HTTP.Stage = "complete"
	return
}

func headerSize(h map[string][]string) int64 {
	var n int64
	for k, vs := range h {
		for _, v := range vs {
			n += int64(len(k) + len(v) + 32)
		}
	}
	return n
}
func attemptDir(i int, a Observation) string {
	kind := "http1"
	if a.Protocol == "HTTP/2" {
		kind = "http2"
	}
	ip := strings.ReplaceAll(a.HTTP.IP, ":", "_")
	return filepath.Join("attempts", fmt.Sprintf("%04d-%s-%s", i+1, ip, kind))
}

func probeEndpoint(ctx context.Context, task DomainTask, c Config, gate func(context.Context) error) Endpoint {
	started := time.Now().UTC()
	attempts := []Observation{}
	done := false
	for _, ip := range task.IPs {
		a := probeAttempt(ctx, Target{task.Rank, ip, task.Domain}, c, "HTTP/1.1", gate)
		attempts = append(attempts, a)
		if a.HTTP.Success {
			done = true
			break
		}
		if ctx.Err() != nil {
			break
		}
		// A failure before TCP connects is independent of the HTTP version.
		if a.HTTP.Stage == "tcp" {
			continue
		}
		a = probeAttempt(ctx, Target{task.Rank, ip, task.Domain}, c, "HTTP/2", gate)
		attempts = append(attempts, a)
		if a.HTTP.Success {
			done = true
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	best := len(attempts) - 1
	if !done {
		for i, a := range attempts {
			if a.HTTP.CertificateCount > 0 {
				best = i
			}
		}
	}
	a := attempts[best]
	e := Endpoint{HTTP: a.HTTP, TLS: a.TLS, LeafPEM: a.LeafPEM, ChainPEM: a.ChainPEM, RawAttempts: attempts}
	e.HTTP.StartedAt = started
	e.HTTP.FinishedAt = time.Now().UTC()
	e.HTTP.DurationMS = time.Since(started).Milliseconds()
	e.HTTP.Complete = ctx.Err() == nil
	e.HTTP.InputIPs = task.IPs
	for i, a := range attempts {
		s := AttemptSummary{IP: a.HTTP.IP, Protocol: a.Protocol, Status: a.HTTP.Status, Stage: a.HTTP.Stage, Error: a.HTTP.Error, CertificateCount: a.HTTP.CertificateCount}
		if a.HTTP.Response != nil {
			s.HTTPStatusCode = a.HTTP.Response.StatusCode
		}
		if len(attempts) > 1 {
			s.Directory = attemptDir(i, a)
		}
		e.HTTP.Attempts = append(e.HTTP.Attempts, s)
	}
	return e
}
