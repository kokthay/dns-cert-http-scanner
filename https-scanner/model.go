package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const profile = "https-direct-ip-fallback-v2"

type Target struct {
	Rank   int    `json:"rank"`
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}
type InputRow struct {
	Rank   int      `json:"rank"`
	Domain string   `json:"domain"`
	IP     string   `json:"ip,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}
type DomainTask struct {
	Rank   int
	Domain string
	IPs    []string
}
type Response struct {
	StatusCode int                 `json:"status_code"`
	Status     string              `json:"status"`
	Protocol   string              `json:"protocol"`
	Headers    map[string][]string `json:"headers"`
	RawHeaders string              `json:"raw_headers,omitempty"`
}
type AttemptSummary struct {
	IP               string `json:"ip"`
	Protocol         string `json:"protocol"`
	Status           string `json:"status"`
	Stage            string `json:"stage"`
	Error            string `json:"error,omitempty"`
	CertificateCount int    `json:"certificate_count"`
	HTTPStatusCode   int    `json:"http_status_code,omitempty"`
	Directory        string `json:"directory,omitempty"`
}
type HTTPResult struct {
	Target
	Schema               string           `json:"schema"`
	Complete             bool             `json:"complete"`
	Port                 int              `json:"port"`
	URL                  string           `json:"url"`
	SNI                  string           `json:"sni"`
	Host                 string           `json:"host"`
	UserAgent            string           `json:"user_agent"`
	StartedAt            time.Time        `json:"started_at"`
	FinishedAt           time.Time        `json:"finished_at"`
	DurationMS           int64            `json:"duration_ms"`
	Success              bool             `json:"success"`
	Status               string           `json:"status"`
	Stage                string           `json:"stage"`
	Error                string           `json:"error,omitempty"`
	TLSHandshakeComplete bool             `json:"tls_handshake_complete"`
	CertificateCount     int              `json:"certificate_count"`
	Informational        []Response       `json:"informational_responses,omitempty"`
	Response             *Response        `json:"response,omitempty"`
	InputIPs             []string         `json:"input_ips,omitempty"`
	Attempts             []AttemptSummary `json:"attempts,omitempty"`
	ImportedFrom         string           `json:"imported_from,omitempty"`
}
type CertificateInfo struct {
	Index              int       `json:"index"`
	SHA256             string    `json:"sha256"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial_number_hex"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PolicyOIDs         []string  `json:"policy_oids,omitempty"`
}
type TLSResult struct {
	Target
	SNI                   string            `json:"sni"`
	HandshakeComplete     bool              `json:"handshake_complete"`
	HandshakeError        string            `json:"handshake_error,omitempty"`
	Version               string            `json:"version,omitempty"`
	CipherSuite           string            `json:"cipher_suite,omitempty"`
	ALPN                  string            `json:"alpn"`
	VerificationPerformed bool              `json:"verification_performed"`
	Certificates          []CertificateInfo `json:"certificates"`
}
type Observation struct {
	HTTP              HTTPResult
	TLS               TLSResult
	LeafPEM, ChainPEM []byte
	Protocol          string
	Err               error
}
type Endpoint struct {
	HTTP              HTTPResult
	TLS               TLSResult
	LeafPEM, ChainPEM []byte
	RawAttempts       []Observation
}

func normalize(t *Target) error {
	if t.Rank <= 0 {
		return errors.New("rank must be positive")
	}
	ip, err := netip.ParseAddr(t.IP)
	if err != nil || ip.Zone() != "" {
		return errors.New("ip must be a literal IPv4 or IPv6 address without zone")
	}
	t.IP = ip.Unmap().String()
	t.Domain = strings.ToLower(strings.TrimSuffix(t.Domain, "."))
	if len(t.Domain) == 0 || len(t.Domain) > 253 {
		return errors.New("invalid domain length")
	}
	for _, label := range strings.Split(t.Domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("invalid domain label length")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return errors.New("domain must use ASCII letters, digits, hyphens, underscores, and dots; use punycode for IDNs")
			}
		}
	}
	return nil
}
func targetDir(root string, t Target) string {
	name := fmt.Sprintf("%07d-%s", t.Rank, t.Domain)
	if len(name) > 255 {
		h := sha256.Sum256([]byte(t.Domain))
		name = fmt.Sprintf("%07d-%s-%x", t.Rank, t.Domain[:220], h[:8])
	}
	return filepath.Join(root, fmt.Sprintf("%03d", (t.Rank-1)/10000), name)
}
func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
func sameIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ip := range a {
		if !contains(b, ip) {
			return false
		}
	}
	return true
}

type codedError struct{ Code, Message string }

func (e *codedError) Error() string          { return e.Message }
func codeError(code string, err error) error { return &codedError{code, err.Error()} }
func classify(stage string, err error) string {
	if err == nil {
		return "OK"
	}
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.Code
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return "TIMEOUT"
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELED"
	}
	for _, p := range []struct {
		err  error
		code string
	}{{syscall.ECONNREFUSED, "CONNECTION_REFUSED"}, {syscall.ECONNRESET, "CONNECTION_RESET"}, {syscall.ENETUNREACH, "NETWORK_UNREACHABLE"}, {syscall.EHOSTUNREACH, "HOST_UNREACHABLE"}, {syscall.EADDRNOTAVAIL, "ADDRESS_UNAVAILABLE"}, {syscall.EPIPE, "CONNECTION_CLOSED"}} {
		if errors.Is(err, p.err) {
			return p.code
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "CONNECTION_CLOSED"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no application protocol") || strings.Contains(msg, "no application_protocol") {
		return "ALPN_UNSUPPORTED"
	}
	if strings.Contains(msg, "header list") && strings.Contains(msg, "large") || strings.Contains(msg, "response headers exceeded") || strings.Contains(msg, "response headers exceed") {
		return "HEADER_LIMIT"
	}
	if stage == "tcp" {
		return "CONNECTION_ERROR"
	}
	if stage == "tls" {
		return "TLS_HANDSHAKE_ERROR"
	}
	return "HTTP_ERROR"
}
func atomicWrite(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".scan-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0644); e == nil {
		_, e = f.Write(data)
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, append(b, '\n'))
}
func saveFiles(dir string, h HTTPResult, t TLSResult, leaf, chain []byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "http.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	for name, b := range map[string][]byte{"certificate.pem": leaf, "chain.pem": chain} {
		p := filepath.Join(dir, name)
		if len(b) == 0 {
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				return e
			}
		} else if e := atomicWrite(p, b); e != nil {
			return e
		}
	}
	if e := writeJSON(filepath.Join(dir, "tls.json"), t); e != nil {
		return e
	}
	return writeJSON(filepath.Join(dir, "http.json"), h)
}
func saveEndpoint(dir string, e Endpoint) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "http.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Only this scanner's private attempt subtree is replaced.
	if len(e.RawAttempts) > 0 {
		if err := os.RemoveAll(filepath.Join(dir, "attempts")); err != nil {
			return err
		}
	}
	if len(e.RawAttempts) > 1 {
		for i, a := range e.RawAttempts {
			if err := saveFiles(filepath.Join(dir, e.HTTP.Attempts[i].Directory), a.HTTP, a.TLS, a.LeafPEM, a.ChainPEM); err != nil {
				return err
			}
		}
	}
	return saveFiles(dir, e.HTTP, e.TLS, e.LeafPEM, e.ChainPEM)
}
func loadCompleted(dir string, task DomainTask, c Config) (Endpoint, bool) {
	var e Endpoint
	if !c.Resume {
		return e, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.json"))
	if err != nil || json.Unmarshal(b, &e.HTTP) != nil {
		return e, false
	}
	h := e.HTTP
	if !h.Complete || h.Schema != profile || h.Rank != task.Rank || h.Domain != task.Domain || h.Port != c.Port || h.UserAgent != c.UserAgent || c.RetryFailed && !h.Success {
		return e, false
	}
	if h.Success {
		if !contains(task.IPs, h.IP) {
			return e, false
		}
	} else if !sameIPs(h.InputIPs, task.IPs) {
		return e, false
	}
	b, err = os.ReadFile(filepath.Join(dir, "tls.json"))
	if err != nil || json.Unmarshal(b, &e.TLS) != nil || e.TLS.Target != h.Target {
		return e, false
	}
	if h.CertificateCount > 0 {
		for _, n := range []string{"certificate.pem", "chain.pem"} {
			if st, err := os.Stat(filepath.Join(dir, n)); err != nil || st.Size() == 0 {
				return e, false
			}
		}
	}
	return e, true
}
func importLegacy(root string, task DomainTask, c Config) (Endpoint, bool) {
	var e Endpoint
	dir := targetDir(root, Target{Rank: task.Rank, Domain: task.Domain})
	b, err := os.ReadFile(filepath.Join(dir, "http.json"))
	if err != nil || json.Unmarshal(b, &e.HTTP) != nil {
		return e, false
	}
	h := e.HTTP
	if h.Schema != "https-direct-ip-http1-v1" || !h.Complete || !h.Success || h.CertificateCount == 0 || h.Response == nil || h.Rank != task.Rank || h.Domain != task.Domain || !contains(task.IPs, h.IP) || h.Port != c.Port || h.UserAgent != c.UserAgent {
		return e, false
	}
	b, err = os.ReadFile(filepath.Join(dir, "tls.json"))
	if err != nil || json.Unmarshal(b, &e.TLS) != nil || e.TLS.Target != h.Target {
		return e, false
	}
	e.LeafPEM, err = os.ReadFile(filepath.Join(dir, "certificate.pem"))
	if err != nil || len(e.LeafPEM) == 0 {
		return e, false
	}
	e.ChainPEM, err = os.ReadFile(filepath.Join(dir, "chain.pem"))
	if err != nil || len(e.ChainPEM) == 0 {
		return e, false
	}
	e.HTTP.Schema = profile
	e.HTTP.Status = "OK"
	e.HTTP.Error = ""
	e.HTTP.Stage = "complete"
	e.HTTP.InputIPs = task.IPs
	e.HTTP.ImportedFrom = "legacy_http1"
	e.TLS.VerificationPerformed = false
	e.HTTP.Attempts = []AttemptSummary{{IP: h.IP, Protocol: "HTTP/1.1", Status: "OK", Stage: "complete", CertificateCount: h.CertificateCount, HTTPStatusCode: h.Response.StatusCode}}
	return e, true
}

type FailureRecord struct {
	Rank                int              `json:"rank"`
	Domain              string           `json:"domain"`
	IP                  string           `json:"ip"`
	Status              string           `json:"status"`
	Error               string           `json:"error"`
	Stage               string           `json:"stage"`
	ObservedAt          time.Time        `json:"observed_at"`
	CertificateObtained bool             `json:"certificate_obtained"`
	HTTPObtained        bool             `json:"http_obtained"`
	Attempts            []AttemptSummary `json:"attempts"`
	ResultDirectory     string           `json:"result_directory"`
}

func syncFailure(root, dir string, e Endpoint) (*FailureRecord, error) {
	failureDir := targetDir(root, e.HTTP.Target)
	path := filepath.Join(failureDir, "errors.json")
	if e.HTTP.Success {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		_ = os.Remove(failureDir)
		return nil, nil
	}
	record := FailureRecord{Rank: e.HTTP.Rank, Domain: e.HTTP.Domain, IP: e.HTTP.IP, Status: e.HTTP.Status, Error: e.HTTP.Error, Stage: e.HTTP.Stage, ObservedAt: e.HTTP.StartedAt, CertificateObtained: e.HTTP.CertificateCount > 0, HTTPObtained: e.HTTP.Response != nil, Attempts: e.HTTP.Attempts, ResultDirectory: dir}
	if err := os.MkdirAll(failureDir, 0755); err != nil {
		return nil, err
	}
	if err := writeJSON(path, record); err != nil {
		return nil, err
	}
	return &record, nil
}
