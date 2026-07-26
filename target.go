// Package tlstester target data structures and multi-source target parser.
//
// OBJECTIVES:
// Provide parsing and validation of target endpoints from host:port strings, URLs, list
// input files/STDIN, and Cartesian hostname/port combinations.
//
// CORE COMPONENTS & DATA FLOW:
//   - Target (target.go): Struct representing a single host, port, and HTTP path target tuple.
//   - TargetResult (target.go): Comprehensive diagnostic output data structure compiling DNS, TCP,
//     TLS, X.509 cert, HTTP ALPN, active OCSP, and protocol scan results.
//   - ParseURLTarget & ParseTargets (target.go): Deduplicates and expands input target sources.
package tlstester

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"criticalsys.net/tlstester/probes"
)

// Target represents a single diagnostic target host, port, and optional HTTP path.
type Target struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	HTTPPath  string `json:"http_path,omitempty"`
	RawTarget string `json:"raw_target"`
}

// TargetResult aggregates complete diagnostic probe findings for a Target instance.
type TargetResult struct {
	Target                     Target                      `json:"target"`
	ResolvedIPs                []string                    `json:"resolved_ips"`
	DNSLatency                 time.Duration               `json:"dns_latency_ns"`
	TCPLatency                 time.Duration               `json:"tcp_latency_ns"`
	TCPConnected               bool                        `json:"tcp_connected"`
	TLSHandshakeSuccess        bool                        `json:"tls_handshake_success"`
	TLSHandshakeLatency        time.Duration               `json:"tls_handshake_latency_ns"`
	TLSProtocol                string                      `json:"tls_protocol,omitempty"`
	TLSCipher                  string                      `json:"tls_cipher,omitempty"`
	TLSAlpn                    string                      `json:"tls_alpn,omitempty"`
	NegotiatedGroup            string                      `json:"negotiated_group,omitempty"`
	OCSPStapled                bool                        `json:"ocsp_stapled"`
	CertChainTrusted           bool                        `json:"cert_chain_trusted"`
	CertChainTrustError        string                      `json:"cert_chain_trust_error,omitempty"`
	CertExpirationWarning      string                      `json:"cert_expiration_warning,omitempty"`
	ActiveOCSPStatus           string                      `json:"active_ocsp_status,omitempty"`
	CapturedChain              []*x509.Certificate         `json:"-"`
	HTTPStatusLine             string                      `json:"http_status_line,omitempty"`
	HTTPAltSvcLine             string                      `json:"http_alt_svc_line,omitempty"`
	HTTPLatency                time.Duration               `json:"http_latency_ns,omitempty"`
	ProtocolScanResults        []probes.ProtocolScanResult `json:"protocol_scan_results,omitempty"`
	ServerCiphers              []string                    `json:"server_ciphers,omitempty"`
	SessionResumptionAttempted bool                        `json:"session_resumption_attempted"`
	SessionResumptionSuccess   bool                        `json:"session_resumption_success"`
	SessionResumptionLatency   time.Duration               `json:"session_resumption_latency_ns"`
	QUICReachable              bool                        `json:"quic_reachable"`
	Error                      string                      `json:"error,omitempty"`
}

// ParseURLTarget parses a raw URL or endpoint string into a Target struct.
// Sanitizes whitespace, supplies default scheme `https://` if missing, and assigns default port 443.
func ParseURLTarget(val string) (Target, error) {
	val = strings.TrimSpace(val)
	raw := val
	urlStr := val
	if !strings.Contains(val, "://") {
		urlStr = "https://" + val
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target URL '%s': %w", val, err)
	}

	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("host cannot be empty in '%s'", val)
	}

	portStr := u.Port()
	port := 443
	if u.Scheme == "http" && portStr == "" {
		port = 80
	}
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return Target{}, fmt.Errorf("invalid port in '%s': %w", val, err)
		}
		port = p
	}

	return Target{
		Host:      host,
		Port:      port,
		HTTPPath:  u.RequestURI(),
		RawTarget: raw,
	}, nil
}

// ParseTargets compiles and deduplicates Target endpoints from all CLI inputs:
// - Hostport string (-hostport)
// - Repeated endpoints (-endpoint)
// - Repeated URLs (-url)
// - Target list files or STDIN (-file)
// - Cartesian grid expansion of hostnames (-hostname) across ports (-port)
func ParseTargets(cfg *Config) ([]Target, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	var targets []Target
	seen := make(map[string]bool)

	addTarget := func(t Target) {
		key := fmt.Sprintf("%s:%d%s", t.Host, t.Port, t.HTTPPath)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, t)
		}
	}

	if cfg.Hostport != "" {
		t, err := ParseURLTarget(cfg.Hostport)
		if err != nil {
			return nil, err
		}
		addTarget(t)
	}

	for _, ep := range cfg.Endpoints {
		t, err := ParseURLTarget(ep)
		if err != nil {
			return nil, err
		}
		addTarget(t)
	}

	for _, u := range cfg.URLs {
		t, err := ParseURLTarget(u)
		if err != nil {
			return nil, err
		}
		addTarget(t)
	}

	if cfg.File != "" {
		var scanner *bufio.Scanner
		if cfg.File == "-" {
			scanner = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(cfg.File)
			if err != nil {
				return nil, fmt.Errorf("failed to open target file '%s': %w", cfg.File, err)
			}
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to close target file '%s': %v\n", cfg.File, closeErr)
				}
			}()
			scanner = bufio.NewScanner(f)
		}

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			t, err := ParseURLTarget(line)
			if err == nil {
				addTarget(t)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading target file '%s': %w", cfg.File, err)
		}
	}

	if cfg.Hostnames != "" {
		hosts := strings.Split(cfg.Hostnames, ",")
		ports := strings.Split(cfg.Ports, ",")
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			for _, pStr := range ports {
				pStr = strings.TrimSpace(pStr)
				p, err := strconv.Atoi(pStr)
				if err != nil {
					p = 443
				}
				targetAddr := net.JoinHostPort(h, strconv.Itoa(p))
				t, err := ParseURLTarget(targetAddr)
				if err == nil {
					addTarget(t)
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets provided")
	}

	return targets, nil
}
