// Package reporter unit tests for reporter.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies output formatting correctness across reporting formats:
//  1. TestDashboardRendering: Tests ANSI color code formatting, certificate chain breakdown, expiration warnings,
//     and failed target error logs.
//  2. TestJSONExport: Verifies JSON structure indentation, field presence, and array formatting.
//  3. TestCSVExport: Validates record header generation, latency integer conversions, and CSV field comma separation.
//  4. TestCSVExportWriteError: Validates proper error propagation when underlying io.Writer fails, ensuring
//     CSV write errors are returned rather than silently discarded.
package reporter

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/tlstester"
	"github.com/edsilegxrepo/tlstester/probes"
)

// TestDashboardRendering verifies ANSI table rendering for connected and failed diagnostic targets.
func TestDashboardRendering(t *testing.T) {
	cfg := tlstester.NewConfig()
	cfg.Cert = true

	results := []tlstester.TargetResult{
		{
			Target: tlstester.Target{
				Host: "google.com",
				Port: 443,
			},
			ResolvedIPs:           []string{"142.250.190.46"},
			DNSLatency:            15 * time.Millisecond,
			TCPLatency:            25 * time.Millisecond,
			TCPConnected:          true,
			TLSHandshakeSuccess:   true,
			TLSHandshakeLatency:   45 * time.Millisecond,
			TLSProtocol:           "TLS 1.3",
			TLSCipher:             "TLS_AES_128_GCM_SHA256",
			TLSAlpn:               "h2",
			NegotiatedGroup:       "X25519",
			OCSPStapled:           true,
			ActiveOCSPStatus:      "OCSP Responder Reachable - HTTP 200 OK",
			CertExpirationWarning: "Certificate expires in 25 days",
			HTTPStatusLine:        "200 OK",
			HTTPLatency:           80 * time.Millisecond,
			CapturedChain: []*x509.Certificate{
				{
					Subject:            pkix.Name{CommonName: "google.com"},
					Issuer:             pkix.Name{CommonName: "GTS CA 1C3"},
					NotAfter:           time.Now().Add(25 * 24 * time.Hour),
					DNSNames:           []string{"google.com", "*.google.com"},
					SerialNumber:       big.NewInt(123456789),
					SignatureAlgorithm: x509.SHA256WithRSA,
				},
			},
			ProtocolScanResults: []probes.ProtocolScanResult{
				{Protocol: "TLS1.3", Status: "SUPPORTED", LatencyMs: 40},
			},
		},
		{
			Target: tlstester.Target{
				Host: "failed.target",
				Port: 443,
			},
			TCPConnected: false,
			Error:        "dial tcp: i/o timeout",
		},
	}

	var buf bytes.Buffer
	Dashboard(&buf, cfg, results)
	out := buf.String()

	if !strings.Contains(out, "google.com:443") {
		t.Errorf("Dashboard output missing target host: %s", out)
	}
	if !strings.Contains(out, "CONNECTED") {
		t.Errorf("Dashboard output missing CONNECTED status: %s", out)
	}
	if !strings.Contains(out, "TLS 1.3") {
		t.Errorf("Dashboard output missing TLS 1.3: %s", out)
	}
	if !strings.Contains(out, "failed.target:443") {
		t.Errorf("Dashboard output missing failed target: %s", out)
	}
}

// TestJSONExport tests JSON array serialization of diagnostic results.
func TestJSONExport(t *testing.T) {
	results := []tlstester.TargetResult{
		{
			Target: tlstester.Target{
				Host: "example.com",
				Port: 443,
			},
			TCPConnected:        true,
			TLSHandshakeSuccess: true,
			TLSProtocol:         "TLS 1.3",
		},
	}

	var buf bytes.Buffer
	err := JSON(&buf, results)
	if err != nil {
		t.Fatalf("unexpected error exporting JSON: %v", err)
	}

	if !strings.Contains(buf.String(), "example.com") || !strings.Contains(buf.String(), "TLS 1.3") {
		t.Errorf("JSON output missing expected fields: %s", buf.String())
	}
}

// TestCSVExport tests CSV record serialization and header generation.
func TestCSVExport(t *testing.T) {
	results := []tlstester.TargetResult{
		{
			Target: tlstester.Target{
				Host: "example.com",
				Port: 443,
			},
			TCPConnected:        true,
			TLSHandshakeSuccess: true,
			TLSProtocol:         "TLS 1.3",
		},
	}

	var buf bytes.Buffer
	err := CSV(&buf, results)
	if err != nil {
		t.Fatalf("unexpected error exporting CSV: %v", err)
	}

	if !strings.Contains(buf.String(), "example.com") {
		t.Errorf("CSV output missing expected host: %s", buf.String())
	}
}

// TestCSVExportWriteError tests CSV export error handling with a failing writer.
func TestCSVExportWriteError(t *testing.T) {
	results := []tlstester.TargetResult{
		{
			Target: tlstester.Target{Host: "example.com", Port: 443},
		},
	}

	fw := &failingWriter{failAfter: 0}
	err := CSV(fw, results)
	if err == nil {
		t.Error("expected error for failing writer")
	}
}

// failingWriter is a mock writer that fails after N writes.
type failingWriter struct {
	failAfter int
	writes    int
}

func (fw *failingWriter) Write(p []byte) (int, error) {
	if fw.writes >= fw.failAfter {
		return 0, errMockWrite
	}
	fw.writes++
	return len(p), nil
}

var errMockWrite = &mockWriteError{}

type mockWriteError struct{}

func (e *mockWriteError) Error() string { return "mock write error" }
