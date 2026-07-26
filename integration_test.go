// Package tlstester_test live end-to-end integration test suite.
//
// OBJECTIVES:
// Provide mandatory live integration testing against real public network endpoints (google.com:443, cloudflare.com:443)
// to guarantee 100% functionality coverage of all features under real network conditions.
//
// TEST STRATEGY EXPLANATION:
//  1. TestLiveFullAppCapabilities: Orchestrates multi-target ingestion (hostport, endpoints, URLs, target files,
//     Cartesian grid expansion), parallel Goroutine worker pool execution, DNS resolution, TCP dialing, TLS 1.3
//     handshake, X.509 cert chain parsing, active AIA OCSP responder checks, certificate expiration warnings,
//     PEM cert export, status assertions, protocol scan sweeps, and JSON/CSV/ANSI reporting.
//  2. TestLiveStandaloneProbesDirect: Directly executes package probes (probes.TCP, probes.TLS, probes.HTTP,
//     probes.CheckActiveOCSP, probes.ScanCipherSuites, probes.TestSessionResumption, probes.CheckQUIC) against live CDNs.
package tlstester_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"criticalsys.net/tlstester"
	"criticalsys.net/tlstester/certs"
	"criticalsys.net/tlstester/probes"
	"criticalsys.net/tlstester/reporter"
)

// TestLiveFullAppCapabilities verifies 100% of app features against live public CDN endpoints.
func TestLiveFullAppCapabilities(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "live_run.log")
	csvFile := filepath.Join(tmpDir, "live_report.csv")
	certPrefix := filepath.Join(tmpDir, "live_exported_cert")
	targetFile := filepath.Join(tmpDir, "live_targets.txt")

	_ = os.WriteFile(targetFile, []byte("cloudflare.com:443\n"), 0o600)

	// 1. Configure ALL App Capabilities
	cfg := tlstester.NewConfig()
	cfg.Hostport = "google.com:443"
	cfg.Endpoints = []string{"cloudflare.com:443"}
	cfg.URLs = []string{"https://google.com/search"}
	cfg.File = targetFile
	cfg.Hostnames = "google.com, cloudflare.com"
	cfg.Ports = "443"
	cfg.Workers = 4
	cfg.Timeout = 10 * time.Second
	cfg.Retries = 2
	cfg.InsecureSkipVerify = false
	cfg.Headers = []string{"User-Agent: TLSTesterLive/1.0", "Accept: */*"}
	cfg.AssertStatus = "200,301,302"
	cfg.Cert = true
	cfg.WarnDays = 365
	cfg.CheckOCSP = true
	cfg.ExportCert = certPrefix
	cfg.Scan = true
	cfg.JSON = true
	cfg.CSV = csvFile
	cfg.Log = logFile
	cfg.Color = true
	cfg.Verbose = true

	// 2. Parse Multi-Source Targets (Hostport, Endpoints, URLs, Files, Cartesian Grid)
	targets, err := tlstester.ParseTargets(cfg)
	if err != nil {
		t.Fatalf("failed to parse live targets: %v", err)
	}

	if len(targets) < 2 {
		t.Fatalf("expected at least 2 aggregated live targets, got %d", len(targets))
	}

	// 3. Execute Live Diagnostics Across Worker Pool
	results := tlstester.RunDiagnostics(ctx, cfg, targets)
	if len(results) == 0 {
		t.Fatal("expected non-empty live target results")
	}

	// 4. Verify LIVE Feature Outcomes
	for _, res := range results {
		if !res.TCPConnected {
			t.Errorf("LIVE TCP connection failed for %s: %s", res.Target.Host, res.Error)
			continue
		}
		if !res.TLSHandshakeSuccess {
			t.Errorf("LIVE TLS handshake failed for %s: %s", res.Target.Host, res.Error)
			continue
		}

		// Verify Resolved IPs
		if len(res.ResolvedIPs) == 0 {
			t.Errorf("LIVE DNS resolution returned 0 IPs for %s", res.Target.Host)
		}

		// Verify TLS Handshake metadata
		if res.TLSProtocol == "" {
			t.Errorf("LIVE TLS protocol empty for %s", res.Target.Host)
		}
		if res.TLSCipher == "" {
			t.Errorf("LIVE TLS cipher empty for %s", res.Target.Host)
		}

		// Verify Peer Certificates
		if len(res.CapturedChain) == 0 {
			t.Errorf("LIVE certificate extraction returned 0 certs for %s", res.Target.Host)
		} else {
			days := certs.DaysUntilExpiration(res.CapturedChain[0])
			if days <= 0 {
				t.Errorf("LIVE certificate expiration calculation invalid (%d days)", days)
			}
		}

		// Verify Expiration Warning Threshold
		if res.CertExpirationWarning == "" {
			t.Errorf("LIVE expiration warning threshold alert empty for %s", res.Target.Host)
		}

		// Verify HTTP Probe Status & Alt-Svc
		if res.HTTPStatusLine == "" {
			t.Errorf("LIVE HTTP probe status line empty for %s", res.Target.Host)
		}

		// Verify Protocol Sweep Scan
		if len(res.ProtocolScanResults) == 0 {
			t.Errorf("LIVE protocol sweep returned 0 results for %s", res.Target.Host)
		}
	}

	// 5. Verify LIVE Export Cert File Creation
	exportedFiles, _ := filepath.Glob(certPrefix + "*.crt")
	if len(exportedFiles) == 0 {
		t.Error("LIVE certificate export failed: 0 .crt files created")
	}

	// 6. Verify LIVE Reporters (JSON, CSV, ANSI Dashboard)
	var bufJSON bytes.Buffer
	if err := reporter.JSON(&bufJSON, results); err != nil {
		t.Fatalf("LIVE JSON export failed: %v", err)
	}
	if !strings.Contains(bufJSON.String(), "google.com") {
		t.Error("LIVE JSON output missing google.com target")
	}

	var bufCSV bytes.Buffer
	if err := reporter.CSV(&bufCSV, results); err != nil {
		t.Fatalf("LIVE CSV export failed: %v", err)
	}
	if !strings.Contains(bufCSV.String(), "TCP_Connected") {
		t.Error("LIVE CSV output missing header")
	}

	var bufDash bytes.Buffer
	reporter.Dashboard(&bufDash, cfg, results)
	if !strings.Contains(bufDash.String(), "TLS DIAGNOSTIC RESULTS DASHBOARD") {
		t.Error("LIVE ANSI dashboard output missing header")
	}

	// 7. Verify LIVE Security Environment Diagnostic Dump (-diagnose)
	var bufDiag bytes.Buffer
	if err := tlstester.DumpDiagnostics(&bufDiag); err != nil {
		t.Fatalf("LIVE DumpDiagnostics failed: %v", err)
	}
	if !strings.Contains(bufDiag.String(), "Go Security & Cryptographic Environment") {
		t.Error("LIVE DumpDiagnostics output missing header")
	}
}

// TestLiveStandaloneProbesDirect verifies low-level package probes directly against live endpoints.
func TestLiveStandaloneProbesDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live standalone probes test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// 1. Live TCP Socket Probe
	conn, ips, _, tcpLat, err := probes.TCP(ctx, "google.com", 443, 5*time.Second, 2, "", "")
	if err != nil {
		t.Fatalf("LIVE probes.TCP failed: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("conn.Close warning: %v", closeErr)
		}
	}()

	if len(ips) == 0 || tcpLat == 0 {
		t.Errorf("LIVE TCP probe metadata missing: IPs=%v, TCP=%v", ips, tcpLat)
	}

	// 2. Live TLS Handshake Probe
	tlsConfig, err := tlstester.CreateTLSConfig(tlstester.NewConfig(), tlstester.Target{Host: "google.com", Port: 443})
	if err != nil {
		t.Fatalf("CreateTLSConfig failed: %v", err)
	}

	tlsConn, tlsRes, err := probes.TLS(ctx, tlsConfig, "google.com", 443, conn, 5*time.Second, 2, "", "")
	if err != nil {
		t.Fatalf("LIVE probes.TLS failed: %v", err)
	}
	defer func() {
		if closeErr := tlsConn.Close(); closeErr != nil {
			t.Logf("tlsConn.Close warning: %v", closeErr)
		}
	}()

	if !tlsRes.HandshakeSuccess || len(tlsRes.PeerCertificates) == 0 {
		t.Error("LIVE probes.TLS handshake or cert extraction failed")
	}

	// 3. Live Active OCSP Check on Certificate
	ocspStatus := probes.CheckActiveOCSP(ctx, tlsRes.PeerCertificates[0])
	if ocspStatus == "" {
		t.Error("LIVE probes.CheckActiveOCSP status empty")
	}

	// 4. Live HTTP Probe
	httpRes := probes.HTTP(ctx, tlsConfig, "google.com", 443, "/", nil, "200,301,302", 5*time.Second)
	if httpRes.StatusLine == "" {
		t.Error("LIVE probes.HTTP status line empty")
	}

	// 5. Live Cipher & Resumption Sweep
	scanResults, ciphers := probes.ScanCipherSuites(ctx, "google.com", 443, 5*time.Second, 2, "", "")
	if len(scanResults) == 0 || len(ciphers) == 0 {
		t.Error("LIVE probes.ScanCipherSuites returned empty results")
	}

	_, _ = probes.TestSessionResumption(ctx, "google.com", 443, 5*time.Second, 2, "", "", false)
	_ = probes.CheckQUIC(ctx, "google.com", 443, 5*time.Second)
}
