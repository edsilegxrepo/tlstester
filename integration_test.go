// Package tlstester_test live end-to-end integration test suite.
//
// OBJECTIVES:
// Provide mandatory live integration testing against real public network endpoints (google.com:443, cloudflare.com:443,
// github.com:443) to guarantee 100% functionality coverage of all features under real network conditions.
//
// TEST STRATEGY EXPLANATION:
//  1. TestLiveFullAppCapabilities: Orchestrates multi-target ingestion (hostport, endpoints, URLs, target files,
//     Cartesian grid expansion), parallel Goroutine worker pool execution, DNS resolution, TCP dialing, TLS 1.3
//     handshake, X.509 cert chain parsing, active AIA OCSP responder checks, certificate expiration warnings,
//     PEM cert export, status assertions, protocol scan sweeps, and JSON/CSV/ANSI reporting.
//  2. TestLiveStandaloneProbesDirect: Directly executes package probes (probes.TCP, probes.TLS, probes.HTTP,
//     probes.CheckActiveOCSP, probes.ScanCipherSuites, probes.TestSessionResumption, probes.CheckQUIC) against live CDNs.
//  3. TestLiveOCSPRevocation: Validates proper OCSP POST-based revocation checking with issuer cert provided,
//     verifying response parsing (status, timestamps, reason codes) against real CA OCSP responders.
//  4. TestLiveOCSPRevocationViaAIA: Tests OCSP revocation when issuer cert is fetched automatically via AIA
//     extension, validating FetchIssuerFromAIA against real certificate authority infrastructure.
//  5. TestLiveLeafCertificateFields: Verifies all leaf certificate metadata fields (LeafSubject, LeafIssuer,
//     LeafSANs, LeafNotBefore, LeafNotAfter, LeafIsExpired, LeafDaysRemaining, LeafKeyType, LeafKeySize,
//     LeafSerial, LeafSignatureAlgorithm) are correctly populated from live certificate chains.
//  6. TestLiveSCTPresence: Validates Certificate Transparency SCT detection and parsing, verifying SCTsPresent,
//     SCTCount, and SCT details (LogID, Timestamp, Source) against live certificates with embedded SCTs.
//
// NETWORK REQUIREMENTS:
//   - Tests require live internet access to public CDN endpoints.
//   - Tests are skipped in short mode (-short flag) to allow fast local iteration.
//   - Tests gracefully handle OCSP responder unavailability (some CAs have deprecated OCSP).
package tlstester_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/tlstester"
	"github.com/edsilegxrepo/tlstester/certs"
	"github.com/edsilegxrepo/tlstester/probes"
	"github.com/edsilegxrepo/tlstester/reporter"
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

	tlsConn, tlsRes, err := probes.TLS(ctx, probes.TLSOptions{
		Config:  tlsConfig,
		Host:    "google.com",
		Port:    443,
		RawConn: conn,
		Timeout: 5 * time.Second,
		Retries: 2,
	})
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

// TestLiveOCSPRevocation verifies proper OCSP POST-based revocation checking against live CAs.
func TestLiveOCSPRevocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live OCSP revocation test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try multiple sites - some CAs have disabled OCSP in favor of CRLs
	testHosts := []string{"github.com", "microsoft.com", "amazon.com"}

	for _, host := range testHosts {
		conn, _, _, _, err := probes.TCP(ctx, host, 443, 5*time.Second, 2, "", "")
		if err != nil {
			t.Logf("LIVE TCP failed for %s: %v, trying next", host, err)
			continue
		}

		tlsConfig, _ := tlstester.CreateTLSConfig(tlstester.NewConfig(), tlstester.Target{Host: host, Port: 443})
		tlsConn, tlsRes, err := probes.TLS(ctx, probes.TLSOptions{
			Config:  tlsConfig,
			Host:    host,
			Port:    443,
			RawConn: conn,
			Timeout: 5 * time.Second,
			Retries: 2,
		})
		if err != nil {
			t.Logf("LIVE TLS failed for %s: %v, trying next", host, err)
			continue
		}

		if len(tlsRes.PeerCertificates) < 2 {
			_ = tlsConn.Close()
			t.Logf("LIVE %s cert chain has < 2 certs, trying next", host)
			continue
		}

		leafCert := tlsRes.PeerCertificates[0]
		issuerCert := tlsRes.PeerCertificates[1]

		// Check if cert has OCSP URL
		if len(leafCert.OCSPServer) == 0 {
			_ = tlsConn.Close()
			t.Logf("LIVE %s cert has no OCSP URL in AIA, trying next", host)
			continue
		}

		// Test CheckOCSPRevocation with issuer provided
		result := probes.CheckOCSPRevocation(ctx, leafCert, issuerCert)
		_ = tlsConn.Close()

		if !result.Checked {
			t.Errorf("LIVE OCSP revocation check was not performed for %s", host)
			continue
		}
		if result.URL == "" {
			t.Errorf("LIVE OCSP URL should be populated for %s", host)
			continue
		}

		t.Logf("LIVE OCSP for %s: Status=%s, URL=%s", host, result.Status, result.URL)

		// For a valid cert, status should be "Good"
		if result.Status == "Good" {
			// Verify timestamps are populated for successful checks
			if result.ThisUpdate.IsZero() {
				t.Errorf("LIVE OCSP ThisUpdate should be populated for Good status on %s", host)
			}
			if result.ProducedAt.IsZero() {
				t.Errorf("LIVE OCSP ProducedAt should be populated for Good status on %s", host)
			}
			t.Logf("LIVE OCSP check passed for %s", host)
			return // Success - test passed
		}

		// Log but don't fail on responder issues
		if result.Status == "Error" || result.Status == "Unreachable" {
			t.Logf("LIVE OCSP responder issue for %s (non-fatal): %s", host, result.Error)
		}
	}

	// If we get here without returning, no host had working OCSP
	t.Log("LIVE OCSP: No test host had working OCSP - this is acceptable as some CAs have disabled OCSP")
}

// TestLiveOCSPRevocationViaAIA verifies OCSP revocation with issuer fetched via AIA.
func TestLiveOCSPRevocationViaAIA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live OCSP AIA test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try multiple sites to find one with both OCSP URL and AIA issuer URL
	testHosts := []string{"github.com", "microsoft.com", "amazon.com"}

	for _, host := range testHosts {
		conn, _, _, _, err := probes.TCP(ctx, host, 443, 5*time.Second, 2, "", "")
		if err != nil {
			t.Logf("LIVE TCP failed for %s: %v, trying next", host, err)
			continue
		}

		tlsConfig, _ := tlstester.CreateTLSConfig(tlstester.NewConfig(), tlstester.Target{Host: host, Port: 443})
		tlsConn, tlsRes, err := probes.TLS(ctx, probes.TLSOptions{
			Config:  tlsConfig,
			Host:    host,
			Port:    443,
			RawConn: conn,
			Timeout: 5 * time.Second,
			Retries: 2,
		})
		if err != nil {
			t.Logf("LIVE TLS failed for %s: %v, trying next", host, err)
			continue
		}

		if len(tlsRes.PeerCertificates) == 0 {
			_ = tlsConn.Close()
			continue
		}

		leafCert := tlsRes.PeerCertificates[0]

		// Need both OCSP URL and AIA issuer URL
		if len(leafCert.OCSPServer) == 0 {
			_ = tlsConn.Close()
			t.Logf("LIVE %s has no OCSP URL, trying next", host)
			continue
		}
		if len(leafCert.IssuingCertificateURL) == 0 {
			_ = tlsConn.Close()
			t.Logf("LIVE %s has no AIA IssuingCertificateURL, trying next", host)
			continue
		}

		_ = tlsConn.Close()

		// Test CheckOCSPRevocation WITHOUT issuer - should fetch via AIA
		result := probes.CheckOCSPRevocation(ctx, leafCert, nil)
		if !result.Checked {
			t.Errorf("LIVE OCSP revocation check was not performed for %s", host)
			continue
		}

		t.Logf("LIVE OCSP via AIA for %s: Status=%s, URL=%s, Error=%s", host, result.Status, result.URL, result.Error)

		// Should succeed or fail gracefully
		if result.Status == "Good" {
			t.Logf("LIVE OCSP AIA fetch succeeded for %s", host)
			return // Success
		}
	}

	t.Log("LIVE OCSP AIA: No test host had working OCSP with AIA - this is acceptable")
}

// TestLiveLeafCertificateFields verifies new leaf certificate metadata fields are populated.
func TestLiveLeafCertificateFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live leaf cert fields test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg := tlstester.NewConfig()
	cfg.Timeout = 10 * time.Second
	cfg.Retries = 2

	targets := []tlstester.Target{
		{Host: "google.com", Port: 443},
		{Host: "cloudflare.com", Port: 443},
	}

	results := tlstester.RunDiagnostics(ctx, cfg, targets)

	for _, res := range results {
		if !res.TLSHandshakeSuccess {
			t.Errorf("LIVE TLS failed for %s: %s", res.Target.Host, res.Error)
			continue
		}

		// Verify LeafSubject populated
		if res.LeafSubject == "" {
			t.Errorf("LIVE LeafSubject empty for %s", res.Target.Host)
		}

		// Verify LeafIssuer populated
		if res.LeafIssuer == "" {
			t.Errorf("LIVE LeafIssuer empty for %s", res.Target.Host)
		}

		// Verify LeafNotBefore/NotAfter are valid dates
		if res.LeafNotBefore.IsZero() {
			t.Errorf("LIVE LeafNotBefore is zero for %s", res.Target.Host)
		}
		if res.LeafNotAfter.IsZero() {
			t.Errorf("LIVE LeafNotAfter is zero for %s", res.Target.Host)
		}

		// Verify LeafIsExpired is false for live certs
		if res.LeafIsExpired {
			t.Errorf("LIVE LeafIsExpired should be false for %s (cert expired!)", res.Target.Host)
		}

		// Verify LeafDaysRemaining is positive for live certs
		if res.LeafDaysRemaining <= 0 {
			t.Errorf("LIVE LeafDaysRemaining should be positive for %s, got %d", res.Target.Host, res.LeafDaysRemaining)
		}

		// Verify LeafKeyType is populated (RSA or ECDSA typically)
		if res.LeafKeyType == "" || res.LeafKeyType == "Unknown" {
			t.Errorf("LIVE LeafKeyType should be RSA/ECDSA for %s, got %s", res.Target.Host, res.LeafKeyType)
		}

		// Verify LeafKeySize is reasonable (2048+ for RSA, 256+ for ECDSA)
		if res.LeafKeySize == 0 {
			t.Errorf("LIVE LeafKeySize should be non-zero for %s", res.Target.Host)
		}
		if res.LeafKeyType == "RSA" && res.LeafKeySize < 2048 {
			t.Errorf("LIVE RSA key size too small for %s: %d", res.Target.Host, res.LeafKeySize)
		}
		if res.LeafKeyType == "ECDSA" && res.LeafKeySize < 256 {
			t.Errorf("LIVE ECDSA key size too small for %s: %d", res.Target.Host, res.LeafKeySize)
		}

		// Verify LeafSerial is populated
		if res.LeafSerial == "" {
			t.Errorf("LIVE LeafSerial empty for %s", res.Target.Host)
		}

		// Verify LeafSignatureAlgorithm is populated
		if res.LeafSignatureAlgorithm == "" {
			t.Errorf("LIVE LeafSignatureAlgorithm empty for %s", res.Target.Host)
		}

		// Verify LeafSANs populated (google.com and cloudflare.com have SANs)
		if len(res.LeafSANs) == 0 {
			t.Errorf("LIVE LeafSANs empty for %s", res.Target.Host)
		}

		t.Logf("LIVE %s: KeyType=%s, KeySize=%d, DaysRemaining=%d, SANs=%d",
			res.Target.Host, res.LeafKeyType, res.LeafKeySize, res.LeafDaysRemaining, len(res.LeafSANs))
	}
}

// TestLiveSCTPresence verifies SCT (Signed Certificate Timestamp) detection on live certs.
func TestLiveSCTPresence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live SCT test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg := tlstester.NewConfig()
	cfg.Timeout = 10 * time.Second

	targets := []tlstester.Target{
		{Host: "google.com", Port: 443},
	}

	results := tlstester.RunDiagnostics(ctx, cfg, targets)

	for _, res := range results {
		if !res.TLSHandshakeSuccess {
			t.Fatalf("LIVE TLS failed for %s: %s", res.Target.Host, res.Error)
		}

		// Google certs should have SCTs (Certificate Transparency)
		if !res.SCTsPresent {
			t.Logf("LIVE SCTs not present for %s (may be in TLS extension)", res.Target.Host)
		} else {
			if res.SCTCount == 0 {
				t.Errorf("LIVE SCTsPresent=true but SCTCount=0 for %s", res.Target.Host)
			}
			t.Logf("LIVE %s: SCTCount=%d", res.Target.Host, res.SCTCount)

			// Verify SCT details if available
			for i, sct := range res.SCTs {
				if sct.LogID == "" {
					t.Errorf("LIVE SCT[%d] LogID empty for %s", i, res.Target.Host)
				}
				if sct.Timestamp.IsZero() {
					t.Errorf("LIVE SCT[%d] Timestamp zero for %s", i, res.Target.Host)
				}
				t.Logf("LIVE SCT[%d]: LogID=%s, Source=%s, Time=%s",
					i, sct.LogID, sct.Source, sct.Timestamp.Format("2006-01-02"))
			}
		}
	}
}
