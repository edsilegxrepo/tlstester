// Package tlstester runner orchestration engine and TLS configuration builder.
//
// OBJECTIVES:
// Provide thread-safe Goroutine worker pool execution (`RunDiagnostics`) to process diagnostic targets
// concurrently with context deadlines, clean channel synchronization, and zero state mutations.
//
// CORE COMPONENTS & DATA FLOW:
//   - CreateTLSConfig (runner.go): Initializes a tls.Config with requested TLS versions, cipher suites,
//     SNI options, custom truststores, and mTLS client certificates.
//   - RunDiagnostics (runner.go): Orchestrates parallel task dispatch across worker Goroutines.
//   - ExecuteTarget (runner.go): Executes sequential diagnostic steps (TCP socket, TLS handshake,
//     HTTP probe, OCSP check, protocol sweep) for a single target tuple.
package tlstester

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"criticalsys.net/tlstester/certs"
	"criticalsys.net/tlstester/probes"
)

// CreateTLSConfig initializes a tls.Config based on Config parameters and target properties.
// Configures TLS min/max versions, cipher suites, SNI overrides, root truststores, and mTLS client keypairs.
func CreateTLSConfig(cfg *Config, target Target) (*tls.Config, error) {
	if cfg == nil {
		cfg = NewConfig()
	}

	/* #nosec G402 -- User-controlled parameter: InsecureSkipVerify defaults to false (enforcing full chain validation) and is only enabled when explicit -insecure CLI flag is passed */
	tlsConfig := &tls.Config{ // nosemgrep
		InsecureSkipVerify: cfg.InsecureSkipVerify, // nosemgrep
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12, // nosemgrep
	}

	if cfg.NoSNI {
		tlsConfig.ServerName = ""
	} else if cfg.SNI != "" {
		tlsConfig.ServerName = cfg.SNI
	} else {
		tlsConfig.ServerName = target.Host
	}

	if cfg.TLSVersion != "" {
		switch strings.ToUpper(cfg.TLSVersion) {
		case "TLS1.0", "TLS10":
			tlsConfig.MinVersion = tls.VersionTLS10
			tlsConfig.MaxVersion = tls.VersionTLS10
		case "TLS1.1", "TLS11":
			tlsConfig.MinVersion = tls.VersionTLS11
			tlsConfig.MaxVersion = tls.VersionTLS11
		case "TLS1.2", "TLS12":
			tlsConfig.MinVersion = tls.VersionTLS12
			tlsConfig.MaxVersion = tls.VersionTLS12
		case "TLS1.3", "TLS13":
			tlsConfig.MinVersion = tls.VersionTLS13
			tlsConfig.MaxVersion = tls.VersionTLS13
		default:
			return nil, fmt.Errorf("invalid TLS version: %s", cfg.TLSVersion)
		}
	}

	if cfg.CipherSuite != "" {
		var ciphers []uint16
		for _, suite := range tls.CipherSuites() {
			if strings.EqualFold(suite.Name, cfg.CipherSuite) {
				ciphers = append(ciphers, suite.ID)
				break
			}
		}
		if len(ciphers) == 0 {
			return nil, fmt.Errorf("invalid Cipher Suite: %s", cfg.CipherSuite)
		}
		tlsConfig.CipherSuites = ciphers
	}

	if cfg.Truststore != "" || cfg.Keystore != "" {
		tsPath := cfg.Truststore
		if tsPath == "" {
			tsPath = cfg.Keystore
		}
		rootPool, err := certs.LoadTruststore(tsPath)
		if err == nil && rootPool != nil {
			tlsConfig.RootCAs = rootPool
		}
	}

	if cfg.Keystore != "" {
		clientCerts, err := certs.LoadClientKeypair(cfg.Keystore)
		if err == nil && len(clientCerts) > 0 {
			tlsConfig.Certificates = clientCerts
		}
	}

	return tlsConfig, nil
}

// RunDiagnostics orchestrates parallel target probing using a context-aware Goroutine worker pool.
// Returns a consolidated slice of TargetResult objects upon worker pool completion.
func RunDiagnostics(ctx context.Context, cfg *Config, targets []Target) []TargetResult {
	if cfg == nil {
		cfg = NewConfig()
	}

	targetChan := make(chan Target, len(targets))
	resultChan := make(chan TargetResult, len(targets))

	for _, t := range targets {
		targetChan <- t
	}
	close(targetChan)

	numWorkers := cfg.Workers
	if numWorkers > len(targets) {
		numWorkers = len(targets)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				select {
				case <-ctx.Done():
					return
				default:
					res := ExecuteTarget(ctx, cfg, target)
					resultChan <- res
				}
			}
		}()
	}

	wg.Wait()
	close(resultChan)

	var results []TargetResult
	for res := range resultChan {
		results = append(results, res)
	}

	return results
}

// ExecuteTarget executes the complete sequence of granular diagnostic probes against a single target:
// 1. TCP socket dialing & proxy tunnel handshake.
// 2. TLS handshake, cipher/protocol negotiation, cert chain extraction.
// 3. Certificate expiration threshold calculation & active AIA OCSP query.
// 4. HTTP application probe with status assertion & Alt-Svc header extraction.
// 5. Capability scan across supported TLS versions, session ticket resumption, & QUIC datagram reachability.
func ExecuteTarget(ctx context.Context, cfg *Config, target Target) TargetResult {
	if cfg == nil {
		cfg = NewConfig()
	}

	// 1. TCP Socket & Proxy Probe
	rawConn, ips, dnsLatency, tcpLatency, dialErr := probes.TCP(ctx, target.Host, target.Port, cfg.Timeout, cfg.Retries, cfg.Proxy, cfg.ProxyType)

	result := TargetResult{
		Target:      target,
		ResolvedIPs: ips,
		DNSLatency:  dnsLatency,
		TCPLatency:  tcpLatency,
	}

	if dialErr != nil {
		result.TCPConnected = false
		result.Error = dialErr.Error()
		return result
	}

	result.TCPConnected = true

	// 2. TLS Handshake Probe
	tlsConfig, err := CreateTLSConfig(cfg, target)
	if err != nil {
		_ = rawConn.Close()
		result.Error = fmt.Sprintf("Failed to create TLS config: %v", err)
		return result
	}

	tlsConn, tlsRes, handshakeErr := probes.TLS(ctx, tlsConfig, target.Host, target.Port, rawConn, cfg.Timeout, cfg.Retries, cfg.Proxy, cfg.ProxyType)
	result.TLSHandshakeSuccess = tlsRes.HandshakeSuccess
	result.TLSHandshakeLatency = tlsRes.HandshakeLatency
	result.TLSProtocol = tlsRes.Protocol
	result.TLSCipher = tlsRes.Cipher
	result.TLSAlpn = tlsRes.Alpn
	result.NegotiatedGroup = tlsRes.NegotiatedGroup
	result.OCSPStapled = tlsRes.OCSPStapled
	result.CapturedChain = tlsRes.PeerCertificates
	result.CertChainTrusted = tlsRes.CertTrusted
	result.CertChainTrustError = tlsRes.TrustError

	if len(tlsRes.PeerCertificates) > 0 {
		cert := tlsRes.PeerCertificates[0]
		daysRemaining := certs.DaysUntilExpiration(cert)
		if cfg.WarnDays > 0 && daysRemaining <= cfg.WarnDays {
			result.CertExpirationWarning = fmt.Sprintf("Certificate expires in %d days (%s)", daysRemaining, cert.NotAfter.Format(time.RFC3339))
		}
		if cfg.CheckOCSP {
			result.ActiveOCSPStatus = probes.CheckActiveOCSP(ctx, cert)
		}
		if cfg.ExportCert != "" {
			_ = probes.ExportCertificates(cfg.ExportCert, target.Host, target.Port, tlsRes.PeerCertificates)
		}
	}

	if handshakeErr != nil {
		_ = rawConn.Close()
		result.Error = handshakeErr.Error()
		return result
	}

	defer func() {
		if closeErr := tlsConn.Close(); closeErr != nil && result.Error == "" {
			result.Error = fmt.Sprintf("TLS connection close error: %v", closeErr)
		}
	}()

	// 3. HTTP Application Probe
	httpRes := probes.HTTP(ctx, tlsConfig, target.Host, target.Port, target.HTTPPath, cfg.Headers, cfg.AssertStatus, cfg.Timeout)
	result.HTTPStatusLine = httpRes.StatusLine
	result.HTTPAltSvcLine = httpRes.AltSvc
	result.HTTPLatency = httpRes.Latency
	if httpRes.Error != "" {
		result.Error = httpRes.Error
	}

	// 4. Cipher Sweep & Session Resumption Scan
	if cfg.Scan {
		scanResults, ciphers := probes.ScanCipherSuites(ctx, target.Host, target.Port, cfg.Timeout, cfg.Retries, cfg.Proxy, cfg.ProxyType)
		result.ProtocolScanResults = scanResults
		result.ServerCiphers = ciphers

		resumed, latency := probes.TestSessionResumption(ctx, target.Host, target.Port, cfg.Timeout, cfg.Retries, cfg.Proxy, cfg.ProxyType, cfg.InsecureSkipVerify)
		result.SessionResumptionAttempted = true
		result.SessionResumptionSuccess = resumed
		result.SessionResumptionLatency = latency

		result.QUICReachable = probes.CheckQUIC(ctx, target.Host, target.Port, cfg.Timeout)
	}

	return result
}
