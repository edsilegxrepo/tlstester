// Package tlstester runner orchestration engine and TLS configuration builder.
//
// OBJECTIVES:
// Provide thread-safe Goroutine worker pool execution (`RunDiagnostics`) to process diagnostic targets
// concurrently with context deadlines, clean channel synchronization, result order preservation, and
// zero state mutations.
//
// CORE COMPONENTS & DATA FLOW:
//   - CreateTLSConfig (runner.go): Initializes a tls.Config with requested TLS versions, cipher suites,
//     SNI options, custom truststores, and mTLS client certificates.
//   - RunDiagnostics (runner.go): Orchestrates parallel task dispatch across worker Goroutines with
//     indexed channels to preserve input order in output results.
//   - ExecuteTarget (runner.go): Executes sequential diagnostic steps (TCP socket, TLS handshake,
//     HTTP probe, OCSP check, protocol sweep) for a single target tuple, extracting leaf certificate
//     metadata (subject, issuer, SANs, expiration, key type/size) for library consumers.
//   - getKeyInfo (runner.go): Extracts public key type (RSA, ECDSA, Ed25519) and bit size from certificates.
//
// CONCURRENCY MODEL:
//   - Worker pool size bounded by min(cfg.Workers, len(targets)).
//   - Channel buffer sizes bounded by maxChannelBuffer (10000) to prevent OOM on large target lists.
//   - Indexed result collection preserves input target order regardless of completion sequence.
package tlstester

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edsilegxrepo/tlstester/certs"
	"github.com/edsilegxrepo/tlstester/probes"
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

// indexedTarget pairs a target with its original index for order preservation.
type indexedTarget struct {
	index  int
	target Target
}

// indexedResult pairs a result with its original index for order preservation.
type indexedResult struct {
	index  int
	result TargetResult
}

// maxChannelBuffer bounds channel buffer sizes to prevent OOM on large target lists.
// Targets exceeding this limit queue in the producer goroutine rather than buffering.
const maxChannelBuffer = 10000

// RunDiagnostics orchestrates parallel target probing using a context-aware Goroutine worker pool.
// Returns a consolidated slice of TargetResult objects in the same order as input targets.
func RunDiagnostics(ctx context.Context, cfg *Config, targets []Target) []TargetResult {
	if cfg == nil {
		cfg = NewConfig()
	}

	if len(targets) == 0 {
		return nil
	}

	// Bound channel buffer size to prevent OOM
	bufSize := len(targets)
	if bufSize > maxChannelBuffer {
		bufSize = maxChannelBuffer
	}

	targetChan := make(chan indexedTarget, bufSize)
	resultChan := make(chan indexedResult, bufSize)

	// Feed targets with their indices
	go func() {
		for i, t := range targets {
			select {
			case <-ctx.Done():
				close(targetChan)
				return
			case targetChan <- indexedTarget{index: i, target: t}:
			}
		}
		close(targetChan)
	}()

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
			for it := range targetChan {
				select {
				case <-ctx.Done():
					return
				default:
					res := ExecuteTarget(ctx, cfg, it.target)
					select {
					case <-ctx.Done():
						return
					case resultChan <- indexedResult{index: it.index, result: res}:
					}
				}
			}
		}()
	}

	// Close result channel after all workers done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and sort by original index
	results := make([]TargetResult, len(targets))
	received := 0
	for ir := range resultChan {
		results[ir.index] = ir.result
		received++
	}

	// If cancelled early, trim to received results
	if received < len(targets) {
		results = results[:received]
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
		result.Error = fmt.Sprintf("failed to create TLS config: %v", err)
		return result
	}

	tlsConn, tlsRes, handshakeErr := probes.TLS(ctx, probes.TLSOptions{
		Config:    tlsConfig,
		Host:      target.Host,
		Port:      target.Port,
		RawConn:   rawConn,
		Timeout:   cfg.Timeout,
		Retries:   cfg.Retries,
		ProxyAddr: cfg.Proxy,
		ProxyType: cfg.ProxyType,
	})
	result.TLSHandshakeSuccess = tlsRes.HandshakeSuccess
	result.TLSHandshakeLatency = tlsRes.HandshakeLatency
	result.TLSProtocol = tlsRes.Protocol
	result.TLSCipher = tlsRes.Cipher
	result.TLSAlpn = tlsRes.Alpn
	result.NegotiatedGroup = tlsRes.NegotiatedGroup
	result.OCSPStapled = tlsRes.OCSPStapled
	result.SCTsPresent = tlsRes.SCTsPresent
	result.SCTCount = tlsRes.SCTCount
	result.SCTs = tlsRes.SCTs
	result.CapturedChain = tlsRes.PeerCertificates
	result.CertChainTrusted = tlsRes.CertTrusted
	result.CertChainTrustError = tlsRes.TrustError

	if len(tlsRes.PeerCertificates) > 0 {
		cert := tlsRes.PeerCertificates[0]
		daysRemaining := certs.DaysUntilExpiration(cert)

		// Populate leaf certificate info for library consumers
		result.LeafSubject = cert.Subject.String()
		result.LeafIssuer = cert.Issuer.String()
		result.LeafSANs = cert.DNSNames
		result.LeafNotBefore = cert.NotBefore
		result.LeafNotAfter = cert.NotAfter
		result.LeafIsExpired = time.Now().After(cert.NotAfter)
		result.LeafDaysRemaining = daysRemaining
		result.LeafSerial = fmt.Sprintf("%X", cert.SerialNumber)
		result.LeafSignatureAlgorithm = cert.SignatureAlgorithm.String()
		result.LeafKeyType, result.LeafKeySize = getKeyInfo(cert)

		if cfg.WarnDays > 0 && daysRemaining <= cfg.WarnDays {
			result.CertExpirationWarning = fmt.Sprintf("Certificate expires in %d days (%s)", daysRemaining, cert.NotAfter.Format(time.RFC3339))
		}
		if cfg.CheckOCSP {
			result.ActiveOCSPStatus = probes.CheckActiveOCSP(ctx, cert)
			// Also perform proper OCSP revocation check if we have the issuer cert
			if len(tlsRes.PeerCertificates) > 1 {
				issuer := tlsRes.PeerCertificates[1]
				ocspResult := probes.CheckOCSPRevocation(ctx, cert, issuer)
				result.OCSPRevocation = &ocspResult
			}
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

// getKeyInfo extracts the public key type and size from a certificate.
func getKeyInfo(cert *x509.Certificate) (keyType string, keySize int) {
	if cert == nil || cert.PublicKey == nil {
		return "Unknown", 0
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}
