// Package probes low-level TLS handshake engine, Certificate Transparency parser, and X.509 certificate exporter.
//
// OBJECTIVES:
// Provide granular TLS handshake execution over raw sockets, capturing negotiated protocol versions,
// cipher suite names, ALPN protocols, key exchange curves, OCSP stapled responses, Certificate Transparency
// SCTs (Signed Certificate Timestamps), and peer certificates (including insecure fallback certificate
// extraction on validation failure).
//
// CORE COMPONENTS & DATA FLOW:
// - TLSOptions (probes/tls.go): Bundles TLS probe parameters (config, host, port, raw conn, timeout, retries, proxy).
// - TLSResult (probes/tls.go): Struct capturing raw TLS handshake metadata, cert chain, and SCT information.
// - SCTInfo (probes/tls.go): Parsed Certificate Transparency SCT with version, log ID, timestamp, and source.
// - TLS (probes/tls.go): Wraps raw net.Conn with tls.Client and executes context-aware handshakes.
// - parseSCT/parseEmbeddedSCTs/parseSCTList (probes/tls.go): Parse SCTs from TLS extension or embedded in certificates.
// - ExportCertificates (probes/tls.go): Encodes X.509 certificate chains into PEM files on disk with path sanitization.
//
// SECURITY FEATURES:
// - Path traversal prevention in ExportCertificates via filepath.Abs and hostname sanitization.
// - Fallback probe captures certificates even when chain validation fails (for diagnostics).
package probes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SCTInfo holds parsed Signed Certificate Timestamp information.
type SCTInfo struct {
	Version   int       // SCT version (0 = v1)
	LogID     string    // CT log ID (hex-encoded first 8 bytes)
	Timestamp time.Time // When the SCT was issued
	Source    string    // "tls_extension", "embedded", or "ocsp"
}

// TLSResult holds raw TLS handshake diagnostic output from probes.TLS.
type TLSResult struct {
	HandshakeSuccess bool
	HandshakeLatency time.Duration
	Protocol         string
	Cipher           string
	Alpn             string
	NegotiatedGroup  string
	OCSPStapled      bool
	SCTsPresent      bool      // Certificate Transparency SCTs present (via TLS extension or cert)
	SCTCount         int       // Number of SCTs found
	SCTs             []SCTInfo // Parsed SCT details
	PeerCertificates []*x509.Certificate
	CertTrusted      bool
	TrustError       string
}

// TLSOptions bundles parameters for the TLS probe function.
type TLSOptions struct {
	Config    *tls.Config
	Host      string
	Port      int
	RawConn   net.Conn
	Timeout   time.Duration
	Retries   int
	ProxyAddr string
	ProxyType string
}

// TLS wraps an established TCP connection with TLS and executes a context-aware handshake.
// Executes an insecure fallback probe to capture peer certificates when trust validation fails.
func TLS(ctx context.Context, opts TLSOptions) (*tls.Conn, TLSResult, error) {
	result := TLSResult{}

	tlsConfig := opts.Config
	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: opts.Host, MinVersion: tls.VersionTLS12}
	}

	tlsConn := tls.Client(opts.RawConn, tlsConfig)
	tlsStart := time.Now()

	errChan := make(chan error, 1)
	go func() {
		errChan <- tlsConn.HandshakeContext(ctx)
	}()

	var err error
	select {
	case <-ctx.Done():
		if closeErr := tlsConn.Close(); closeErr != nil {
			return nil, result, fmt.Errorf("context cancelled and socket close failed: %v: %w", closeErr, ctx.Err())
		}
		return nil, result, ctx.Err()
	case err = <-errChan:
	}

	result.HandshakeLatency = time.Since(tlsStart)

	if err != nil {
		result.CertTrusted = false
		result.TrustError = err.Error()

		// Fallback probe to capture certificates when chain validation fails
		fallbackConn, _, _, _, dialErr := TCP(ctx, opts.Host, opts.Port, opts.Timeout, opts.Retries, opts.ProxyAddr, opts.ProxyType)
		if dialErr == nil {
			/* #nosec G402 -- Intentional fallback certificate extraction probe on trust failure */
			insecureConfig := tlsConfig.Clone()
			insecureConfig.InsecureSkipVerify = true
			insecureTLSConn := tls.Client(fallbackConn, insecureConfig)
			if insecureErr := insecureTLSConn.HandshakeContext(ctx); insecureErr == nil {
				state := insecureTLSConn.ConnectionState()
				result.PeerCertificates = state.PeerCertificates
				if closeErr := insecureTLSConn.Close(); closeErr != nil {
					result.TrustError += fmt.Sprintf(" (fallback tls close error: %v)", closeErr)
				}
			} else {
				if closeErr := fallbackConn.Close(); closeErr != nil {
					result.TrustError += fmt.Sprintf(" (fallback tcp close error: %v)", closeErr)
				}
			}
		}
		return nil, result, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	result.HandshakeSuccess = true
	result.CertTrusted = true
	result.Protocol = tls.VersionName(state.Version)
	result.Cipher = tls.CipherSuiteName(state.CipherSuite)
	result.Alpn = state.NegotiatedProtocol
	result.PeerCertificates = state.PeerCertificates
	result.OCSPStapled = len(state.OCSPResponse) > 0

	// Check for Certificate Transparency SCTs
	// SCTs can be delivered via TLS extension or embedded in certificate
	var scts []SCTInfo

	// Parse SCTs from TLS extension
	for _, sctData := range state.SignedCertificateTimestamps {
		if sct := parseSCT(sctData, "tls_extension"); sct != nil {
			scts = append(scts, *sct)
		}
	}

	// If no TLS extension SCTs, check embedded in certificate
	if len(scts) == 0 && len(state.PeerCertificates) > 0 {
		scts = parseEmbeddedSCTs(state.PeerCertificates[0])
	}

	result.SCTs = scts
	result.SCTCount = len(scts)
	result.SCTsPresent = len(scts) > 0

	if state.CurveID != 0 {
		result.NegotiatedGroup = state.CurveID.String()
	} else {
		result.NegotiatedGroup = "RSA (No ECDHE)"
	}

	return tlsConn, result, nil
}

// parseSCT parses a single SCT and returns structured info.
// SCT format: version (1) + log_id (32) + timestamp (8) + extensions_len (2) + extensions + sig
func parseSCT(data []byte, source string) *SCTInfo {
	if len(data) < 43 { // minimum: 1 + 32 + 8 + 2 = 43 bytes
		return nil
	}

	version := int(data[0])
	logID := fmt.Sprintf("%X", data[1:9]) // First 8 bytes of 32-byte log ID

	// Timestamp is milliseconds since epoch (big-endian uint64 at offset 33)
	tsMs := uint64(0)
	for i := 0; i < 8; i++ {
		tsMs = (tsMs << 8) | uint64(data[33+i])
	}
	timestamp := time.UnixMilli(int64(tsMs))

	return &SCTInfo{
		Version:   version,
		LogID:     logID,
		Timestamp: timestamp,
		Source:    source,
	}
}

// parseEmbeddedSCTs parses SCTs embedded in a certificate via the SCT List extension.
func parseEmbeddedSCTs(cert *x509.Certificate) []SCTInfo {
	if cert == nil {
		return nil
	}

	// SCT List OID: 1.3.6.1.4.1.11129.2.4.2
	sctOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sctOID) {
			return parseSCTList(ext.Value, "embedded")
		}
	}
	return nil
}

// parseSCTList parses a serialized SCT list (used in both cert extension and OCSP).
// Format: 2-byte total length, then repeated (2-byte len + SCT data)
func parseSCTList(data []byte, source string) []SCTInfo {
	if len(data) < 2 {
		return nil
	}

	// The extension value is wrapped in an OCTET STRING, decode it first
	var sctListBytes []byte
	if _, err := asn1.Unmarshal(data, &sctListBytes); err != nil {
		// If ASN.1 unwrap fails, try raw data
		sctListBytes = data
	}

	if len(sctListBytes) < 2 {
		return nil
	}

	listLen := int(sctListBytes[0])<<8 | int(sctListBytes[1])
	if listLen+2 > len(sctListBytes) {
		return nil
	}

	var scts []SCTInfo
	pos := 2
	for pos < listLen+2 {
		if pos+2 > len(sctListBytes) {
			break
		}
		sctLen := int(sctListBytes[pos])<<8 | int(sctListBytes[pos+1])
		pos += 2
		if pos+sctLen > len(sctListBytes) {
			break
		}
		if sct := parseSCT(sctListBytes[pos:pos+sctLen], source); sct != nil {
			scts = append(scts, *sct)
		}
		pos += sctLen
	}
	return scts
}

// countEmbeddedSCTs counts SCTs embedded in a certificate (legacy, for backward compatibility).
func countEmbeddedSCTs(cert *x509.Certificate) int {
	return len(parseEmbeddedSCTs(cert))
}

// ExportCertificates saves peer certificate chains to disk as individual PEM-encoded files with prefix.
// Prefix can be a directory path (e.g., "/tmp/certs") and is sanitized to prevent path traversal.
func ExportCertificates(prefix string, host string, port int, chain []*x509.Certificate) error {
	// Sanitize prefix to prevent path traversal
	cleanPrefix := filepath.Clean(prefix)
	absPrefix, err := filepath.Abs(cleanPrefix)
	if err != nil {
		return fmt.Errorf("invalid prefix path: %w", err)
	}
	if strings.Contains(absPrefix, "..") {
		return fmt.Errorf("path traversal detected in prefix '%s'", prefix)
	}

	// Sanitize hostname to prevent directory creation via host manipulation
	// Replace both forward and back slashes for cross-platform safety
	safeHost := strings.ReplaceAll(host, "/", "_")
	safeHost = strings.ReplaceAll(safeHost, "\\", "_")
	safeHost = strings.ReplaceAll(safeHost, "..", "_")

	for i, cert := range chain {
		fileName := fmt.Sprintf("%s_%s_%d_%d.crt", absPrefix, safeHost, port, i)
		pemBuf := new(bytes.Buffer)
		if err := pem.Encode(pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("failed to encode certificate %d: %w", i, err)
		}
		if err := os.WriteFile(fileName, pemBuf.Bytes(), 0o600); err != nil {
			return fmt.Errorf("failed to write certificate %d to %s: %w", i, fileName, err)
		}
	}
	return nil
}
