// Package probes low-level TLS handshake engine and X.509 certificate exporter.
//
// OBJECTIVES:
// Provide granular TLS handshake execution over raw sockets, capturing negotiated protocol versions,
// cipher suite names, ALPN protocols, key exchange curves, OCSP stapled responses, and peer certificates
// (including insecure fallback certificate extraction on validation failure).
//
// CORE COMPONENTS & DATA FLOW:
// - TLSResult (probes/tls.go): Struct capturing raw TLS handshake metadata and cert chain.
// - TLS (probes/tls.go): Wraps raw net.Conn with tls.Client and executes context-aware handshakes.
// - ExportCertificates (probes/tls.go): Encodes X.509 certificate chains into PEM files on disk.
package probes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"
)

// TLSResult holds raw TLS handshake diagnostic output from probes.TLS.
type TLSResult struct {
	HandshakeSuccess bool
	HandshakeLatency time.Duration
	Protocol         string
	Cipher           string
	Alpn             string
	NegotiatedGroup  string
	OCSPStapled      bool
	PeerCertificates []*x509.Certificate
	CertTrusted      bool
	TrustError       string
}

// TLS wraps an established TCP connection with TLS and executes a context-aware handshake.
// Executes an insecure fallback probe to capture peer certificates when trust validation fails.
func TLS(ctx context.Context, tlsConfig *tls.Config, host string, port int, rawConn net.Conn, timeout time.Duration, retries int, proxyAddr, proxyType string) (*tls.Conn, TLSResult, error) {
	result := TLSResult{}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
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
		fallbackConn, _, _, _, dialErr := TCP(ctx, host, port, timeout, retries, proxyAddr, proxyType)
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

	if state.Version == tls.VersionTLS13 {
		result.NegotiatedGroup = "TLS1.3 ECDHE/X25519 (Negotiated)"
	} else {
		result.NegotiatedGroup = "ECDHE (Standard)"
	}

	return tlsConn, result, nil
}

// ExportCertificates saves peer certificate chains to disk as individual PEM-encoded files with prefix.
func ExportCertificates(prefix string, host string, port int, chain []*x509.Certificate) error {
	for i, cert := range chain {
		fileName := fmt.Sprintf("%s_%s_%d_%d.crt", prefix, host, port, i)
		pemBuf := new(bytes.Buffer)
		if err := pem.Encode(pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
		if err := os.WriteFile(fileName, pemBuf.Bytes(), 0o600); err != nil {
			return err
		}
	}
	return nil
}
