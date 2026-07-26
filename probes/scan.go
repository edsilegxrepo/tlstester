// Package probes low-level protocol capabilities scanner, session ticket resumption tester, and UDP/QUIC prober.
//
// OBJECTIVES:
// Provide capability sweeps across supported TLS protocol versions (TLS 1.0 - 1.3), cipher suite discovery,
// TLS session ticket resumption latency benchmarking, and UDP/QUIC datagram socket reachability tests.
//
// CORE COMPONENTS & DATA FLOW:
// - ProtocolScanResult (probes/scan.go): Struct capturing TLS version scan status and handshake latency.
// - ScanCipherSuites (probes/scan.go): Sweeps TLS 1.0, 1.1, 1.2, and 1.3 handshakes against a target server.
// - TestSessionResumption (probes/scan.go): Tests session caching and ticket resumption across sequential connections.
// - CheckQUIC (probes/scan.go): Probes UDP datagram packet reachability.
package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ProtocolScanResult records the outcome of testing a specific TLS version.
type ProtocolScanResult struct {
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
}

// ScanCipherSuites sweeps available TLS versions (1.0 - 1.3) and ciphers against host:port,
// recording protocol support status and negotiated cipher names.
func ScanCipherSuites(ctx context.Context, host string, port int, timeout time.Duration, retries int, proxyAddr, proxyType string) ([]ProtocolScanResult, []string) {
	var scanResults []ProtocolScanResult
	var supportedCiphers []string

	versions := []struct {
		name string
		ver  uint16
	}{
		{"TLS1.0", tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	}

	for _, v := range versions {
		select {
		case <-ctx.Done():
			return scanResults, supportedCiphers
		default:
		}

		conn, _, _, _, err := TCP(ctx, host, port, timeout, retries, proxyAddr, proxyType)
		if err != nil {
			scanResults = append(scanResults, ProtocolScanResult{
				Protocol: v.name,
				Status:   "FAILED (TCP)",
			})
			continue
		}

		/* #nosec G402 -- Intentional protocol scan behavior: ScanCipherSuites sweeps TLS 1.0-1.3 capability without throwing trust validation errors during discovery */
		tlsConfig := &tls.Config{ // nosemgrep
			InsecureSkipVerify: true, // nosemgrep
			MinVersion:         v.ver,
			MaxVersion:         v.ver,
			ServerName:         host,
		}

		tlsConn := tls.Client(conn, tlsConfig)
		start := time.Now()
		hErr := tlsConn.HandshakeContext(ctx)
		latency := time.Since(start).Milliseconds()

		if hErr == nil {
			state := tlsConn.ConnectionState()
			scanResults = append(scanResults, ProtocolScanResult{
				Protocol:  v.name,
				Status:    "SUPPORTED",
				LatencyMs: latency,
			})
			cipherName := tls.CipherSuiteName(state.CipherSuite)
			supportedCiphers = append(supportedCiphers, fmt.Sprintf("%s (%s)", cipherName, v.name))
			if closeErr := tlsConn.Close(); closeErr != nil {
				// Record socket close error if handshake succeeded
				scanResults[len(scanResults)-1].Status += fmt.Sprintf(" (Close error: %v)", closeErr)
			}
		} else {
			scanResults = append(scanResults, ProtocolScanResult{
				Protocol:  v.name,
				Status:    "DISABLED / REJECTED",
				LatencyMs: latency,
			})
			_ = conn.Close()
		}
	}

	return scanResults, supportedCiphers
}

// TestSessionResumption evaluates TLS session ticket/ID caching latency and success across sequential handshakes.
func TestSessionResumption(ctx context.Context, host string, port int, timeout time.Duration, retries int, proxyAddr, proxyType string, insecure bool) (bool, time.Duration) {
	cache := tls.NewLRUClientSessionCache(10)

	dialAndHandshake := func() (*tls.Conn, time.Duration, error) {
		rawConn, _, _, _, dialErr := TCP(ctx, host, port, timeout, retries, proxyAddr, proxyType)
		if dialErr != nil {
			return nil, 0, dialErr
		}
		/* #nosec G402 -- User-controlled parameter: InsecureSkipVerify is bound directly to the user-supplied -insecure CLI flag for testing non-prod endpoints */
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         host,
			ClientSessionCache: cache,
			MinVersion:         tls.VersionTLS12,
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		start := time.Now()
		err := tlsConn.HandshakeContext(ctx)
		return tlsConn, time.Since(start), err
	}

	conn1, _, err1 := dialAndHandshake()
	if err1 != nil {
		return false, 0
	}
	if closeErr := conn1.Close(); closeErr != nil {
		return false, 0
	}

	conn2, latency2, err2 := dialAndHandshake()
	if err2 != nil {
		return false, 0
	}
	resumed := conn2.ConnectionState().DidResume
	_ = conn2.Close()

	return resumed, latency2
}

// CheckQUIC probes UDP datagram reachability to host:port using a test datagram packet.
func CheckQUIC(ctx context.Context, host string, port int, timeout time.Duration) bool {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		return false
	}

	writeOk := false
	if _, wErr := conn.Write([]byte{0x00, 0x01, 0x02, 0x03}); wErr == nil {
		writeOk = true
	}

	cErr := conn.Close()
	return writeOk && cErr == nil
}
