// Package probes low-level context-aware network socket prober.
//
// OBJECTIVES:
// Provide granular network socket layer probing including DNS resolution, raw TCP dialing,
// HTTP CONNECT proxy tunneling, and SOCKS5 proxy handshakes.
//
// CORE COMPONENTS & DATA FLOW:
// - TCP (probes/tcp.go): Dials TCP sockets with retry logic and records DNS & TCP latencies.
// - DialViaProxy (probes/tcp.go): Routes socket connections through HTTP CONNECT or SOCKS5 proxies.
// - socks5Handshake (probes/tcp.go): Implements RFC 1928 SOCKS5 greeting & CONNECT request handshakes.
package probes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Network timing constants for retry behavior
const (
	// retryDelay is the context-aware sleep duration between TCP connection retry attempts.
	// Uses time.After with select to allow cancellation during the delay period.
	retryDelay = 500 * time.Millisecond
)

// closeConnWithError attempts to close a net.Conn and appends any close error to origErr.
func closeConnWithError(conn net.Conn, origErr error) error {
	if conn == nil {
		return origErr
	}
	if closeErr := conn.Close(); closeErr != nil {
		return fmt.Errorf("%w (socket close error: %v)", origErr, closeErr)
	}
	return origErr
}

// TCP connects a raw TCP socket to host:port, measuring DNS resolution and TCP connect latencies.
// Supports HTTP CONNECT and SOCKS5 proxy tunneling with retry attempts and context deadlines.
func TCP(ctx context.Context, host string, port int, timeout time.Duration, retries int, proxyAddr, proxyType string) (net.Conn, []string, time.Duration, time.Duration, error) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	dnsStart := time.Now()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(ctx, host)
	dnsLatency := time.Since(dnsStart)

	if err != nil && proxyAddr == "" {
		return nil, nil, dnsLatency, 0, fmt.Errorf("DNS resolution failed for '%s': %w", host, err)
	}

	var conn net.Conn
	var tcpLatency time.Duration

	for i := 0; i <= retries; i++ {
		select {
		case <-ctx.Done():
			return nil, ips, dnsLatency, tcpLatency, ctx.Err()
		default:
		}

		tcpStart := time.Now()
		if proxyAddr != "" {
			conn, err = DialViaProxy(ctx, proxyAddr, proxyType, targetAddr, timeout)
		} else {
			dialer := &net.Dialer{Timeout: timeout}
			conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
		}
		tcpLatency = time.Since(tcpStart)

		if err == nil {
			break
		}
		if i < retries {
			// Context-aware sleep to allow cancellation during retry delay
			select {
			case <-ctx.Done():
				return nil, ips, dnsLatency, tcpLatency, ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}

	if err != nil {
		return nil, ips, dnsLatency, tcpLatency, fmt.Errorf("TCP connection to %s failed after retries: %w", targetAddr, err)
	}

	return conn, ips, dnsLatency, tcpLatency, nil
}

// DialViaProxy establishes a context-aware connection through an HTTP CONNECT or SOCKS5 proxy server.
func DialViaProxy(ctx context.Context, proxyAddr, proxyType, targetAddr string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	proxyConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy connection to '%s' failed: %w", proxyAddr, err)
	}

	if strings.EqualFold(proxyType, "socks") || strings.EqualFold(proxyType, "socks5") {
		return socks5Handshake(proxyConn, targetAddr)
	}

	req, err := http.NewRequestWithContext(ctx, "CONNECT", "//"+targetAddr, nil)
	if err != nil {
		return nil, closeConnWithError(proxyConn, fmt.Errorf("failed to create CONNECT request: %w", err))
	}
	req.URL.Host = targetAddr
	req.Header.Set("User-Agent", "TLSTester/1.0")

	if err := req.Write(proxyConn); err != nil {
		return nil, closeConnWithError(proxyConn, fmt.Errorf("failed to write CONNECT request to proxy: %w", err))
	}

	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		return nil, closeConnWithError(proxyConn, fmt.Errorf("failed to read CONNECT response from proxy: %w", err))
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		return nil, closeConnWithError(proxyConn, fmt.Errorf("failed to close CONNECT response body: %w", closeErr))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, closeConnWithError(proxyConn, fmt.Errorf("proxy CONNECT rejected with status: %s", resp.Status))
	}

	return proxyConn, nil
}

// socks5Handshake performs SOCKS5 greeting (NO AUTH) and CONNECT request handshakes over an open TCP connection.
func socks5Handshake(conn net.Conn, targetAddr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, closeConnWithError(conn, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, closeConnWithError(conn, fmt.Errorf("invalid port number: %s", portStr))
	}

	if len(host) > 255 {
		return nil, closeConnWithError(conn, fmt.Errorf("host length exceeds SOCKS5 255 byte limit: %s", host))
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, closeConnWithError(conn, fmt.Errorf("SOCKS5 greeting write failed: %w", err))
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 || buf[1] != 0x00 {
		return nil, closeConnWithError(conn, fmt.Errorf("SOCKS5 greeting response rejected"))
	}

	/* #nosec G115 -- Mathematically safe cast: len(host) is bounds-checked (len(host) <= 255) prior to SOCKS5 1-byte domain length encoding */
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	/* #nosec G115 -- Mathematically safe cast: port is bounds-checked (0 <= port <= 65535) prior to SOCKS5 2-byte port encoding */
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return nil, closeConnWithError(conn, fmt.Errorf("SOCKS5 connect request write failed: %w", err))
	}

	respBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, respBuf); err != nil || respBuf[1] != 0x00 {
		return nil, closeConnWithError(conn, fmt.Errorf("SOCKS5 connection rejected by proxy (code %d)", respBuf[1]))
	}

	var addrLen int
	switch respBuf[3] {
	case 0x01:
		addrLen = 4 + 2
	case 0x04:
		addrLen = 16 + 2
	case 0x03:
		dLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, dLen); err != nil {
			return nil, closeConnWithError(conn, err)
		}
		addrLen = int(dLen[0]) + 2
	}
	if addrLen > 0 {
		skip := make([]byte, addrLen)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return nil, closeConnWithError(conn, fmt.Errorf("failed to read SOCKS5 bind address: %w", err))
		}
	}

	return conn, nil
}
