// Package probes unit tests for network and cryptographic probers.
//
// TEST STRATEGY EXPLANATION:
// Employs sub-second in-memory mock servers (httptest.NewTLSServer, httptest.NewServer, net.Listen, net.ListenUDP)
// to verify probe execution without network latency:
// 1. TestMockTCPProbing & TestMockTCPContextCancelled: Local TCP socket dialing and context deadline cancellation.
// 2. TestMockTLSAndHTTPProbing & TestTLSFallbackPeerCertificates: Handshake verification, Alt-Svc header extraction, cipher scanning, session ticket resumption, and fallback cert capture on trust validation failure.
// 3. TestMockHTTPProxyTunneling & TestMockHTTPProxyRejection: In-memory HTTP CONNECT proxy 200 OK and 403 Forbidden scenarios.
// 4. TestMockSOCKS5ProxyTunneling & TestMockSOCKS5ProxyErrors: In-memory SOCKS5 greeting, authentication rejection, and domain target connection.
// 5. TestMockActiveOCSPResponder: Local HTTP mock server AIA OCSP responder 200 OK and 500 error queries.
// 6. TestMockQUICReachability & TestExportCertificatesWrite: Local UDP datagram socket reachability and PEM certificate file export.
package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestMockTCPProbing tests probes.TCP against a local listener in milliseconds.
func TestMockTCPProbing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("ln.Close warning: %v", closeErr)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("conn.Close warning: %v", closeErr)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, ips, _, _, err := TCP(ctx, "localhost", port, 1*time.Second, 0, "", "")
	if err != nil {
		t.Fatalf("TCP probe failed: %v", err)
	}
	_ = conn.Close()

	if len(ips) == 0 {
		t.Error("expected non-empty IP slice")
	}
}

// TestMockTCPContextCancelled tests TCP dialing with an already cancelled context.
func TestMockTCPContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, _, _, err := TCP(ctx, "google.com", 443, 1*time.Second, 0, "", "")
	if err == nil {
		t.Error("expected error for cancelled context in TCP probe")
	}
}

// TestMockTLSAndHTTPProbing tests probes.TLS and probes.HTTP using httptest.NewTLSServer.
func TestMockTLSAndHTTPProbing(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Raw TCP
	rawConn, _, _, _, err := TCP(ctx, host, port, 1*time.Second, 0, "", "")
	if err != nil {
		t.Fatalf("TCP failed: %v", err)
	}

	// 2. TLS Handshake
	tlsConfig := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = host

	tlsConn, tlsRes, err := TLS(ctx, tlsConfig, host, port, rawConn, 1*time.Second, 0, "", "")
	if err != nil {
		t.Fatalf("TLS failed: %v", err)
	}
	_ = tlsConn.Close()

	if !tlsRes.HandshakeSuccess {
		t.Error("expected TLS HandshakeSuccess")
	}
	if len(tlsRes.PeerCertificates) == 0 {
		t.Error("expected peer certificates")
	}

	// 3. HTTP Probe with status assertions
	httpRes := HTTP(ctx, tlsConfig, host, port, "/", []string{"X-Custom: 1"}, "200", 1*time.Second)
	if httpRes.Error != "" {
		t.Errorf("unexpected HTTP probe error: %s", httpRes.Error)
	}
	if httpRes.StatusLine == "" {
		t.Error("expected non-empty status line")
	}
	if httpRes.AltSvc == "" {
		t.Error("expected Alt-Svc header extraction")
	}

	// 4. Scan Cipher Suites against mock
	scanRes, ciphers := ScanCipherSuites(ctx, host, port, 1*time.Second, 0, "", "")
	if len(scanRes) == 0 {
		t.Error("expected non-empty scan results")
	}
	_ = ciphers

	// 5. Test Session Resumption against mock
	_, _ = TestSessionResumption(ctx, host, port, 1*time.Second, 0, "", "", true)
}

// TestTLSFallbackPeerCertificates tests TLS handshake validation failure capturing certificates in fallback probe.
func TestTLSFallbackPeerCertificates(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rawConn, _, _, _, err := TCP(ctx, host, port, 1*time.Second, 0, "", "")
	if err != nil {
		t.Fatalf("TCP failed: %v", err)
	}

	// Deliberately strict TLS config without Root CAs to trigger trust validation failure
	strictConfig := &tls.Config{InsecureSkipVerify: false, ServerName: host}
	_, tlsRes, err := TLS(ctx, strictConfig, host, port, rawConn, 1*time.Second, 0, "", "")

	if err == nil {
		t.Error("expected TLS trust validation error for untrusted self-signed cert")
	}
	if len(tlsRes.PeerCertificates) == 0 {
		t.Error("expected fallback TLS probe to capture peer certificates on trust failure")
	}
}

// TestMockHTTPProxyTunneling tests HTTP CONNECT proxy tunneling in memory.
func TestMockHTTPProxyTunneling(t *testing.T) {
	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() {
		if closeErr := targetLn.Close(); closeErr != nil {
			t.Logf("targetLn.Close warning: %v", closeErr)
		}
	}()

	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("conn.Close warning: %v", closeErr)
			}
		}
	}()

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	targetHost, targetPortStr, _ := net.SplitHostPort(targetLn.Addr().String())
	targetPort, _ := strconv.Atoi(targetPortStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, _, _, _, err := TCP(ctx, targetHost, targetPort, 1*time.Second, 0, proxyURL.Host, "http")
	if err != nil {
		t.Fatalf("HTTP CONNECT proxy tunneling failed: %v", err)
	}
	_ = conn.Close()
}

// TestMockHTTPProxyRejection tests HTTP CONNECT proxy 403 response.
func TestMockHTTPProxyRejection(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := DialViaProxy(ctx, proxyURL.Host, "http", "example.com:443", 500*time.Millisecond)
	if err == nil {
		t.Error("expected error for proxy rejection")
	}
}

// TestMockSOCKS5ProxyTunneling tests SOCKS5 proxy handshake in memory.
func TestMockSOCKS5ProxyTunneling(t *testing.T) {
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start SOCKS listener: %v", err)
	}
	defer func() {
		if closeErr := socksLn.Close(); closeErr != nil {
			t.Logf("socksLn.Close warning: %v", closeErr)
		}
	}()

	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("conn.Close warning: %v", closeErr)
			}
		}()

		// Read SOCKS5 greeting
		buf := make([]byte, 3)
		_, _ = conn.Read(buf)
		// Send SOCKS5 greeting response (NO AUTH)
		_, _ = conn.Write([]byte{0x05, 0x00})

		// Read SOCKS5 connect request
		reqBuf := make([]byte, 128)
		n, _ := conn.Read(reqBuf)
		if n > 0 {
			// Reply success (0x00) with Domain Name type (0x03)
			_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, 80})
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialViaProxy(ctx, socksLn.Addr().String(), "socks5", "example.com:443", 1*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 handshake failed: %v", err)
	}
	_ = conn.Close()
}

// TestMockSOCKS5ProxyErrors tests SOCKS5 error handling branches.
func TestMockSOCKS5ProxyErrors(t *testing.T) {
	socksLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() {
		if closeErr := socksLn.Close(); closeErr != nil {
			t.Logf("socksLn.Close warning: %v", closeErr)
		}
	}()

	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("conn.Close warning: %v", closeErr)
			}
		}()
		// Send rejected greeting response (0xFF)
		_, _ = conn.Write([]byte{0x05, 0xFF})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := DialViaProxy(ctx, socksLn.Addr().String(), "socks5", "example.com:443", 500*time.Millisecond)
	if err == nil {
		t.Error("expected error for rejected SOCKS5 greeting")
	}

	// Invalid target address format for SOCKS5
	_, err = DialViaProxy(ctx, socksLn.Addr().String(), "socks5", "invalid_target_no_port", 500*time.Millisecond)
	if err == nil {
		t.Error("expected error for invalid target address format")
	}
}

// TestMockActiveOCSPResponder tests probes.CheckActiveOCSP with local HTTP mock server.
func TestMockActiveOCSPResponder(t *testing.T) {
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ocspServer.Close()

	cert := &x509.Certificate{
		OCSPServer: []string{ocspServer.URL},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status := CheckActiveOCSP(ctx, cert)
	if status == "" {
		t.Error("expected non-empty OCSP status")
	}

	// Non-200 Status
	ocspErrServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ocspErrServer.Close()

	certErr := &x509.Certificate{OCSPServer: []string{ocspErrServer.URL}}
	statusErr := CheckActiveOCSP(ctx, certErr)
	if statusErr == "" {
		t.Error("expected status error string")
	}
}

// TestMockQUICReachability tests probes.CheckQUIC with local UDP listener.
func TestMockQUICReachability(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("conn.Close warning: %v", closeErr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	reachable := CheckQUIC(ctx, host, port, 500*time.Millisecond)
	if !reachable {
		t.Error("expected UDP/QUIC reachability to be true")
	}
}

// TestExportCertificatesWrite tests probes.ExportCertificates with a dummy certificate.
func TestExportCertificatesWrite(t *testing.T) {
	tmpDir := t.TempDir()
	prefix := filepath.Join(tmpDir, "export")

	cert := &x509.Certificate{
		Raw: []byte("DUMMY CERTIFICATE DATA"),
	}

	err := ExportCertificates(prefix, "example.com", 443, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("ExportCertificates failed: %v", err)
	}

	expectedFile := filepath.Join(tmpDir, "export_example.com_443_0.crt")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("expected certificate file '%s' was not created", expectedFile)
	}
}
