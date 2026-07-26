// Package probes low-level HTTP/ALPN application prober.
//
// OBJECTIVES:
// Provide application-layer HTTP GET probing over TLS, supporting HTTP/1.1 and HTTP/2 transports,
// custom request header injection, Alt-Svc header extraction, and HTTP status code assertions.
//
// CORE COMPONENTS & DATA FLOW:
// - HTTPResult (probes/http.go): Struct capturing HTTP response status line, Alt-Svc header, TTFB latency, and errors.
// - HTTP (probes/http.go): Executes context-aware HTTP GET requests over TLS against host:port/path.
package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPResult holds the outcome of an HTTP probe request.
type HTTPResult struct {
	StatusLine string
	AltSvc     string
	Latency    time.Duration
	Error      string
}

// HTTP executes an HTTP GET request over TLS against host:port/path using HTTP/1.1 or HTTP/2 transport.
// Injects custom request headers, extracts Alt-Svc headers, and evaluates expected HTTP status code assertions.
// Automatically cleans up idle transport connections to prevent resource leaks across high-volume scans.
func HTTP(ctx context.Context, tlsConfig *tls.Config, host string, port int, path string, headers []string, assertStatus string, timeout time.Duration) HTTPResult {
	result := HTTPResult{}

	host = strings.TrimSpace(host)
	if path == "" {
		path = "/"
	}

	targetURL := fmt.Sprintf("https://%s:%d%s", host, port, path)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create HTTP probe request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", "TLSTester/1.0")

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13}
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("HTTP probe failed: %v", err)
		return result
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && result.Error == "" {
			result.Error = fmt.Sprintf("failed to close response body: %v", closeErr)
		}
	}()

	result.StatusLine = fmt.Sprintf("%d %s", resp.StatusCode, resp.Status)
	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != "" {
		result.AltSvc = altSvc
	}

	if assertStatus != "" {
		expectedCodes := strings.Split(assertStatus, ",")
		matched := false
		currentStatus := strconv.Itoa(resp.StatusCode)
		for _, exp := range expectedCodes {
			if strings.TrimSpace(exp) == currentStatus {
				matched = true
				break
			}
		}
		if !matched {
			result.Error = fmt.Sprintf("HTTP Status Code assertion failed: got %d, expected [%s]", resp.StatusCode, assertStatus)
		}
	}

	return result
}
