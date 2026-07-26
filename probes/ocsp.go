// Package probes low-level active Authority Information Access (AIA) OCSP responder prober.
//
// OBJECTIVES:
// Provide active revocation reachability testing by querying X.509 certificate AIA OCSP responder URLs.
//
// CORE COMPONENTS & DATA FLOW:
// - CheckActiveOCSP (probes/ocsp.go): Extracts AIA OCSP server URLs from an X.509 certificate and issues an HTTP GET query.
package probes

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// CheckActiveOCSP performs a context-aware HTTP GET query to the certificate's AIA OCSP responder URL,
// returning a descriptive reachability and status string.
func CheckActiveOCSP(ctx context.Context, cert *x509.Certificate) string {
	if cert == nil || len(cert.OCSPServer) == 0 {
		return "No OCSP Server URL in Certificate AIA"
	}

	ocspURL := cert.OCSPServer[0]
	req, err := http.NewRequestWithContext(ctx, "GET", ocspURL, nil)
	if err != nil {
		return fmt.Sprintf("Failed to create OCSP request: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("OCSP responder reachability failed: %v", err)
	}
	closeErr := resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if closeErr != nil {
			return fmt.Sprintf("OCSP Responder Reachable (%s) - HTTP 200 OK (body close error: %v)", ocspURL, closeErr)
		}
		return fmt.Sprintf("OCSP Responder Reachable (%s) - HTTP 200 OK", ocspURL)
	}
	return fmt.Sprintf("OCSP Responder (%s) returned HTTP %d", ocspURL, resp.StatusCode)
}
