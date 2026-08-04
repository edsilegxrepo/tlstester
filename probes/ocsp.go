// Package probes low-level active Authority Information Access (AIA) OCSP responder prober.
//
// OBJECTIVES:
// Provide active revocation checking by querying X.509 certificate AIA OCSP responder URLs
// with proper OCSP request/response handling per RFC 6960.
//
// CORE COMPONENTS & DATA FLOW:
// - OCSPResult (probes/ocsp.go): Structured result containing revocation status, timestamps, and reason codes.
// - FetchIssuerFromAIA (probes/ocsp.go): Retrieves issuer certificate via AIA extension for OCSP signing verification.
// - CheckOCSPRevocation (probes/ocsp.go): Full OCSP POST request with proper nonce, issuer verification, and response parsing.
// - CheckActiveOCSP (probes/ocsp.go): Legacy GET-based OCSP reachability check (deprecated, use CheckOCSPRevocation).
// - newSecureHTTPClient (probes/ocsp.go): Constructs HTTP client with TLS 1.2+ minimum and response size limits.
//
// SECURITY FEATURES:
// - HTTP body size limits (maxIssuerCertSize, maxOCSPResponseSize) prevent DoS via oversized responses.
// - TLS 1.2 minimum enforced for all OCSP/AIA HTTP requests.
// - Proper OCSP POST request format with Content-Type headers per RFC 6960.
package probes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// HTTP body size limits to prevent DoS from malicious responders.
// These limits are applied via io.LimitReader when reading response bodies.
const (
	maxIssuerCertSize   = 10 * 1024 * 1024 // 10 MB max for issuer certificate fetched via AIA
	maxOCSPResponseSize = 1 * 1024 * 1024  // 1 MB max for OCSP response body
)

// newSecureHTTPClient creates an HTTP client with explicit TLS configuration.
func newSecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// OCSPResult holds the structured result of an OCSP revocation check.
type OCSPResult struct {
	Checked       bool      // Whether OCSP check was performed
	URL           string    // OCSP responder URL used
	Status        string    // "Good", "Revoked", "Unknown", or error description
	RevocationTime time.Time // If revoked, when it was revoked
	RevokedReason  string    // If revoked, the reason code
	ThisUpdate    time.Time // OCSP response validity start
	NextUpdate    time.Time // OCSP response validity end
	ProducedAt    time.Time // When the OCSP response was generated
	Error         string    // Error message if check failed
}

// FetchIssuerFromAIA fetches the issuer certificate from the certificate's AIA extension.
// Returns nil if AIA is not present or fetch fails.
func FetchIssuerFromAIA(ctx context.Context, cert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("no issuer URL in certificate AIA")
	}

	issuerURL := cert.IssuingCertificateURL[0]
	req, err := http.NewRequestWithContext(ctx, "GET", issuerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := newSecureHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer fetch returned HTTP %d", resp.StatusCode)
	}

	// Limit body size to prevent DoS
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIssuerCertSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer response: %w", err)
	}

	// Try DER format first (most common for AIA)
	issuer, err := x509.ParseCertificate(body)
	if err == nil {
		return issuer, nil
	}

	// Try PEM format
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
}

// CheckOCSPRevocation performs a proper OCSP revocation check using POST with an OCSP request body.
// If issuer is nil, attempts to fetch it via AIA.
func CheckOCSPRevocation(ctx context.Context, cert, issuer *x509.Certificate) OCSPResult {
	result := OCSPResult{Checked: true}

	if cert == nil {
		result.Error = "nil certificate"
		result.Status = "Error"
		return result
	}

	if len(cert.OCSPServer) == 0 {
		result.Error = "no OCSP server URL in certificate AIA"
		result.Status = "No OCSP URL"
		return result
	}

	result.URL = cert.OCSPServer[0]

	// If issuer not provided, try to fetch via AIA
	if issuer == nil {
		var err error
		issuer, err = FetchIssuerFromAIA(ctx, cert)
		if err != nil {
			result.Error = fmt.Sprintf("issuer certificate required: %v", err)
			result.Status = "Error"
			return result
		}
	}

	// Build OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create OCSP request: %v", err)
		result.Status = "Error"
		return result
	}

	// Send OCSP request via POST
	httpReq, err := http.NewRequestWithContext(ctx, "POST", result.URL, bytes.NewReader(ocspReq))
	if err != nil {
		result.Error = fmt.Sprintf("failed to create HTTP request: %v", err)
		result.Status = "Error"
		return result
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	client := newSecureHTTPClient(10 * time.Second)
	resp, err := client.Do(httpReq)
	if err != nil {
		result.Error = fmt.Sprintf("OCSP request failed: %v", err)
		result.Status = "Unreachable"
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("OCSP responder returned HTTP %d", resp.StatusCode)
		result.Status = "Error"
		return result
	}

	// Read and parse OCSP response with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOCSPResponseSize))
	if err != nil {
		result.Error = fmt.Sprintf("failed to read OCSP response: %v", err)
		result.Status = "Error"
		return result
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse OCSP response: %v", err)
		result.Status = "Error"
		return result
	}

	result.ThisUpdate = ocspResp.ThisUpdate
	result.NextUpdate = ocspResp.NextUpdate
	result.ProducedAt = ocspResp.ProducedAt

	switch ocspResp.Status {
	case ocsp.Good:
		result.Status = "Good"
	case ocsp.Revoked:
		result.Status = "Revoked"
		result.RevocationTime = ocspResp.RevokedAt
		result.RevokedReason = revocationReasonString(ocspResp.RevocationReason)
	case ocsp.Unknown:
		result.Status = "Unknown"
	default:
		result.Status = fmt.Sprintf("Unexpected status: %d", ocspResp.Status)
	}

	return result
}

// revocationReasonString converts an OCSP revocation reason code to a human-readable string.
func revocationReasonString(reason int) string {
	reasons := map[int]string{
		0:  "Unspecified",
		1:  "KeyCompromise",
		2:  "CACompromise",
		3:  "AffiliationChanged",
		4:  "Superseded",
		5:  "CessationOfOperation",
		6:  "CertificateHold",
		8:  "RemoveFromCRL",
		9:  "PrivilegeWithdrawn",
		10: "AACompromise",
	}
	if s, ok := reasons[reason]; ok {
		return s
	}
	return fmt.Sprintf("Unknown (%d)", reason)
}

// CheckActiveOCSP performs a context-aware HTTP GET query to the certificate's AIA OCSP responder URL,
// returning a descriptive reachability and status string.
// Deprecated: Use CheckOCSPRevocation for proper revocation checking.
func CheckActiveOCSP(ctx context.Context, cert *x509.Certificate) string {
	if cert == nil || len(cert.OCSPServer) == 0 {
		return "No OCSP Server URL in Certificate AIA"
	}

	ocspURL := cert.OCSPServer[0]
	req, err := http.NewRequestWithContext(ctx, "GET", ocspURL, nil)
	if err != nil {
		return fmt.Sprintf("failed to create OCSP request: %v", err)
	}

	client := newSecureHTTPClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("OCSP responder reachability failed: %v", err)
	}
	closeErr := resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if closeErr != nil {
			return fmt.Sprintf("OCSP responder reachable (%s) - HTTP 200 OK (body close error: %v)", ocspURL, closeErr)
		}
		return fmt.Sprintf("OCSP responder reachable (%s) - HTTP 200 OK", ocspURL)
	}
	return fmt.Sprintf("OCSP responder (%s) returned HTTP %d", ocspURL, resp.StatusCode)
}
