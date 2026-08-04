// Package certs provides certificate handling, PEM truststore loading, mTLS client keypair loading,
// and certificate expiration calculations.
//
// OBJECTIVES:
// Provide an isolated cryptographic certificate management module for loading root CAs, parsing client
// keypairs for mTLS authentication, and calculating validity remaining windows.
//
// CORE COMPONENTS & DATA FLOW:
// - LoadTruststore (certs.go): Reads PEM truststores and merges custom CAs with system root CA pools.
// - LoadClientKeypair (certs.go): Reads PEM client certificate/private key pairs for mTLS.
// - DaysUntilExpiration (certs.go): Calculates remaining days before an X.509 certificate expires.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sanitizePath validates and sanitizes a file path to prevent path traversal attacks.
// Returns the absolute, cleaned path or an error if the path is invalid.
func sanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}

	// Clean and convert to absolute path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Verify the cleaned path doesn't escape via traversal
	// After Abs(), any remaining ".." would indicate attempted traversal
	if strings.Contains(absPath, "..") {
		return "", fmt.Errorf("path traversal detected in '%s'", path)
	}

	return absPath, nil
}

// LoadTruststore loads custom root CA certificates from a file or specified truststore string format
// and appends them dynamically to the system root certificate pool (or creates a new pool if system pool unavailable).
func LoadTruststore(arg string) (*x509.CertPool, error) {
	if arg == "" {
		return nil, nil
	}

	path := arg
	parts := strings.Split(arg, ",")
	if len(parts) >= 1 {
		path = parts[0]
	}

	cleanPath, err := sanitizePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid truststore path: %w", err)
	}

	certs, err := x509.SystemCertPool()
	if err != nil || certs == nil {
		certs = x509.NewCertPool()
	}

	/* #nosec G304 -- User-supplied configuration path: path is sanitized using filepath.Clean before loading custom truststore PEM files */
	caCert, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read truststore file '%s': %w", cleanPath, err)
	}

	if !certs.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse PEM certificate from truststore '%s'", cleanPath)
	}

	return certs, nil
}

// LoadClientKeypair loads a client certificate and private key pair from a PEM file for mTLS authentication.
func LoadClientKeypair(arg string) ([]tls.Certificate, error) {
	if arg == "" {
		return nil, nil
	}

	parts := strings.Split(arg, ",")
	certPath := parts[0]
	cleanPath, err := sanitizePath(certPath)
	if err != nil {
		return nil, fmt.Errorf("invalid keystore path: %w", err)
	}

	/* #nosec G304 -- User-supplied configuration path: path is sanitized using filepath.Clean before loading custom mTLS client keypair PEM files */
	certPEM, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client keystore file '%s': %w", cleanPath, err)
	}

	cert, err := tls.X509KeyPair(certPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate/key from '%s': %w", cleanPath, err)
	}

	return []tls.Certificate{cert}, nil
}

// DaysUntilExpiration calculates the remaining days before an X.509 certificate expires relative to current time.
func DaysUntilExpiration(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	return int(time.Until(cert.NotAfter).Hours() / 24)
}
