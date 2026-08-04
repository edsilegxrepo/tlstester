// Package certs unit tests for certs.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies certificate parsing, validity calculations, and security controls:
//  1. DaysUntilExpiration calculation for nil certificates and valid NotAfter time windows.
//  2. LoadTruststore handling of empty input paths, non-existent files, and invalid non-PEM contents.
//  3. LoadClientKeypair handling of empty input strings, non-existent files, and invalid keypair PEM data.
//  4. TestLoadTruststorePathTraversal & TestLoadClientKeypairPathTraversal: Path traversal prevention
//     security tests verifying that sanitizePath blocks directory escape attempts (../).
package certs

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDaysUntilExpiration verifies remaining validity days calculation for X.509 certificates.
func TestDaysUntilExpiration(t *testing.T) {
	if DaysUntilExpiration(nil) != 0 {
		t.Error("expected 0 for nil cert")
	}

	cert := &x509.Certificate{
		NotAfter: time.Now().Add(48 * time.Hour),
	}
	days := DaysUntilExpiration(cert)
	if days < 1 || days > 2 {
		t.Errorf("expected ~2 days until expiration, got %d", days)
	}
}

// TestLoadTruststoreEmpty tests handling of empty truststore input paths.
func TestLoadTruststoreEmpty(t *testing.T) {
	pool, err := LoadTruststore("")
	if err != nil || pool != nil {
		t.Errorf("expected nil pool and nil error for empty path")
	}
}

// TestLoadTruststoreNonExistent tests error handling when truststore file does not exist.
func TestLoadTruststoreNonExistent(t *testing.T) {
	_, err := LoadTruststore("non_existent_file.pem")
	if err == nil {
		t.Error("expected error for non-existent truststore file")
	}
}

// TestLoadTruststoreInvalidContent tests error handling when truststore file contains invalid non-PEM content.
func TestLoadTruststoreInvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "invalid.pem")
	_ = os.WriteFile(filePath, []byte("NOT A PEM CERTIFICATE"), 0o600)

	_, err := LoadTruststore(filePath)
	if err == nil {
		t.Error("expected error for invalid PEM content")
	}
}

// TestLoadClientKeypairEmpty tests handling of empty client keystore input paths.
func TestLoadClientKeypairEmpty(t *testing.T) {
	certs, err := LoadClientKeypair("")
	if err != nil || len(certs) != 0 {
		t.Errorf("expected empty certs for empty keystore string")
	}
}

// TestLoadClientKeypairNonExistent tests error handling when client keystore file does not exist.
func TestLoadClientKeypairNonExistent(t *testing.T) {
	_, err := LoadClientKeypair("non_existent_key.pem")
	if err == nil {
		t.Error("expected error for non-existent keystore file")
	}
}

// TestLoadClientKeypairInvalidContent tests error handling when client keystore file contains invalid PEM keypair data.
func TestLoadClientKeypairInvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "invalid_key.pem")
	_ = os.WriteFile(filePath, []byte("NOT A VALID KEYPAIR"), 0o600)

	_, err := LoadClientKeypair(filePath)
	if err == nil {
		t.Error("expected error for invalid keypair PEM content")
	}
}

// TestLoadTruststorePathTraversal tests that path traversal is blocked in LoadTruststore.
func TestLoadTruststorePathTraversal(t *testing.T) {
	_, err := LoadTruststore("../../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal attempt")
	}
}

// TestLoadClientKeypairPathTraversal tests that path traversal is blocked in LoadClientKeypair.
func TestLoadClientKeypairPathTraversal(t *testing.T) {
	_, err := LoadClientKeypair("../../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal attempt")
	}
}
