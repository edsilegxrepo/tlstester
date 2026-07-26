// Package tlstester unit tests for runner.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies tls.Config generation logic across various parameter configurations:
// 1. Min/Max TLS version forcing for TLS 1.0, 1.1, 1.2, 1.3.
// 2. Error handling when invalid/unsupported TLS version strings are supplied.
// 3. Mapping of standard Go cipher suite names to binary uint16 cipher IDs.
// 4. Server Name Indication (SNI) rules: default host SNI, custom -sni override, and -no-sni suppression.
package tlstester

import (
	"crypto/tls"
	"testing"
)

// TestCreateTLSConfigVersions tests TLS min/max version mapping for TLS 1.0, 1.1, 1.2, and 1.3.
func TestCreateTLSConfigVersions(t *testing.T) {
	target := Target{Host: "example.com", Port: 443}

	versions := []struct {
		input   string
		minVers uint16
		maxVers uint16
	}{
		{"TLS1.0", tls.VersionTLS10, tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13, tls.VersionTLS13},
	}

	for _, tt := range versions {
		cfg := NewConfig()
		cfg.TLSVersion = tt.input

		tlsConfig, err := CreateTLSConfig(cfg, target)
		if err != nil {
			t.Fatalf("unexpected error creating TLS config for version %s: %v", tt.input, err)
		}

		if tlsConfig.MinVersion != tt.minVers || tlsConfig.MaxVersion != tt.maxVers {
			t.Errorf("expected min/max version %d/%d for %s, got %d/%d", tt.minVers, tt.maxVers, tt.input, tlsConfig.MinVersion, tlsConfig.MaxVersion)
		}
	}
}

// TestCreateTLSConfigInvalidVersion verifies error handling when an unsupported TLS version string is provided.
func TestCreateTLSConfigInvalidVersion(t *testing.T) {
	cfg := NewConfig()
	cfg.TLSVersion = "TLS9.9"
	target := Target{Host: "example.com", Port: 443}

	_, err := CreateTLSConfig(cfg, target)
	if err == nil {
		t.Error("expected error for invalid TLS version")
	}
}

// TestCreateTLSConfigCipherSuite tests mapping standard Go cipher suite names into binary cipher IDs.
func TestCreateTLSConfigCipherSuite(t *testing.T) {
	cfg := NewConfig()
	cfg.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	target := Target{Host: "example.com", Port: 443}

	tlsConfig, err := CreateTLSConfig(cfg, target)
	if err != nil {
		t.Fatalf("unexpected error creating TLS config with cipher suite: %v", err)
	}

	if len(tlsConfig.CipherSuites) != 1 {
		t.Errorf("expected 1 cipher suite, got %d", len(tlsConfig.CipherSuites))
	}
}

// TestCreateTLSConfigSNI tests default SNI, custom SNI override, and SNI suppression (-no-sni).
func TestCreateTLSConfigSNI(t *testing.T) {
	target := Target{Host: "example.com", Port: 443}

	// Default SNI
	cfg1 := NewConfig()
	tc1, _ := CreateTLSConfig(cfg1, target)
	if tc1.ServerName != "example.com" {
		t.Errorf("expected default SNI 'example.com', got '%s'", tc1.ServerName)
	}

	// Override SNI
	cfg2 := NewConfig()
	cfg2.SNI = "custom.com"
	tc2, _ := CreateTLSConfig(cfg2, target)
	if tc2.ServerName != "custom.com" {
		t.Errorf("expected custom SNI 'custom.com', got '%s'", tc2.ServerName)
	}

	// No SNI
	cfg3 := NewConfig()
	cfg3.NoSNI = true
	tc3, _ := CreateTLSConfig(cfg3, target)
	if tc3.ServerName != "" {
		t.Errorf("expected empty SNI for NoSNI, got '%s'", tc3.ServerName)
	}
}
