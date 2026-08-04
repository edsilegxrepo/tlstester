// Package tlstester unit tests for target.go.
//
// TEST STRATEGY EXPLANATION:
// Validates target parsing mechanics across multiple input sources:
// 1. Raw URL string parsing (scheme, host, port defaults, request paths).
// 2. Cartesian grid expansion (-hostname x -port) to confirm grid arithmetic.
// 3. Target file ingestion skipping comments (#) and blank lines.
// 4. Error validation when target inputs are completely empty or invalid.
package tlstester

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseURLTarget verifies URL parsing into structured Target tuples across valid and invalid inputs.
func TestParseURLTarget(t *testing.T) {
	tests := []struct {
		input        string
		expectedHost string
		expectedPort int
		expectedPath string
		expectError  bool
	}{
		{"example.com:443", "example.com", 443, "/", false},
		{"https://example.com:8443/api/v1", "example.com", 8443, "/api/v1", false},
		{"http://example.com/status", "example.com", 80, "/status", false},
		{"192.168.1.1:8443", "192.168.1.1", 8443, "/", false},
		{"invalid_url:not_a_port", "", 0, "", true},
		{":443", "", 0, "", true},
	}

	for _, tt := range tests {
		target, err := ParseURLTarget(tt.input)
		if tt.expectError {
			if err == nil {
				t.Errorf("expected error for input '%s', got nil", tt.input)
			}
			continue
		}

		if err != nil {
			t.Fatalf("unexpected error for input '%s': %v", tt.input, err)
		}
		if target.Host != tt.expectedHost {
			t.Errorf("expected host %s, got %s", tt.expectedHost, target.Host)
		}
		if target.Port != tt.expectedPort {
			t.Errorf("expected port %d, got %d", tt.expectedPort, target.Port)
		}
		if target.HTTPPath != tt.expectedPath {
			t.Errorf("expected path %s, got %s", tt.expectedPath, target.HTTPPath)
		}
	}
}

// TestCartesianTargetExpansion verifies Cartesian product expansion across multiple hostnames and ports.
func TestCartesianTargetExpansion(t *testing.T) {
	cfg := NewConfig()
	cfg.Hostnames = "host1.com, host2.com"
	cfg.Ports = "443, 8443"

	targets, err := ParseTargets(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 4 {
		t.Errorf("expected 4 targets from 2x2 expansion, got %d", len(targets))
	}
}

// TestParseTargetsFromFile tests file-based target ingestion skipping empty lines and comments (#).
func TestParseTargetsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")

	content := "# Comment line\nexample.com:443\n\n# Another comment\n10.0.0.1:8443\n"
	err := os.WriteFile(targetFile, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write temp target file: %v", err)
	}

	cfg := NewConfig()
	cfg.File = targetFile

	targets, err := ParseTargets(cfg)
	if err != nil {
		t.Fatalf("ParseTargets failed: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets from file, got %d", len(targets))
	}
}

// TestParseTargetsEmpty verifies error handling when no targets are specified or config is nil.
func TestParseTargetsEmpty(t *testing.T) {
	cfg := NewConfig()
	_, err := ParseTargets(cfg)
	if err == nil {
		t.Error("expected error for empty targets config")
	}

	_, err = ParseTargets(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}

	cfgErr := NewConfig()
	cfgErr.Hostport = ":invalid"
	_, err = ParseTargets(cfgErr)
	if err == nil {
		t.Error("expected error for invalid hostport")
	}

	cfgFileErr := NewConfig()
	cfgFileErr.File = "non_existent_file_xyz.txt"
	_, err = ParseTargets(cfgFileErr)
	if err == nil {
		t.Error("expected error for non existent target file")
	}
}

// TestParseTargetsWithWarnings tests file parsing with invalid lines generating warnings.
func TestParseTargetsWithWarnings(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets_with_errors.txt")

	// File with one valid and one invalid target
	content := "example.com:443\n:invalid_no_host\ngoogle.com:443\n"
	err := os.WriteFile(targetFile, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write temp target file: %v", err)
	}

	cfg := NewConfig()
	cfg.File = targetFile

	result, err := ParseTargetsWithWarnings(cfg)
	if err != nil {
		t.Fatalf("ParseTargetsWithWarnings failed: %v", err)
	}

	// Should have 2 valid targets
	if len(result.Targets) != 2 {
		t.Errorf("expected 2 valid targets, got %d", len(result.Targets))
	}

	// Should have 1 warning for the invalid line
	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(result.Warnings))
	}
}

// TestParseTargetsStrictParsing tests that StrictParsing fails on first invalid target.
func TestParseTargetsStrictParsing(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets_strict.txt")

	content := "example.com:443\n:invalid_no_host\ngoogle.com:443\n"
	err := os.WriteFile(targetFile, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write temp target file: %v", err)
	}

	cfg := NewConfig()
	cfg.File = targetFile
	cfg.StrictParsing = true

	_, err = ParseTargetsWithWarnings(cfg)
	if err == nil {
		t.Error("expected error with StrictParsing enabled")
	}
}
