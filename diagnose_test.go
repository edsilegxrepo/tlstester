// Package tlstester unit tests for diagnose.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies security environment inspection:
// 1. GetSecurityEnvironment returns populated compiler version, OS, Arch, and supported TLS versions.
// 2. DumpDiagnostics writes formatted diagnostic tables to an io.Buffer without errors.
package tlstester

import (
	"bytes"
	"strings"
	"testing"
)

// TestGetSecurityEnvironment tests Go compiler and crypto runtime metadata extraction.
func TestGetSecurityEnvironment(t *testing.T) {
	env := GetSecurityEnvironment()
	if env.CompilerVersion == "" {
		t.Error("expected non-empty compiler version")
	}
	if env.OS == "" || env.Arch == "" {
		t.Error("expected non-empty OS and Arch")
	}
	if len(env.SupportedTLS) == 0 {
		t.Error("expected supported TLS versions list")
	}
}

// TestDumpDiagnostics tests writing formatted security diagnostic reports to an io.Writer.
func TestDumpDiagnostics(t *testing.T) {
	var buf bytes.Buffer
	err := DumpDiagnostics(&buf)
	if err != nil {
		t.Fatalf("DumpDiagnostics failed: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Go Security & Cryptographic Environment") {
		t.Errorf("diagnostic output missing header: %s", out)
	}
	if !strings.Contains(out, "Supported TLS Versions") {
		t.Errorf("diagnostic output missing TLS versions: %s", out)
	}
	if !strings.Contains(out, "Standard Supported Cipher Suites") {
		t.Errorf("diagnostic output missing cipher suites: %s", out)
	}
}
