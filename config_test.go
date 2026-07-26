// Package tlstester unit tests for config.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies that default Configuration parameter constructors (NewConfig) initialize expected
// safe network timeouts, worker counts, and default ports. Validates StringSliceFlag CLI parsing
// mechanics (Set and String methods) for slice flag ingestion without side effects.
package tlstester

import (
	"testing"
	"time"
)

// TestNewConfigDefaults verifies default parameter initialization of NewConfig().
func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", cfg.Timeout)
	}
	if cfg.Retries != 3 {
		t.Errorf("expected default retries 3, got %d", cfg.Retries)
	}
	if cfg.Workers != 4 {
		t.Errorf("expected default workers 4, got %d", cfg.Workers)
	}
	if cfg.Ports != "443" {
		t.Errorf("expected default ports '443', got '%s'", cfg.Ports)
	}
	if cfg.ProxyType != "http" {
		t.Errorf("expected default proxy-type 'http', got '%s'", cfg.ProxyType)
	}
}

// TestStringSliceFlag tests repeatable command-line flag value accumulation and formatting.
func TestStringSliceFlag(t *testing.T) {
	var flag StringSliceFlag
	if flag.String() != "" {
		t.Errorf("expected empty string for new flag, got '%s'", flag.String())
	}

	err := flag.Set("value1")
	if err != nil {
		t.Fatalf("unexpected error setting flag: %v", err)
	}
	_ = flag.Set("value2")

	if len(flag) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(flag))
	}
	if flag[0] != "value1" || flag[1] != "value2" {
		t.Errorf("unexpected slice content: %v", flag)
	}
	if flag.String() != "value1, value2" {
		t.Errorf("unexpected String() representation: '%s'", flag.String())
	}
}
