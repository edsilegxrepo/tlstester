// Package tlstester provides the core orchestration engine and programmatic APIs for probing
// network targets, inspecting X.509 certificate chains, scanning supported TLS protocols/ciphers,
// querying active AIA OCSP responders, and verifying application HTTP health.
//
// OBJECTIVES:
// Supply a thread-safe, side-effect-free diagnostic engine that can be consumed both as an importable
// Go library package and as a command-line binary.
//
// CORE COMPONENTS & DATA FLOW:
// - Config (config.go): Holds diagnostic parameters, flags, timeouts, and options.
// - Target & TargetResult (target.go): Defines target structures, Cartesian grid expansion, and diagnostic output models.
// - Runner (runner.go): Coordinates Goroutine worker pools, TLS config creation, and probe dispatches.
// - Security Environment (diagnose.go): Inspects Go compiler runtime and cryptographic environment.
package tlstester

import (
	"strings"
	"time"
)

// Config holds configuration parameters and execution options for TLS diagnostic operations.
// It is side-effect-free and thread-safe for concurrent read access across worker Goroutines.
type Config struct {
	Hostport           string        `json:"hostport,omitempty"`
	Endpoints          []string      `json:"endpoints,omitempty"`
	URLs               []string      `json:"urls,omitempty"`
	File               string        `json:"file,omitempty"`
	Hostnames          string        `json:"hostnames,omitempty"`
	Ports              string        `json:"ports,omitempty"`
	Workers            int           `json:"workers"`
	Timeout            time.Duration `json:"timeout_ns"`
	Retries            int           `json:"retries"`
	TLSVersion         string        `json:"tls_version,omitempty"`
	CipherSuite        string        `json:"cipher_suite,omitempty"`
	Keystore           string        `json:"keystore,omitempty"`
	Truststore         string        `json:"truststore,omitempty"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
	SNI                string        `json:"sni,omitempty"`
	NoSNI              bool          `json:"no_sni"`
	Proxy              string        `json:"proxy,omitempty"`
	ProxyType          string        `json:"proxy_type,omitempty"`
	Headers            []string      `json:"headers,omitempty"`
	AssertStatus       string        `json:"assert_status,omitempty"`
	Cert               bool          `json:"cert"`
	ExportCert         string        `json:"export_cert,omitempty"`
	Scan               bool          `json:"scan"`
	JSON               bool          `json:"json"`
	CSV                string        `json:"csv,omitempty"`
	Log                string        `json:"log,omitempty"`
	Color              bool          `json:"color"`
	NoColor            bool          `json:"no_color"`
	Verbose            bool          `json:"verbose"`
	Diagnose           bool          `json:"diagnose"`
	Version            bool          `json:"version"`
	WarnDays           int           `json:"warn_days"`
	CheckOCSP          bool          `json:"check_ocsp"`
}

// NewConfig initializes a Config struct with safe production default parameters
// (default HTTPS port 443, 4 worker threads, 10s timeout, 3 retries, HTTP proxy default type).
func NewConfig() *Config {
	return &Config{
		Ports:     "443",
		Workers:   4,
		Timeout:   10 * time.Second,
		Retries:   3,
		ProxyType: "http",
	}
}

// StringSliceFlag assists CLI flag parsing for repeated slice flags (e.g. -endpoint, -url, -header).
type StringSliceFlag []string

// String formats the slice as a comma-separated string for flag display.
func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

// Set appends a newly parsed flag value to the StringSliceFlag slice.
func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
