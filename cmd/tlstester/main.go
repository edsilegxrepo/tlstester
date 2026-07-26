// Package main provides the standalone executable binary entry point for tlstester.
//
// OBJECTIVES:
// Parse command-line flags into a tlstester.Config instance, trigger target ingestion, wire OS interrupt
// signals (SIGINT/SIGTERM) to context deadlines, dispatch parallel diagnostics, and output reports
// to stdout, log files, JSON streams, or CSV summaries.
//
// CORE COMPONENTS & DATA FLOW:
//   - main (cmd/tlstester/main.go): CLI entry point handling flag registration, signal context creation,
//     log file creation, diagnostic execution, output formatting, and granular exit code resolution.
//
// GRANULAR EXIT CODES:
//   - Exit 0: Success (All target checks passed).
//   - Exit 1: General Target Probe / Status Failure (TCP connect, TLS handshake, or status assertion failure).
//   - Exit 2: Invalid CLI Usage / Target Parsing Error.
//   - Exit 3: I/O File Creation / Log File Error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"criticalsys.net/tlstester"
	"criticalsys.net/tlstester/reporter"
)

var version = "1.0.0"

// Exit codes for diagnostic automation and pipeline scripting
const (
	ExitSuccess       = 0
	ExitTargetFailure = 1
	ExitUsageError    = 2
	ExitIOError       = 3
)

func main() {
	cfg := tlstester.NewConfig()

	var endpointsFlag tlstester.StringSliceFlag
	var urlsFlag tlstester.StringSliceFlag
	var headersFlag tlstester.StringSliceFlag

	flag.StringVar(&cfg.Hostport, "hostport", "", "Hostname:port to test")
	flag.Var(&endpointsFlag, "endpoint", "Target server endpoint (host:port), can be repeated")
	flag.Var(&urlsFlag, "url", "Target URL to check, can be repeated")
	flag.StringVar(&cfg.File, "file", "", "File path containing targets, or '-' for stdin")
	flag.StringVar(&cfg.Hostnames, "hostname", "", "Comma-separated list of hostnames")
	flag.StringVar(&cfg.Ports, "port", "443", "Comma-separated list of ports to pair with hostnames")
	flag.IntVar(&cfg.Workers, "workers", 4, "Number of concurrent execution workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout for network operations")
	flag.IntVar(&cfg.Retries, "retries", 3, "Number of connection retries")
	flag.StringVar(&cfg.TLSVersion, "tls", "", "Specific TLS version (e.g., TLS1.0, TLS1.1, TLS1.2, TLS1.3)")
	flag.StringVar(&cfg.CipherSuite, "cipher", "", "Specific Cipher Suite name")
	flag.StringVar(&cfg.Keystore, "keystore", "", "Client keystore for mTLS: <file>,<type>[,<passfile>]")
	flag.StringVar(&cfg.Truststore, "truststore", "", "Custom truststore: <file>,<type>[,<passfile>]")
	flag.BoolVar(&cfg.InsecureSkipVerify, "insecure", false, "Skip chain of trust verification")
	flag.StringVar(&cfg.SNI, "sni", "", "Override Server Name Indication (SNI) hostname")
	flag.BoolVar(&cfg.NoSNI, "no-sni", false, "Disable Server Name Indication (SNI)")
	flag.StringVar(&cfg.Proxy, "proxy", "", "Route outbound traffic through proxy host:port")
	flag.StringVar(&cfg.ProxyType, "proxy-type", "http", "Proxy protocol type: http or socks")
	flag.Var(&headersFlag, "header", "Custom HTTP request header (e.g., 'Header: Value'), can be repeated")
	flag.StringVar(&cfg.AssertStatus, "assert-status", "", "Comma-separated expected HTTP status codes (e.g., '200,301')")
	flag.BoolVar(&cfg.Cert, "cert", false, "Display complete certificate chain details")
	flag.StringVar(&cfg.ExportCert, "export-cert", "", "Export peer certificates with specified prefix")
	flag.BoolVar(&cfg.Scan, "scan", false, "Execute full protocol and cipher suite scan")
	flag.BoolVar(&cfg.JSON, "json", false, "Format output as serialized JSON array")
	flag.StringVar(&cfg.CSV, "csv", "", "Path to write aggregated CSV report summary")
	flag.StringVar(&cfg.Log, "log", "", "Redirect console output to specified log file")
	flag.BoolVar(&cfg.Color, "color", false, "Force ANSI color output")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Suppress ANSI color output")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose diagnostic logs")
	flag.BoolVar(&cfg.Diagnose, "diagnose", false, "Dump Go security/crypto environment properties")
	flag.BoolVar(&cfg.Version, "version", false, "Display version information")
	flag.IntVar(&cfg.WarnDays, "warn-days", 0, "Warn/fail if certificate expires within N days")
	flag.BoolVar(&cfg.CheckOCSP, "check-ocsp", false, "Actively query AIA OCSP endpoint for revocation status")

	flag.Parse()

	cfg.Endpoints = endpointsFlag
	cfg.URLs = urlsFlag
	cfg.Headers = headersFlag

	// Display Version
	if cfg.Version {
		fmt.Printf("TLS Connection Tester - Version %s\n", version)
		os.Exit(ExitSuccess)
	}

	// Security Diagnostics mode
	if cfg.Diagnose {
		if err := tlstester.DumpDiagnostics(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing security environment diagnostics: %v\n", err)
			os.Exit(ExitIOError)
		}
		os.Exit(ExitSuccess)
	}

	// Parse Targets
	targets, err := tlstester.ParseTargets(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing targets: %v\n", err)
		os.Exit(ExitUsageError)
	}

	// Context for cancellation & signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Log Redirection (-log)
	var outputWriter io.Writer = os.Stdout
	if cfg.Log != "" {
		logFile, err := os.Create(cfg.Log)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating log file '%s': %v\n", cfg.Log, err)
			os.Exit(ExitIOError)
		}
		defer func() {
			if closeErr := logFile.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "Error closing log file '%s': %v\n", cfg.Log, closeErr)
			}
		}()
		outputWriter = io.MultiWriter(os.Stdout, logFile)
	}

	// Run Diagnostics
	results := tlstester.RunDiagnostics(ctx, cfg, targets)

	// Format Output
	if cfg.JSON {
		if err := reporter.JSON(outputWriter, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON: %v\n", err)
		}
	} else {
		reporter.Dashboard(outputWriter, cfg, results)
	}

	// CSV Export
	if cfg.CSV != "" {
		csvFile, err := os.Create(cfg.CSV)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating CSV file '%s': %v\n", cfg.CSV, err)
			os.Exit(ExitIOError)
		} else {
			if csvErr := reporter.CSV(csvFile, results); csvErr != nil {
				fmt.Fprintf(os.Stderr, "Error writing CSV report: %v\n", csvErr)
			}
			if closeErr := csvFile.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "Error closing CSV file '%s': %v\n", cfg.CSV, closeErr)
			}
		}
	}

	// Granular Exit Code Resolution
	hasFailures := false
	for _, r := range results {
		if !r.TCPConnected || !r.TLSHandshakeSuccess || r.Error != "" {
			hasFailures = true
			break
		}
	}

	if hasFailures {
		os.Exit(ExitTargetFailure)
	}
	os.Exit(ExitSuccess)
}
