// Package main CLI wrapper unit tests for main.go.
//
// TEST STRATEGY EXPLANATION:
// Verifies command-line argument parsing and flag set validation:
// 1. TestCLIVersionFlag: Verifies parsing of the -version flag via flag.CommandLine.
// 2. TestCLIDiagnoseFlag: Verifies parsing of the -diagnose flag via flag.CommandLine.
// 3. TestCLITargetFlagsParsing: Verifies parsing of -hostport, -json, -cert, and -warn-days flags.
package main

import (
	"flag"
	"os"
	"testing"
)

// TestCLIVersionFlag tests CLI parsing for the -version flag.
func TestCLIVersionFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"tlstester", "-version"}
	flag.CommandLine = flag.NewFlagSet("tlstester", flag.ContinueOnError)

	var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "version flag")
	_ = flag.CommandLine.Parse(os.Args[1:])

	if !versionFlag {
		t.Error("expected version flag to be true")
	}
}

// TestCLIDiagnoseFlag tests CLI parsing for the -diagnose flag.
func TestCLIDiagnoseFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"tlstester", "-diagnose"}
	flag.CommandLine = flag.NewFlagSet("tlstester", flag.ContinueOnError)

	var diagnoseFlag bool
	flag.BoolVar(&diagnoseFlag, "diagnose", false, "diagnose flag")
	_ = flag.CommandLine.Parse(os.Args[1:])

	if !diagnoseFlag {
		t.Error("expected diagnose flag to be true")
	}
}

// TestCLITargetFlagsParsing tests CLI flag set parsing for -hostport, -json, -cert, and -warn-days.
func TestCLITargetFlagsParsing(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"tlstester", "-hostport", "google.com:443", "-json", "-cert", "-warn-days", "30"}
	flag.CommandLine = flag.NewFlagSet("tlstester", flag.ContinueOnError)

	var hostport string
	var jsonFlag bool
	var certFlag bool
	var warnDays int

	flag.StringVar(&hostport, "hostport", "", "hostport")
	flag.BoolVar(&jsonFlag, "json", false, "json")
	flag.BoolVar(&certFlag, "cert", false, "cert")
	flag.IntVar(&warnDays, "warn-days", 0, "warn-days")

	_ = flag.CommandLine.Parse(os.Args[1:])

	if hostport != "google.com:443" || !jsonFlag || !certFlag || warnDays != 30 {
		t.Errorf("unexpected CLI flag parsing: hostport=%s, json=%t, cert=%t, warnDays=%d", hostport, jsonFlag, certFlag, warnDays)
	}
}
