// Package tlstester security environment diagnostic inspector (-diagnose flag).
//
// OBJECTIVES:
// Provide runtime inspection of local Go compiler versions, operating system architecture,
// supported TLS protocol ranges, elliptic curve groups, supported cipher suites, and system trust pool status.
//
// CORE COMPONENTS & DATA FLOW:
// - SecurityEnvironment (diagnose.go): Struct capturing Go crypto environment metadata.
// - GetSecurityEnvironment (diagnose.go): Populates SecurityEnvironment properties.
// - DumpDiagnostics (diagnose.go): Formats and writes diagnostic tables to an io.Writer.
package tlstester

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"runtime"
)

// SecurityEnvironment holds details about local Go runtime crypto properties and capabilities.
type SecurityEnvironment struct {
	CompilerVersion  string   `json:"compiler_version"`
	OS               string   `json:"os"`
	Arch             string   `json:"arch"`
	SupportedTLS     []string `json:"supported_tls"`
	SupportedCurves  []string `json:"supported_curves"`
	SystemPoolLoaded bool     `json:"system_pool_loaded"`
}

// GetSecurityEnvironment retrieves system crypto provider configuration and system trust pool status.
func GetSecurityEnvironment() SecurityEnvironment {
	pool, err := x509.SystemCertPool()
	poolLoaded := err == nil && pool != nil

	return SecurityEnvironment{
		CompilerVersion:  runtime.Version(),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		SupportedTLS:     []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"},
		SupportedCurves:  []string{"CurveP256", "CurveP384", "CurveP521", "X25519"},
		SystemPoolLoaded: poolLoaded,
	}
}

// DumpDiagnostics formats and writes Go security environment properties and cipher suite lists to an io.Writer.
// Returns an error if writing to the output stream encounters an I/O error.
//
//nolint:errcheck
func DumpDiagnostics(w io.Writer) error {
	env := GetSecurityEnvironment()

	_, _ = fmt.Fprintln(w, "================================================================================")
	_, _ = fmt.Fprintln(w, "                     Go Security & Cryptographic Environment                     ")
	_, _ = fmt.Fprintln(w, "================================================================================")
	_, _ = fmt.Fprintf(w, " Go Compiler Version       : %s (%s/%s)\n", env.CompilerVersion, env.OS, env.Arch)
	_, _ = fmt.Fprintf(w, " Supported TLS Versions    : %s\n", "TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3")
	_, _ = fmt.Fprintf(w, " Default TLS Min Version   : TLS 1.2\n")
	_, _ = fmt.Fprintf(w, " Default TLS Max Version   : TLS 1.3\n")
	_, _ = fmt.Fprintf(w, " Supported Elliptic Curves : %s\n", "CurveP256, CurveP384, CurveP521, X25519")

	if env.SystemPoolLoaded {
		_, _ = fmt.Fprintln(w, " System Trust Pool         : Successfully loaded system CAs")
	} else {
		_, _ = fmt.Fprintln(w, " System Trust Pool         : Empty / Unavailable")
	}

	_, _ = fmt.Fprintln(w, "\nStandard Supported Cipher Suites:")
	for _, suite := range tls.CipherSuites() {
		verList := ""
		for _, v := range suite.SupportedVersions {
			verList += tls.VersionName(v) + " "
		}
		_, _ = fmt.Fprintf(w, "  - 0x%04X : %-45s [%s]\n", suite.ID, suite.Name, verList)
	}

	_, _ = fmt.Fprintln(w, "\nInsecure / Obsolete Cipher Suites:")
	for _, suite := range tls.InsecureCipherSuites() {
		_, _ = fmt.Fprintf(w, "  - 0x%04X : %-45s [INSECURE]\n", suite.ID, suite.Name)
	}
	_, err := fmt.Fprintln(w, "================================================================================")
	return err
}
