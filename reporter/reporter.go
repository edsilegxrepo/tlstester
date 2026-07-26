// Package reporter provides side-effect-free diagnostic output formatting for stdout, files, or custom io.Writer targets.
//
// OBJECTIVES:
// Supply human-readable ANSI terminal dashboards, machine-readable JSON array exporters, and tabular CSV writers
// operating exclusively on the io.Writer interface without modifying global process state.
//
// CORE COMPONENTS & DATA FLOW:
// - Dashboard (reporter.go): Formats ANSI diagnostic summary tables with color highlights.
// - JSON (reporter.go): Serializes []TargetResult structs into indented JSON arrays.
// - CSV (reporter.go): Writes tabular CSV header rows and target record data.
package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"criticalsys.net/tlstester"
)

// Dashboard renders formatted ANSI diagnostic tables to the provided io.Writer target.
// Supports color output toggle based on configuration flags and NO_COLOR environment settings.
func Dashboard(w io.Writer, cfg *tlstester.Config, results []tlstester.TargetResult) {
	if cfg == nil {
		cfg = tlstester.NewConfig()
	}

	useColor := (cfg.Color || os.Getenv("NO_COLOR") == "") && !cfg.NoColor
	green := func(s string) string {
		if useColor {
			return "\033[32m" + s + "\033[0m"
		}
		return s
	}
	red := func(s string) string {
		if useColor {
			return "\033[31m" + s + "\033[0m"
		}
		return s
	}
	yellow := func(s string) string {
		if useColor {
			return "\033[33m" + s + "\033[0m"
		}
		return s
	}
	cyan := func(s string) string {
		if useColor {
			return "\033[36m" + s + "\033[0m"
		}
		return s
	}

	_, _ = fmt.Fprintln(w, "\n================================================================================")
	_, _ = fmt.Fprintln(w, "                       TLS DIAGNOSTIC RESULTS DASHBOARD                        ")
	_, _ = fmt.Fprintln(w, "================================================================================")

	for i, res := range results {
		_, _ = fmt.Fprintf(w, "\nTarget [%d/%d]: %s:%d\n", i+1, len(results), res.Target.Host, res.Target.Port)
		if len(res.ResolvedIPs) > 0 {
			_, _ = fmt.Fprintf(w, "  Resolved IPs         : %s\n", strings.Join(res.ResolvedIPs, ", "))
		}
		_, _ = fmt.Fprintf(w, "  DNS Lookup Latency   : %v\n", res.DNSLatency)
		_, _ = fmt.Fprintf(w, "  TCP Connect Latency  : %v\n", res.TCPLatency)

		if !res.TCPConnected {
			_, _ = fmt.Fprintf(w, "  TCP Connection       : %s\n", red("FAILED"))
			if res.Error != "" {
				_, _ = fmt.Fprintf(w, "  Error                : %s\n", res.Error)
			}
			continue
		}
		_, _ = fmt.Fprintf(w, "  TCP Connection       : %s\n", green("CONNECTED"))

		if !res.TLSHandshakeSuccess {
			_, _ = fmt.Fprintf(w, "  TLS Handshake        : %s (%v)\n", red("FAILED"), res.TLSHandshakeLatency)
			if res.CertChainTrustError != "" {
				_, _ = fmt.Fprintf(w, "  Trust Validation     : %s\n", red(res.CertChainTrustError))
			}
			if res.Error != "" {
				_, _ = fmt.Fprintf(w, "  Error                : %s\n", res.Error)
			}
			continue
		}

		_, _ = fmt.Fprintf(w, "  TLS Handshake        : %s (%v)\n", green("SUCCESS"), res.TLSHandshakeLatency)
		_, _ = fmt.Fprintf(w, "  Negotiated Protocol  : %s\n", cyan(res.TLSProtocol))
		_, _ = fmt.Fprintf(w, "  Negotiated Cipher    : %s\n", cyan(res.TLSCipher))
		if res.TLSAlpn != "" {
			_, _ = fmt.Fprintf(w, "  ALPN Protocol        : %s\n", cyan(res.TLSAlpn))
		}
		if res.NegotiatedGroup != "" {
			_, _ = fmt.Fprintf(w, "  Key Exchange Group   : %s\n", cyan(res.NegotiatedGroup))
		}
		_, _ = fmt.Fprintf(w, "  OCSP Stapled         : %t\n", res.OCSPStapled)
		if res.ActiveOCSPStatus != "" {
			_, _ = fmt.Fprintf(w, "  Active OCSP Status   : %s\n", res.ActiveOCSPStatus)
		}
		if res.CertExpirationWarning != "" {
			_, _ = fmt.Fprintf(w, "  Cert Expiration Warn : %s\n", yellow(res.CertExpirationWarning))
		}

		if res.SessionResumptionAttempted {
			if res.SessionResumptionSuccess {
				_, _ = fmt.Fprintf(w, "  Session Resumption   : %s (Latency: %v)\n", green("RESUMED"), res.SessionResumptionLatency)
			} else {
				_, _ = fmt.Fprintf(w, "  Session Resumption   : %s\n", yellow("NOT RESUMED"))
			}
		}

		if res.HTTPStatusLine != "" {
			_, _ = fmt.Fprintf(w, "  HTTP Status          : %s (TTFB: %v)\n", green(res.HTTPStatusLine), res.HTTPLatency)
		}
		if res.HTTPAltSvcLine != "" {
			_, _ = fmt.Fprintf(w, "  HTTP Alt-Svc         : %s\n", cyan(res.HTTPAltSvcLine))
		}

		if (cfg.Cert || cfg.Verbose) && len(res.CapturedChain) > 0 {
			_, _ = fmt.Fprintln(w, "\n  Certificate Chain Details:")
			for idx, cert := range res.CapturedChain {
				_, _ = fmt.Fprintf(w, "    [%d] Subject : %s\n", idx+1, cert.Subject)
				_, _ = fmt.Fprintf(w, "        Issuer  : %s\n", cert.Issuer)
				_, _ = fmt.Fprintf(w, "        Expires : %s\n", cert.NotAfter.Format(time.RFC3339))
				if len(cert.DNSNames) > 0 {
					_, _ = fmt.Fprintf(w, "        SANs    : %s\n", strings.Join(cert.DNSNames, ", "))
				}
				_, _ = fmt.Fprintf(w, "        Serial  : %X\n", cert.SerialNumber)
				_, _ = fmt.Fprintf(w, "        SigAlgo : %s\n", cert.SignatureAlgorithm)
			}
		}

		if len(res.ProtocolScanResults) > 0 {
			_, _ = fmt.Fprintln(w, "\n  Protocol Scan Sweeps:")
			for _, scan := range res.ProtocolScanResults {
				var statusStr string
				if strings.Contains(scan.Status, "SUPPORTED") {
					statusStr = green(scan.Status)
				} else {
					statusStr = yellow(scan.Status)
				}
				_, _ = fmt.Fprintf(w, "    %-10s : %s (%d ms)\n", scan.Protocol, statusStr, scan.LatencyMs)
			}
		}

		if res.Error != "" {
			_, _ = fmt.Fprintf(w, "  Error Assertion      : %s\n", red(res.Error))
		}
	}
	_, _ = fmt.Fprintln(w, "================================================================================")
}

// JSON serializes diagnostic results into an indented JSON array written to io.Writer.
func JSON(w io.Writer, results []tlstester.TargetResult) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing JSON results: %w", err)
	}
	_, err = w.Write(append(jsonData, '\n'))
	return err
}

// CSV exports diagnostic summary results to the provided io.Writer in CSV format.
func CSV(w io.Writer, results []tlstester.TargetResult) error {
	wWriter := csv.NewWriter(w)
	defer wWriter.Flush()

	_ = wWriter.Write([]string{
		"Host", "Port", "DNS_Ms", "TCP_Ms", "TCP_Connected",
		"TLS_Success", "TLS_Ms", "Protocol", "Cipher", "ALPN",
		"OCSP_Stapled", "HTTP_Status", "Error",
	})

	for _, res := range results {
		_ = wWriter.Write([]string{
			res.Target.Host,
			strconv.Itoa(res.Target.Port),
			strconv.FormatInt(res.DNSLatency.Milliseconds(), 10),
			strconv.FormatInt(res.TCPLatency.Milliseconds(), 10),
			strconv.FormatBool(res.TCPConnected),
			strconv.FormatBool(res.TLSHandshakeSuccess),
			strconv.FormatInt(res.TLSHandshakeLatency.Milliseconds(), 10),
			res.TLSProtocol,
			res.TLSCipher,
			res.TLSAlpn,
			strconv.FormatBool(res.OCSPStapled),
			res.HTTPStatusLine,
			res.Error,
		})
	}
	return nil
}
