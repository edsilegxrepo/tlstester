# TLS Connection Tester (Go tlstester) - High-Performance TLS Diagnostics Utility

`tlstester` is a production-grade, single-binary TLS diagnostics utility and importable Go library. It is designed to probe network targets, verify cryptographic configurations, audit certificate chains, test session resumption, scan supported TLS protocols/ciphers, evaluate HTTP/ALPN endpoints, perform active AIA OCSP revocation checks, and route outbound diagnostic traffic through HTTP or SOCKS proxies.

The utility is engineered for high concurrency, zero external dependencies, and instant startup across Linux, Windows, and macOS platforms. For system architecture, refer to [ARCHITECTURE.md](ARCHITECTURE.md). For detailed design specifications, refer to [DESIGN.md](DESIGN.md). For test suite documentation and coverage reports, refer to [TESTING.md](TESTING.md).

---

## 1. Application Overview and Objectives

The primary objective of `tlstester` is to provide a low-footprint, command-line-driven diagnostic tool and programmatic library to probe network targets and verify their cryptographic safety. It operates as a troubleshooting agent when debugging connection dropouts, trust validation failures, misconfigured Server Name Indication (SNI), certificate expiration, or service degradation.

### Key Functional Objectives
* **Dual-Consumption Architecture**: Consume BOTH as a standalone CLI executable (`cmd/tlstester`) and programmatically via Go subpackages (`import "github.com/edsilegxrepo/tlstester"` or `import "github.com/edsilegxrepo/tlstester/probes"`).
* **Parallelized Target Probing**: Scale diagnostics across multiple targets concurrently using configurable Goroutine worker pools (`-workers`).
* **Cartesian Probing Grid**: Support automated target grid expansion across combinations of hostnames and ports (`-hostname` and `-port`).
* **Cryptographic Auditing**: Enforce deep security validation of TLS protocols and cipher suites (`-scan`), scanning for obsolete protocols (TLS 1.0, TLS 1.1) and cryptographically weak ciphers.
* **Certificate Chain Validation**: Inspect certificate validity windows, CN/SAN matches, validation chains, serial numbers, and signature algorithms, capturing peer certificates even when handshakes fail.
* **Active AIA OCSP & Expiration Warnings**: Perform proper OCSP POST revocation checks with issuer verification (`-check-ocsp`), automatically fetching issuer certificates via AIA extension, and enforce certificate expiration warning thresholds (`-warn-days`).
* **Certificate Transparency (CT) SCT Parsing**: Detect and parse Signed Certificate Timestamps (SCTs) from TLS extensions or embedded in certificates, reporting CT log IDs and timestamps.
* **Dual-Layer Diagnostics**: Prove socket layer reachability (including SOCKS/HTTP proxy routing and UDP/QUIC reachability) as well as application-layer health via HTTP GET status assertions, ALPN verification, and `Alt-Svc` header extraction.
* **Structured Pipeline Output**: Supply tabular ANSI reports for humans, CSV exports (`-csv`), log file redirection (`-log`), and comprehensive JSON outputs (`-json`) for integration into automated CI/CD and deployment pipelines.

---

## 2. Security Assessment

### 2.1 Encryption in Transit
- **Strong Cryptographic Protocols**: Enforces TLS 1.2 and TLS 1.3 by default, supporting modern Perfect Forward Secrecy (PFS) ciphers (e.g. `TLS_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
- **ALPN & HTTP/2 Transport**: Supports Application-Layer Protocol Negotiation (`h2`, `http/1.1`) to verify secure HTTP version upgrades.
- **SNI Integrity**: Automatically populates Server Name Indication (SNI) extension headers matching target domains, with explicit override (`-sni`) and suppression (`-no-sni`) controls for vulnerability auditing.

### 2.2 Secret Management & Credentials Protection
- **Zero In-Memory String Retention**: Client private keys and truststore PEM files are parsed directly into standard Go `x509.CertPool` and `tls.Certificate` objects without persisting secrets in long-lived heap buffers.
- **Zero Hardcoded Credentials**: Contains zero hardcoded passwords, tokens, API keys, or private certificates.

### 2.3 Authentication & Trust Configurations
- **System Trust Pool Integration**: Inherits the operating system's native root certificate pool (`x509.SystemCertPool()`), merging user-supplied root certificates (`-truststore`) dynamically without discarding standard public CAs.
- **Mutual TLS (mTLS) Support**: Supports client certificate and keypair loading (`-keystore`) for authenticating against protected enterprise API gateways and microservices.

### 2.4 Unprivileged Execution Context & Access Control (RBAC)
- **Non-Root Operation**: Designed to execute in an unprivileged user space without requiring root or administrator privileges.
- **Least-Privilege Network Access**: Uses standard user-space TCP socket dialing (`net.DialContext`) and UDP datagram sockets (`net.ListenUDP`), avoiding raw socket root privilege requirements.

### 2.5 Non-Vulnerable Standard Library Footprint
- **Zero Third-Party Dependencies**: Built **100% on Go's standard library** (`crypto/tls`, `crypto/x509`, `net/http`, `net`, `golang.org/x/crypto/ocsp`), ensuring a minimal attack surface immune to supply-chain dependency vulnerabilities.

### 2.6 Input Validation & Path Traversal Prevention
- **Path Sanitization**: All file path inputs (truststores, keystores, certificate export prefixes) are sanitized using `filepath.Abs` and validated against directory traversal attacks (`../`).
- **HTTP Response Size Limits**: OCSP and AIA HTTP responses are bounded via `io.LimitReader` to prevent denial-of-service from oversized responses (10MB issuer certs, 1MB OCSP responses).
- **Hostname Sanitization**: Certificate export filenames sanitize hostnames to prevent directory creation via path separator injection.

---

## 3. Code Quality Assessment and Best Practices

### 3.1 Modular Decoupled Architecture
- **Single-Responsibility Subpackages**: Code is cleanly partitioned into `github.com/edsilegxrepo/tlstester` (orchestration), `github.com/edsilegxrepo/tlstester/probes` (low-level network calls), `github.com/edsilegxrepo/tlstester/certs` (truststore management), and `github.com/edsilegxrepo/tlstester/reporter` (output formatters).

### 3.2 Concurrency & Resource Management
- **Thread Safety**: Goroutine channels and sync primitives prevent race conditions during parallel target scans.
- **Defensive Resource Cleanup**: All network sockets, file streams, and HTTP response bodies use explicit `defer conn.Close()`, `defer resp.Body.Close()`, and `defer transport.CloseIdleConnections()` handlers to prevent socket/file descriptor leaks.
- **Context-Aware Cancellation**: All network operations propagate `context.Context` deadlines, handling OS signal cancellations (`SIGINT`/`SIGTERM`) gracefully.

### 3.3 Granular Exit Codes Reference
| Exit Code | Constant Name | Cause / Description |
| :--- | :--- | :--- |
| **0** | `ExitSuccess` | Success (All target checks passed). |
| **1** | `ExitTargetFailure` | Target Probe / Status Failure (TCP connect, TLS handshake, or status assertion failure). |
| **2** | `ExitUsageError` | Invalid CLI Usage / Target Parsing Error. |
| **3** | `ExitIOError` | File I/O Error (Log file, CSV report, or certificate export failure). |
| **4** | `ExitConfigError` | Invalid Configuration (TLS version, cipher suite, or truststore parsing failure). |
| **5** | `ExitPartialSuccess` | Partial Success (Some targets passed, some failed). |
| **130** | `ExitCancelled` | Interrupted by SIGINT (Standard Unix convention: 128 + signal number). |

### 3.4 Test Suite & Quality Assurance
- **80%+ Coverage Requirement**: Enforces an 80%+ statement coverage requirement across all packages (`83.8%` project average), combining sub-second in-memory mock unit tests with mandatory live integration tests against public CDNs. For full details, refer to [TESTING.md](TESTING.md).

---

## 4. Command Line Arguments Reference

```sh
tlstester [flags]
```

### Complete Flags Matrix

| Flag | Description | Type | Default Value |
| :--- | :--- | :--- | :--- |
| `-hostport` | Target server host:port to test | `string` | `""` |
| `-endpoint` | Target server endpoint (host:port), repeatable | `slice` | `[]` |
| `-url` | Target URL to check, repeatable | `slice` | `[]` |
| `-file` | Target list file path, or `-` for STDIN | `string` | `""` |
| `-hostname` | Comma-separated list of hostnames for grid expansion | `string` | `""` |
| `-port` | Comma-separated list of target ports for grid expansion | `string` | `"443"` |
| `-workers` | Number of concurrent execution Goroutines | `int` | `4` |
| `-timeout` | Network connect and read timeout | `time.Duration` | `10s` |
| `-retries` | Number of connection retry attempts | `int` | `3` |
| `-tls` | Forced TLS version (`TLS1.0`, `TLS1.1`, `TLS1.2`, `TLS1.3`) | `string` | `""` |
| `-cipher` | Specific Cipher Suite name to test | `string` | `""` |
| `-keystore` | Client certificate for mTLS: `<file>,<type>[,<passfile>]` | `string` | `""` |
| `-truststore` | Custom truststore path: `<file>,<type>[,<passfile>]` | `string` | `""` |
| `-insecure` | Skip server certificate chain verification | `bool` | `false` |
| `-sni` | Override Server Name Indication (SNI) host header | `string` | `""` |
| `-no-sni` | Disable SNI extension in ClientHello | `bool` | `false` |
| `-proxy` | Outbound proxy address (`host:port`) | `string` | `""` |
| `-proxy-type` | Outbound proxy type (`http` or `socks`) | `string` | `"http"` |
| `-header` | Custom HTTP request header (e.g. `'Header: Value'`), repeatable | `slice` | `[]` |
| `-assert-status`| Comma-separated expected HTTP statuses (e.g. `'200,301'`) | `string` | `""` |
| `-cert` | Print complete certificate chain details | `bool` | `false` |
| `-warn-days` | Warn/fail if cert expires within N days | `int` | `0` |
| `-check-ocsp` | Actively query AIA OCSP responder URL | `bool` | `false` |
| `-export-cert` | Save peer certs as PEM files with specified prefix | `string` | `""` |
| `-scan` | Execute full TLS protocol & cipher suite sweep | `bool` | `false` |
| `-json` | Format output as serialized JSON array | `bool` | `false` |
| `-csv` | Output path to write aggregated CSV report summary | `string` | `""` |
| `-log` | Redirect console output to specified log file | `string` | `""` |
| `-color` | Force ANSI color output | `bool` | `false` |
| `-no-color` | Suppress ANSI color output | `bool` | `false` |
| `-verbose` | Enable verbose diagnostic logging | `bool` | `false` |
| `-diagnose` | Dump Go crypto environment security properties | `bool` | `false` |
| `-version` | Display application version | `bool` | `false` |

---

## 5. Library Programmatic Usage

For detailed package hierarchy trees, Go API consumption patterns, and code examples for integrating `tlstester` into third-party Go applications, refer to [ARCHITECTURE.md](ARCHITECTURE.md#22-how-to-consume-the-library-in-third-party-go-applications).

---

## 6. Detailed Examples and Output Samples

### 6.1 Basic Target Probing & Cert Inspection with Sample Output
Command:
```sh
tlstester -endpoint google.com:443 -cert
```

Sample Output:
```text
================================================================================
                       TLS DIAGNOSTIC RESULTS DASHBOARD                        
================================================================================

Target [1/1]: google.com:443
  Resolved IPs         : 142.250.190.46, 2607:f8b0:4009:816::200e
  DNS Lookup Latency   : 12.4ms
  TCP Connect Latency  : 24.8ms
  TCP Connection       : CONNECTED
  TLS Handshake        : SUCCESS (42.1ms)
  Negotiated Protocol  : TLS 1.3
  Negotiated Cipher    : TLS_AES_128_GCM_SHA256
  ALPN Protocol        : h2
  Key Exchange Group   : TLS1.3 ECDHE/X25519 (Negotiated)
  OCSP Stapled         : true

  Certificate Chain Details:
    [1] Subject : CN=google.com
        Issuer  : CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
        Expires : 2026-08-20T14:32:00Z
        SANs    : google.com, *.google.com
        Serial  : 4F2A1B89CD7E0123
        SigAlgo : SHA256-RSA
================================================================================
```

### 6.2 JSON Formatting for Automated Pipelines with Sample Output
Command:
```sh
tlstester -endpoint google.com:443 -json
```

Sample Output:
```json
[
  {
    "target": {
      "host": "google.com",
      "port": 443,
      "raw_target": "google.com:443"
    },
    "resolved_ips": [
      "142.250.190.46"
    ],
    "dns_latency_ns": 12400000,
    "tcp_latency_ns": 24800000,
    "tcp_connected": true,
    "tls_handshake_success": true,
    "tls_handshake_latency_ns": 42100000,
    "tls_protocol": "TLS 1.3",
    "tls_cipher": "TLS_AES_128_GCM_SHA256",
    "tls_alpn": "h2",
    "negotiated_group": "TLS1.3 ECDHE/X25519 (Negotiated)",
    "ocsp_stapled": true,
    "cert_chain_trusted": true
  }
]
```

### 6.3 CSV Summary Report Export with Sample Output
Command:
```sh
tlstester -endpoint google.com:443 -csv report.csv
```

Sample Output (`report.csv` file contents):
```csv
Host,Port,DNS_Ms,TCP_Ms,TCP_Connected,TLS_Success,TLS_Ms,Protocol,Cipher,ALPN,OCSP_Stapled,HTTP_Status,Error
google.com,443,12,24,true,true,42,TLS 1.3,TLS_AES_128_GCM_SHA256,h2,true,200 OK,
```

### 6.4 Security Environment Diagnostic Dump with Sample Output
Command:
```sh
tlstester -diagnose
```

Sample Output:
```text
================================================================================
                     Go Security & Cryptographic Environment                     
================================================================================
 Go Compiler Version       : go1.22.1 (windows/amd64)
 Supported TLS Versions    : TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
 Default TLS Min Version   : TLS 1.2
 Default TLS Max Version   : TLS 1.3
 Supported Elliptic Curves : CurveP256, CurveP384, CurveP521, X25519
 System Trust Pool         : Successfully loaded system CAs

Standard Supported Cipher Suites:
  - 0x1301 : TLS_AES_128_GCM_SHA256                        [TLS 1.3 ]
  - 0x1302 : TLS_AES_256_GCM_SHA384                        [TLS 1.3 ]
  - 0x1303 : TLS_CHACHA20_POLY1305_SHA256                  [TLS 1.3 ]
  - 0xC02F : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        [TLS 1.2 ]
================================================================================
```

### 6.5 Cartesian Grid Expansion with Worker Concurrency
Scan multiple hostnames across multiple ports concurrently using 8 worker Goroutines:
```sh
tlstester -hostname google.com,cloudflare.com -port 443,8443 -workers 8
```

### 6.6 Protocol & Cipher Suite Capabilities Sweep with Sample Output
Command:
```sh
tlstester -endpoint api.github.com:443 -scan
```

Sample Output:
```text
  Protocol Scan Sweeps:
    TLS1.0     : DISABLED / REJECTED (22 ms)
    TLS1.1     : DISABLED / REJECTED (18 ms)
    TLS1.2     : SUPPORTED (38 ms)
    TLS1.3     : SUPPORTED (31 ms)
```

### 6.7 HTTP API Probe with Custom Headers & Status Assertion
Query a specific URL endpoint, inject custom headers, assert expected HTTP status codes, and output JSON:
```sh
tlstester -url https://api.github.com/status -header "Authorization: Bearer token" -header "Accept: application/json" -assert-status 200,301 -json
```

### 6.8 Cert Expiration Threshold Alert & Active AIA OCSP Check with Sample Output
Command:
```sh
tlstester -endpoint google.com:443 -warn-days 30 -check-ocsp
```

Sample Output:
```text
  Active OCSP Status   : OCSP Responder Reachable (http://ocsp.pki.goog/gts1c3) - HTTP 200 OK
  Cert Expiration Warn : Certificate expires in 25 days (2026-08-20T14:32:00Z)
```

### 6.9 Forced Specific TLS Version & Cipher Suite Testing
Test connection forcing TLS 1.2 and a specific cipher suite:
```sh
tlstester -hostport google.com:443 -tls TLS1.2 -cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### 6.10 Peer Certificate Export to PEM Files
Export server peer certificates as PEM-encoded files with prefix `/tmp/certs/server`:
```sh
tlstester -endpoint google.com:443 -export-cert /tmp/certs/server
```

Generates:
- `/tmp/certs/server_google.com_443_0.crt` (Leaf certificate)
- `/tmp/certs/server_google.com_443_1.crt` (Intermediate CA certificate)

### 6.11 Client Certificate Authentication (mTLS) Diagnostics
Specify a custom client certificate and truststore to troubleshoot a mutual TLS tunnel:
```sh
tlstester -endpoint internal-gw.corp:8443 -keystore /certs/client.pem -truststore /certs/ca.pem
```

### 6.12 Outbound SOCKS5 & HTTP Proxy Routing
Route diagnostics via an internal corporate bastion SOCKS5 or HTTP proxy server:
```sh
# SOCKS5 Proxy
tlstester -endpoint target-api.external.com:443 -proxy 10.0.1.200:1080 -proxy-type socks

# HTTP CONNECT Proxy
tlstester -endpoint target-api.external.com:443 -proxy 10.0.1.200:8080 -proxy-type http
```

### 6.13 Target File & STDIN Target List Ingestion
Load target endpoints from a file or STDIN:
```sh
# Read from file
tlstester -file /etc/ops/endpoints.list

# Pipe from STDIN
echo "192.168.1.50:8443" | tlstester -file - -endpoint google.com:443
```

#### Sample Target File (`endpoints.list`) Structure:
The target loader skips empty lines and lines starting with `#`:
```text
# Internal microservices
api.internal.corp
auth.internal.corp

# Direct IP targets
10.240.10.15

# Target with explicit port
app-server-01.internal.corp:8443

# URL target with path
https://k8s-ingress.internal.corp/healthz
```

### 6.14 SNI Override, SNI Suppression & Insecure Bypass
Audit target behavior under SNI manipulation or self-signed certificate environments:
```sh
# Override SNI header
tlstester -hostport 10.0.1.50:443 -sni internal.service.com

# Disable SNI extension entirely
tlstester -hostport 10.0.1.50:443 -no-sni

# Bypass chain-of-trust verification for self-signed certificates
tlstester -hostport self-signed.local:8443 -insecure
```

### 6.15 File Log Redirection
Redirect console diagnostic dashboard output to a log file on disk:
```sh
tlstester -endpoint google.com:443 -cert -log /var/log/tlstester/scan.log
```

---

## 7. Build and Packaging

`tlstester` compiles directly against Go's standard library with zero external dependencies.

### 7.1 Building the CLI Executable
To build the CLI executable from the source directory:
```bash
# Build the binary in the root directory
go build -o tlstester.exe ./cmd/tlstester

# Run all unit and integration tests across all subpackages
go test -v ./...
```

### 7.2 Cross-Platform Compilation
```bash
# Linux 64-bit binary
GOOS=linux GOARCH=amd64 go build -o bin/tlstester-linux-amd64 ./cmd/tlstester

# Windows 64-bit binary
GOOS=windows GOARCH=amd64 go build -o bin/tlstester-windows-amd64.exe ./cmd/tlstester

# macOS ARM64 (Apple Silicon) binary
GOOS=darwin GOARCH=arm64 go build -o bin/tlstester-darwin-arm64 ./cmd/tlstester
```

---

## 8. Troubleshooting

- **Invalid TLS version**: Ensure you use one of `TLS1.0`, `TLS1.1`, `TLS1.2`, or `TLS1.3`.
- **Invalid Cipher Suite**: Use standard Go cipher suite names. Note that TLS 1.3 cipher suites are not configurable via the `-cipher` flag in Go.
- **Connection failed after X retries**: Check network connectivity, DNS resolution, firewall rules, and proxy settings (`-proxy`).
- **Failed to parse root certificate**: Ensure the `-keystore` or `-truststore` file is a valid PEM-encoded certificate.
