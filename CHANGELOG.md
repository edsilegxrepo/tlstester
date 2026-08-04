# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-04

### Added
- **OCSP Revocation Checking**: Proper RFC 6960 OCSP POST requests with issuer verification (`CheckOCSPRevocation`)
- **AIA Issuer Fetching**: Automatic issuer certificate retrieval via AIA extension (`FetchIssuerFromAIA`)
- **Certificate Transparency SCT Parsing**: Parse SCTs from TLS extension or embedded in certificates (`SCTInfo`, `parseSCT`, `parseEmbeddedSCTs`)
- **Leaf Certificate Metadata**: New fields for library consumers: `LeafSubject`, `LeafIssuer`, `LeafSANs`, `LeafNotBefore`, `LeafNotAfter`, `LeafIsExpired`, `LeafDaysRemaining`, `LeafSerial`, `LeafSignatureAlgorithm`, `LeafKeyType`, `LeafKeySize`
- **TLSOptions Struct**: Bundled parameters for TLS probe function replacing positional arguments
- **Granular Exit Codes**: Added `ExitConfigError` (4), `ExitPartialSuccess` (5), `ExitCancelled` (130)
- **Result Order Preservation**: Worker pool maintains input target order in output results
- **Live Integration Tests**: `TestLiveOCSPRevocation`, `TestLiveOCSPRevocationViaAIA`, `TestLiveLeafCertificateFields`, `TestLiveSCTPresence`
- **Security Tests**: Path traversal prevention tests for `ExportCertificates`, `LoadTruststore`, `LoadClientKeypair`

### Security
- **Path Traversal Prevention**: `sanitizePath()` in certs.go validates file paths against directory escape
- **ExportCertificates Hardening**: Prefix path sanitization and hostname sanitization (replaces `/`, `\`, `..`)
- **HTTP Response Size Limits**: `io.LimitReader` for OCSP (1MB) and AIA issuer (10MB) responses
- **TLS 1.2 Minimum**: OCSP/AIA HTTP clients enforce TLS 1.2+ for secure fetching

### Changed
- **OCSP Client Reuse**: `newSecureHTTPClient()` factory for consistent HTTP client configuration
- **Context-Aware Retry Delay**: TCP retry uses `time.After` with select for cancellation support
- **Channel Buffer Bounds**: `maxChannelBuffer` (10000) prevents OOM on large target lists
- **Error Message Casing**: Standardized lowercase error messages per Go conventions
- **CSV Error Handling**: `reporter.CSV()` now returns write errors instead of discarding them

### Fixed
- **Blocking Sleep**: Retry delay now respects context cancellation
- **JSON Exit Code**: JSON serialization errors now affect exit code
- **Ineffectual Assignment**: Removed unused `port` variable in TLS cert check

### Documentation
- Updated module path to `github.com/edsilegxrepo/tlstester`
- Comprehensive inline documentation for all packages
- Updated README.md, ARCHITECTURE.md, DESIGN.md, TESTING.md

## [1.0.1] - 2026-08-03

### Changed
- Module path migrated from `criticalsys.net/tlstester` to `github.com/edsilegxrepo/tlstester`

## [1.0.0] - 2026-07-25

### Added
- **Core Orchestration Engine**: `RunDiagnostics()`, `ExecuteTarget()`, `CreateTLSConfig()`
- **Target Parsing**: Multi-source ingestion (hostport, endpoints, URLs, files, Cartesian grid)
- **TCP Probing**: `probes.TCP()` with DNS resolution, retry logic, latency measurement
- **TLS Handshake**: `probes.TLS()` with cipher negotiation, ALPN, peer certificate extraction
- **HTTP Probing**: `probes.HTTP()` with custom headers, status assertions, Alt-Svc extraction
- **OCSP Checking**: `probes.CheckActiveOCSP()` for AIA OCSP responder reachability
- **Protocol Scanning**: `probes.ScanCipherSuites()`, `probes.TestSessionResumption()`, `probes.CheckQUIC()`
- **Certificate Management**: `certs.LoadTruststore()`, `certs.LoadClientKeypair()`, `certs.DaysUntilExpiration()`
- **Reporting**: `reporter.Dashboard()`, `reporter.JSON()`, `reporter.CSV()`
- **Security Diagnostics**: `GetSecurityEnvironment()`, `DumpDiagnostics()`
- **Proxy Support**: HTTP CONNECT and SOCKS5 proxy tunneling
- **mTLS Support**: Client certificate authentication via `-keystore`
- **Custom Truststore**: Merge custom CAs with system pool via `-truststore`
- **Certificate Export**: PEM file export via `-export-cert`
- **Expiration Warnings**: `-warn-days` threshold alerts
- **SNI Controls**: `-sni` override, `-no-sni` suppression
- **CLI Flags**: Complete flag set for all features
- **Live Integration Tests**: `TestLiveFullAppCapabilities`, `TestLiveStandaloneProbesDirect`
- **Mock Unit Tests**: Sub-second in-memory test suite

### Security
- Zero external dependencies (Go standard library only + golang.org/x/crypto/ocsp)
- TLS 1.2 minimum by default
- InsecureSkipVerify requires explicit `-insecure` flag
- Non-root operation with user-space sockets

## [0.x] - Pre-release Development

### Added
- Initial project structure and module setup
- Basic TLS connection testing functionality
- README.md and SECURITY.md documentation
- Dependabot configuration
- Code linting and formatting

[1.1.0]: https://github.com/edsilegxrepo/tlstester/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/edsilegxrepo/tlstester/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/edsilegxrepo/tlstester/releases/tag/v1.0.0
