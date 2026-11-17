# Changelog

## 0.1.0

- Initial local, read-only static security scanner.
- Add checks for credential-like assignments, selected XSS patterns, SQL and shell construction, path operations, SSRF markers, CORS, deserialization, TLS verification, debug settings, and selected cryptographic patterns.
- Add text and JSON reports with severity, CWE, confidence, evidence, impact, and remediation fields.
- Redact credential-like values in report evidence.
- Skip common generated directories, binary files, oversized files, and symbolic links.
- Add unit tests and GitHub Actions CI.
