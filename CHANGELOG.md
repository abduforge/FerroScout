# Changelog

## 0.3.0 - 2026-11-18

- Add Markdown report output for sharing scan results in pull requests and issue discussions.
- Add exact `--exclude-rule` filtering with validation against the built-in rule catalog.
- Add reason-required `ferroscout:ignore-next-line` source-comment suppressions.
- Restrict suppression directives to full-line comments so matching text inside string literals does not hide findings.
- Show source-suppressed and command-line-filtered finding counts in text, JSON, and SARIF reports.
- Add tests for Markdown escaping, suppression reasons, string-literal handling, and CLI rule filtering.
- Update English and Russian documentation and command examples.

## 0.2.0 - 2026-11-17

- Add SARIF 2.1.0 output for integration with GitHub Code Scanning.
- Add a repository scanning workflow that uploads SARIF results on pushes to `main`.
- Refresh the English and Russian README with command examples, rule descriptions, limitations, privacy notes, and release badges.
- Add a project logo and repository contribution files.
- Add issue forms, a pull request template, CODEOWNERS, and release-note categories.
- Add Dependabot updates for Cargo dependencies and GitHub Actions.
- Add a release workflow that packages the Linux x86_64 binary with a SHA-256 checksum.
- Keep the scanner local, passive, and read-only.

## 0.1.0

- Initial local, read-only static security scanner.
- Add checks for credential-like assignments, selected XSS patterns, SQL and shell construction, path operations, SSRF markers, CORS, deserialization, TLS verification, debug settings, and selected cryptographic patterns.
- Add text and JSON reports with severity, CWE, confidence, evidence, impact, and remediation fields.
- Redact credential-like values in report evidence.
- Skip common generated directories, binary files, oversized files, and symbolic links.
- Add unit tests and GitHub Actions CI.
