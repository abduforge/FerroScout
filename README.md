<p align="center">
  <img src="docs/assets/ferroscout-mark.svg" width="132" alt="FerroScout logo">
</p>

<h1 align="center">FerroScout</h1>

<p align="center">
  <strong>Find risky patterns. Keep the evidence. Review the fix.</strong><br>
  A local-first static security scanner written in Rust.
</p>

<p align="center">
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml/badge.svg" alt="Rust CI"></a>
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml/badge.svg" alt="Code scanning"></a>
  <a href="https://github.com/abduforge/FerroScout/releases"><img src="https://img.shields.io/github/v/release/abduforge/FerroScout?display_name=tag&sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/abduforge/FerroScout" alt="MIT license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-stable-orange?logo=rust" alt="Stable Rust"></a>
  <a href="https://github.com/abduforge/FerroScout/issues"><img src="https://img.shields.io/github/issues/abduforge/FerroScout" alt="Open issues"></a>
</p>

<p align="center">
  <a href="README_RU.md">Русская версия</a> ·
  <a href="https://github.com/abduforge/FerroScout/releases">Releases</a> ·
  <a href="https://github.com/abduforge/FerroScout/discussions">Discussions</a>
</p>

---

FerroScout scans source code and configuration files for security-sensitive patterns. Findings include a rule ID, severity, confidence, file location, evidence, potential impact, and a remediation suggestion.

The scanner runs locally and reads files without executing them. It does not contact remote services. Reports can be printed as text, Markdown, JSON, or SARIF 2.1.0. A bounded data-flow pass follows simple assignments and named relative ES-module imports to selected sensitive sinks.

> **Scope:** FerroScout is a small heuristic scanner, not a full language-aware SAST engine. A match is a lead for manual review, not proof of exploitability. A clean scan is not a security guarantee.

## At a glance

| | |
|---|---|
| Language | Rust, edition 2021 |
| Platform | Linux |
| Operation | Local, passive, read-only |
| Reports | Text · Markdown · JSON · SARIF 2.1.0 |
| Baselines | Hide previously reviewed findings; surface new findings |
| Built-in rule groups | 11 |
| Data-flow | Same-file aliases and named relative ES-module imports (bounded heuristic) |
| License | MIT |

## Get started

### Build from source

Install stable Rust, then run:

```bash
git clone https://github.com/abduforge/FerroScout.git
cd FerroScout
cargo generate-lockfile
cargo build --release --locked
```

The binary is `target/release/ferroscout`.

### Download a release

Linux x86_64 archives and SHA-256 checksums are published on the [Releases page](https://github.com/abduforge/FerroScout/releases). Verify the downloaded archive before extracting it:

```bash
sha256sum -c ferroscout-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ferroscout-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
install -Dm755 ferroscout/ferroscout ~/.local/bin/ferroscout
```

Make sure `~/.local/bin` is in your `PATH`.

## Usage

```bash
# Scan a project directory
ferroscout scan ./project

# Scan one file
ferroscout scan ./src/main.rs

# Save a Markdown report
ferroscout scan ./project --format markdown > ferroscout-report.md

# Produce JSON or SARIF
ferroscout scan ./project --format json > ferroscout-report.json
ferroscout scan ./project --format sarif > ferroscout.sarif

# Keep Medium and High findings
ferroscout scan ./project --severity medium

# Exclude a known noisy rule (repeatable)
ferroscout scan ./project --exclude-rule FS-TLS-001

# Exclude generated or fixture directories
ferroscout scan ./project --exclude target --exclude fixtures

# Set the per-file size limit (bytes; maximum 16 MiB)
ferroscout scan ./project --max-file-size 1048576

# List the rules included in this build
ferroscout rules

# Record currently known findings
ferroscout baseline create ./project --output .ferroscout-baseline.json

# Show only findings that are new since the baseline
ferroscout scan ./project --baseline .ferroscout-baseline.json

# Refresh after reviewing/fixing findings (replaces the baseline)
ferroscout baseline create ./project --output .ferroscout-baseline.json --force
```

Use `ferroscout --help` for the complete CLI reference.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | No findings passed the selected filters and the scan had sufficient context |
| `1` | One or more findings were reported |
| `2` | Scan error or insufficient context |

This makes FerroScout usable in scripts and CI. A workflow decides whether a finding should fail a build.

## Managing known exceptions

A finding can be suppressed for the next line with a source comment. The directive must name a rule and include a reason:

```python
# ferroscout:ignore-next-line FS-TLS-001 -- local test server uses a test certificate
requests.get(url, verify=False)
```

JavaScript and Rust comments use the same directive:

```javascript
// ferroscout:ignore-next-line FS-XSS-001 -- value is sanitized by the wrapper above
container.innerHTML = sanitizedValue
```

FerroScout accepts full-line comments starting with `//`, `#`, `/*`, `<!--`, or SQL `--`. It does not accept an empty reason, an unknown rule ID, or a directive embedded inside a string. Use `*` only when the same documented exception genuinely applies to every rule on the next line.

The report shows how many findings were suppressed by source comments. Command-line filters are counted separately. Suppression does not change the source file.

## Built-in checks

| Rule | Area | Looks for |
|---|---|---|
| `FS-SECRET-001` | Secrets | Credential-like assignments, bearer tokens, and private-key markers |
| `FS-XSS-001` | XSS | Untrusted-input markers near dynamic HTML sinks |
| `FS-INJECT-001` | Injection | Dynamic SQL construction and selected shell-command patterns |
| `FS-PATH-001` | Path traversal | Untrusted-input markers near filesystem operations |
| `FS-SSRF-001` | SSRF | User-controlled values near server-side request calls |
| `FS-CORS-001` | CORS | Reflected origins in configurations that also enable credentials |
| `FS-DESER-001` | Deserialization | Selected unsafe deserialization APIs |
| `FS-TLS-001` | TLS | Explicitly disabled certificate verification |
| `FS-DEBUG-001` | Debug | Common debug-mode settings |
| `FS-CRYPTO-001` | Cryptography | Selected weak password-hash and security-sensitive randomness patterns |
| `FS-TAINT-001` | Data flow | Request-derived values that reach selected HTML, SQL, shell, file-path, or HTTP sinks through simple assignments or named relative ES-module imports |

Most checks remain conservative and pattern-based. `FS-TAINT-001` adds a bounded data-flow pass: it follows simple variable assignments and named relative ES-module imports (`import { value } from "./module"`) across scanned files. The pass is limited to 10,000 files, 50,000 recorded facts, and at most 64 module-propagation rounds. It does not parse complete language syntax, follow function calls, resolve framework sanitizers beyond a few known HTML sanitizers, or prove exploitability.

The taint pass also removes ordinary string contents, single-line comments, and block comments before matching source/sink markers, follows simple variables inside JavaScript template literals and Python f-strings, and avoids treating a partially sanitized expression as fully safe. Sanitizer recognition is deliberately narrow and does not replace a context-aware review.

## Finding baselines

Create a baseline after reviewing the findings that are already known:

```bash
ferroscout baseline create ./project --output .ferroscout-baseline.json
```

Then pass it to later scans to keep those existing findings out of the report:

```bash
ferroscout scan ./project --baseline .ferroscout-baseline.json
```

Fingerprints use the rule ID, path relative to the scan target, and redacted evidence. Line numbers are intentionally excluded, so inserting lines above a finding does not make it new. Repeated identical findings are counted separately. The baseline contains fingerprints and review metadata, not source evidence or absolute scan-root paths. Review a baseline before sharing or committing it. To replace an existing baseline after reviewing the updated findings, use `baseline create ... --force`. Baselines are a triage aid, not a security guarantee.

## GitHub Code Scanning

FerroScout can emit SARIF 2.1.0:

```bash
ferroscout scan . --format sarif > ferroscout.sarif
```

The optional `.github/workflows/code-scanning.yml` workflow builds the scanner, creates a SARIF report, and uploads it to GitHub Code Scanning. The workflow excludes `tests` and `src/rules`, which contain synthetic fixtures and rule implementation patterns. Review the workflow before enabling it for sensitive repositories: SARIF contains paths, line numbers, and redacted evidence excerpts.

## Privacy and file handling

- The CLI reads files locally and does not make network requests.
- It does not run scanned programs, scripts, shell commands, or build steps.
- It does not modify or delete scanned files.
- It skips symbolic links during directory traversal and rejects a symbolic link as the scan target.
- It skips binary files and files over the configured size limit (2 MiB by default; 16 MiB maximum).
- It recognizes common source and configuration extensions, plus selected files such as `.env`, `Dockerfile`, `.http`, and `.har`.
- It skips common generated directories by default, including `.git`, `target`, `node_modules`, `vendor`, `dist`, and virtual environments.
- Credential-like values are redacted in evidence. Redaction is heuristic; do not commit secrets.

## Limitations

FerroScout uses regular expressions, nearby-line context, and a bounded assignment/import data-flow pass. It does not perform complete AST analysis, interprocedural function analysis, general-purpose cross-language taint analysis, framework-aware configuration resolution, dynamic testing, or authorization analysis. It does not claim reliable IDOR detection. A rule match needs context, and no match does not establish that code is safe.

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Use synthetic fixtures only. Never add real passwords, tokens, private keys, or user data to tests. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Project files

- [Data-flow analysis details](docs/TAINT_ANALYSIS.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Report a bug](https://github.com/abduforge/FerroScout/issues/new/choose)
- [Discussions](https://github.com/abduforge/FerroScout/discussions)

## License

MIT. See [LICENSE](LICENSE).
