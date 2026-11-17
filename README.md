<p align="center">
  <img src="docs/assets/ferroscout-mark.svg" width="132" alt="FerroScout logo">
</p>

<h1 align="center">FerroScout</h1>

<p align="center">
  <strong>Find risky patterns. See the evidence. Fix the root cause.</strong><br>
  A local-first static security scanner written in Rust.
</p>

<p align="center">
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml/badge.svg" alt="Rust CI"></a>
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml/badge.svg" alt="FerroScout Code Scanning"></a>
  <a href="https://github.com/abduforge/FerroScout/releases"><img src="https://img.shields.io/github/v/release/abduforge/FerroScout?display_name=tag&sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/abduforge/FerroScout" alt="MIT license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust" alt="Rust 1.70 or newer"></a>
  <a href="https://github.com/abduforge/FerroScout/issues"><img src="https://img.shields.io/github/issues/abduforge/FerroScout" alt="Open issues"></a>
</p>

<p align="center">
  <a href="README_RU.md">Русская версия</a> ·
  <a href="https://github.com/abduforge/FerroScout/releases">Releases</a> ·
  <a href="https://github.com/abduforge/FerroScout/issues">Issues</a>
</p>

---

FerroScout walks through source and configuration files, checks them against a small set of security rules, and prints findings with file locations, evidence, confidence, and remediation notes. It can also export **SARIF 2.1.0** for GitHub code scanning workflows.

It is deliberately local and passive: scanned programs are never executed and files are never changed. The CLI itself makes no network requests. The optional GitHub Actions workflow uploads a SARIF findings report (including paths, line numbers, and sanitized evidence excerpts) to GitHub Code Scanning.

> **A note on accuracy:** FerroScout 0.2.0 is a rule-based review aid, not a full language-aware SAST engine. It does not prove exploitability or understand every cross-file data flow. Treat findings as leads for a human review. A clean scan is not a security guarantee.

## At a glance

| | |
|---|---|
| **Language** | Rust (stable, edition 2021) |
| **Platform** | Linux |
| **Analysis** | Local, static, read-only |
| **Reports** | Human-readable text, JSON, SARIF 2.1.0 |
| **Rules** | 10 rule groups |
| **License** | MIT |

## Quick start

### Build from source

Install a stable Rust toolchain, then:

```bash
git clone https://github.com/abduforge/FerroScout.git
cd FerroScout
cargo generate-lockfile
cargo build --release
```

The binary will be at `target/release/ferroscout`.

### Install a release binary

Linux x86_64 archives and SHA-256 checksums are published on the [Releases page](https://github.com/abduforge/FerroScout/releases). Download the matching `.tar.gz` and `.sha256` files, then:

```bash
sha256sum -c ferroscout-v0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ferroscout-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
install -Dm755 ferroscout/ferroscout ~/.local/bin/ferroscout
```

### First scan

```bash
./target/release/ferroscout scan ./path/to/project
```

To make the binary available from your shell, copy it into a directory on your `PATH`:

```bash
install -Dm755 target/release/ferroscout ~/.local/bin/ferroscout
```

## Usage

```bash
# Scan a project directory
ferroscout scan ./project

# Scan one file
ferroscout scan ./src/main.rs

# Machine-readable JSON
ferroscout scan ./project --format json

# GitHub Code Scanning-compatible SARIF
ferroscout scan ./project --format sarif > ferroscout.sarif

# Keep Medium and High severity findings
ferroscout scan ./project --severity medium

# Exclude generated or test data (repeat the option as needed)
ferroscout scan ./project --exclude target --exclude fixtures

# Set a per-file limit in bytes (maximum: 16 MiB)
ferroscout scan ./project --max-file-size 1048576

# List the rules included in this build
ferroscout rules
```

Run `ferroscout --help` for the complete command reference.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | No selected findings; scan had sufficient context |
| `1` | One or more findings were reported |
| `2` | Scan error or insufficient context |

This makes FerroScout usable in scripts and CI. A finding is not automatically a CI failure unless your workflow chooses to treat exit code `1` as one.

## Security checks

| Rule | Area | What the rule looks for |
|---|---|---|
| `FS-SECRET-001` | Secrets | Credential-like assignments, bearer tokens, and private-key markers |
| `FS-XSS-001` | XSS | A known untrusted-input marker close to a dynamic HTML sink |
| `FS-INJECT-001` | Injection | Dynamic SQL construction and selected shell execution patterns |
| `FS-PATH-001` | Path traversal | Untrusted-input markers near filesystem operations |
| `FS-SSRF-001` | SSRF | User-controlled values near server-side request calls |
| `FS-CORS-001` | CORS | Reflected origins in a file that also enables credentials |
| `FS-DESER-001` | Deserialization | Selected unsafe deserialization APIs |
| `FS-TLS-001` | TLS | Explicitly disabled certificate verification |
| `FS-DEBUG-001` | Debug exposure | Common debug-mode settings |
| `FS-CRYPTO-001` | Cryptography | Selected weak password-hash and security-sensitive randomness patterns |

### What a finding contains

Each result includes a rule ID, severity, confidence, file path, line number, evidence excerpt, explanation, potential impact, and a remediation suggestion. Credential-like values are redacted in evidence output.

The rules are intentionally conservative and line-oriented. For example, an `innerHTML` assignment alone is not enough to establish XSS; the current XSS rule also looks for a nearby untrusted-input marker and a lack of a nearby sanitizer marker. This is still a heuristic, not full taint analysis.

## GitHub Code Scanning (SARIF)

FerroScout can write SARIF 2.1.0:

```bash
ferroscout scan . --format sarif > ferroscout.sarif
```

The repository includes a workflow at `.github/workflows/code-scanning.yml` that runs FerroScout on pushes to `main` and uploads its SARIF report to GitHub Code Scanning. Repository code-scanning features must be available/enabled for the upload to appear in the **Security** tab. The workflow excludes `tests` and `src/rules` because those directories intentionally contain synthetic vulnerable examples used to test the detector.

You can also upload SARIF from your own workflow using `github/codeql-action/upload-sarif` and grant the job `security-events: write` permission.

## Scope and privacy

- Reads files on the local machine; the CLI itself makes no network requests.
- The optional Code Scanning workflow uploads SARIF findings to GitHub. SARIF contains paths, line numbers, and evidence excerpts; secret redaction is heuristic, not a guarantee. Review the workflow before using it on sensitive repositories.
- Never executes scanned programs, scripts, shell commands, or build steps.
- Does not modify or delete scanned files.
- Skips symbolic links during directory traversal and rejects a symbolic link as the scan target.
- Skips binary files and files larger than the configured limit (2 MiB by default; hard maximum 16 MiB).
- Scans common source and configuration extensions, plus selected files such as `.env`, `Dockerfile`, `.http`, and `.har`.
- Excludes common generated directories by default, including `.git`, `target`, `node_modules`, `vendor`, `dist`, and virtual environments.
- Redacts credential-like values in finding evidence. Do not use this as a reason to commit secrets.

## Limitations

FerroScout 0.2.0 uses regular expressions and nearby-line context. It does not build complete ASTs, perform interprocedural or cross-file taint analysis, resolve framework configuration, contact services, or verify authorization behavior. It therefore does not claim reliable IDOR detection. A rule match needs context, and the absence of a match does not establish that code is safe.

## Development

```bash
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Use synthetic fixtures only. Never put real passwords, access tokens, private keys, or customer data in tests or examples. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Project links

- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Report a bug](https://github.com/abduforge/FerroScout/issues/new/choose)
- [Releases](https://github.com/abduforge/FerroScout/releases)

## License

MIT. See [LICENSE](LICENSE).
