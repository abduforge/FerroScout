# FerroScout

FerroScout is a small local static security scanner written in Rust. It checks source and configuration files for a handful of security-sensitive patterns and prints findings with file names, line numbers, evidence, and remediation ideas.

This is an early rule-based tool. It does not build full language syntax trees or prove exploitability. Treat its findings as review leads, not confirmed vulnerabilities. A clean scan is not a security guarantee.

## Build

Install a stable Rust toolchain, then run:

```bash
cargo generate-lockfile
cargo fmt --all
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

The binary is created at `target/release/ferroscout`. You can also run it directly from the source directory with `cargo run -- scan ./project`.

## Usage

```bash
# Scan a directory
ferroscout scan ./project

# Scan one file
ferroscout scan ./src/main.rs

# Emit JSON
ferroscout scan ./project --format json

# Show medium and high findings only
ferroscout scan ./project --severity medium

# Exclude additional directories or relative paths
ferroscout scan ./project --exclude fixtures --exclude generated

# Change the per-file size limit (bytes)
ferroscout scan ./project --max-file-size 1048576

# List implemented rules
ferroscout rules
```

The command exits with status `0` when no findings were selected and the scan had sufficient context, `1` when findings are reported, and `2` when the scan could not be completed or there was insufficient context.

## Initial checks

| Rule | What it looks for | Important limitation |
|---|---|---|
| `FS-SECRET-001` | Credential-like assignments and PEM private-key markers | Placeholder filtering is simple; review whether a value is real |
| `FS-XSS-001` | A known untrusted-input marker near a dynamic HTML sink | Checks only a short line window; does not perform full taint analysis |
| `FS-INJECT-001` | Dynamic SQL construction and selected shell execution patterns | Requires manual review of parameter binding and input validation |
| `FS-PATH-001` | User-controlled markers near filesystem operations | Does not resolve path semantics or prove missing containment checks |
| `FS-SSRF-001` | User-controlled markers near server-side HTTP request calls | Does not resolve destinations, redirects, DNS, or network policy |
| `FS-CORS-001` | Reflected origins in a file that also enables credentials | Framework behavior and deployed configuration need review |
| `FS-DESER-001` | Selected unsafe deserialization APIs | Does not determine whether input is attacker-controlled |
| `FS-TLS-001` | Explicitly disabled TLS certificate verification | Test-only configuration may be intentional; verify deployment use |
| `FS-DEBUG-001` | Common debug-mode settings | Does not establish that the setting is used in production |
| `FS-CRYPTO-001` | Some weak password-hash and random-token patterns | Does not infer the purpose of every hash or random value |

The first version uses conservative line-oriented patterns, not language-specific parsers. It may miss multi-line data flows and can report patterns that are safe in their wider context. No IDOR rule is included because reliable IDOR detection requires understanding resource ownership and authorization logic across routes and data access layers.

## Scan behavior and privacy

- Reads files locally and does not make network requests.
- Does not execute scanned programs, shell commands, scripts, or build steps.
- Does not modify or delete scanned files.
- Does not follow symbolic links found during directory traversal; a symbolic-link scan target is rejected.
- Skips binary files and files larger than the configured limit (2 MiB by default).
- Scans common source/configuration extensions and a few well-known files such as `.env`, `.env.*`, and `Dockerfile`. It also recognizes common `.lock`, `.http`, `.har`, and `.txt` files.
- Excludes `.git`, `target`, `node_modules`, `vendor`, `dist`, `build`, virtual environments, and Python cache directories by default.
- Redacts credential-like values in evidence output. Do not treat redaction as a substitute for keeping secrets out of source control.

## Output status

JSON reports include one of these statuses:

- `FINDINGS_FOUND`: one or more findings passed the selected severity filter.
- `NO_ISSUES_FOUND`: at least one supported file was scanned, no scan errors occurred, and no findings passed the selected filter.
- `INSUFFICIENT_CONTEXT`: no supported files were scanned or one or more scan errors prevented a complete review.

`NO_ISSUES_FOUND` means only that the implemented checks did not identify a finding in the scanned scope. It does not mean the application is secure.

## Development

```bash
cargo fmt --all
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Use synthetic test fixtures. Never add real credentials or private keys to tests or examples.

## License

MIT. See [LICENSE](LICENSE).
