# Contributing

Thanks for taking an interest in FerroScout. Focused fixes and small, well-tested rules are easier to review than large rewrites.

## Before opening an issue

- Search existing issues first.
- For a suspected security problem in FerroScout, follow [SECURITY.md](SECURITY.md) instead of posting sensitive details publicly.
- Never attach real credentials, private keys, customer data, or confidential source code. Use synthetic examples.

## Development setup

Install stable Rust, clone the repository, and generate the dependency lockfile:

```bash
git clone https://github.com/abduforge/FerroScout.git
cd FerroScout
cargo generate-lockfile
```

Before submitting a change, run:

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

## Adding or changing a rule

- Give the rule a stable `FS-...` identifier.
- Include at least one positive test and one negative test.
- Prefer evidence-backed patterns over broad keyword matches.
- Do not report a sink as exploitable without a credible source-to-sink relationship.
- Redact secret-like values in evidence.
- Document what the rule cannot infer.

## Pull requests

Keep each PR focused. Explain the user-visible change, how you tested it, and any known limitations. Update both README files when command-line behavior changes.

FerroScout is a heuristic static analyzer. Contributions must not make it claim that a pattern match proves exploitability or that a clean scan proves security.
