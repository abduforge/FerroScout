## What changed?

Describe the change and the reason for it.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --all-targets --locked`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `cargo build --release --locked`

## Security and compatibility

- [ ] No real credentials or private data were added.
- [ ] Scanned files are still read-only; no scanned code is executed.
- [ ] New rules include positive and negative tests.
- [ ] Documentation and CLI examples match the implementation.

## Notes for reviewers

Add context, trade-offs, or known limitations.
