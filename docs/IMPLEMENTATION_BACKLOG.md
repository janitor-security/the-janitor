# Implementation Backlog

Append-only session ledger for implementation directives and deferred follow-up.

## 2026-04-13 — Dual-Model Consensus & Deep Eradication Strike

- Initialized this ledger because the prior tracked backlog path had been renamed away during the GA transition.
- Removed verified-dead direct dependencies from `common`, `anatomist`, and `cli`; pruned stale RC-era scripts and patch artifacts.
- Verified the semantic-depth gap: no production end-to-end cross-file taint spine is proven in the audited runtime path.
- Added roadmap pressure in `.INNOVATION_LOG.md` for semantic-depth disclosure, true taint export completion, Wasm capability receipts, and SCM review-thread parity.
- Verified `cargo test --workspace -- --test-threads=1` and `just audit` pass before the `10.1.1` release attempt.
