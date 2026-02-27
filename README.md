# The Janitor: Structural Firewall for AI-Generated Code
**v6.8.0 — Rust-Native. Zero-Copy. Enforcement at the Gate.**

🎥 **[Watch the 60-Second Terminal Demo →](https://thejanitor.app)**

---

> **Sonar finds style violations.**
> **The Janitor enforces structural integrity.**

> *82% of open Godot Engine pull requests contain no issue link. 20% introduce language antipatterns. Zero comment scanners caught it. The Janitor did — across 50 live PRs, in under 90 seconds.*

---

## The Problem

The Veracode 2025 State of Software Security report established the baseline: AI-assisted code contains **36% more high-severity vulnerabilities** than human-written equivalents. Your linter passes Copilot output. Your SAST tool uploads it to a cloud pipeline. By the time the report arrives, the PR is merged.

The threat model has changed. Your enforcement layer has not.

## The Enforcement Layer

The Janitor is not a linter. It is a **structural firewall** that runs on your hardware, on every pull request — before the merge button is available.

### Zero-Copy Execution

Every analysis executes via **memory-mapped file access**. Source code is never copied to heap, never serialized, never transmitted. No network call is made during the dead-symbol pipeline.

**Benchmark:** 3.5 million lines of Godot Engine — **33 seconds, 58 MB peak RAM.** On a standard CI runner. Zero panics.

### Zombie Dependency Detection

AI generators hallucinate package imports. The Janitor scans `package.json`, `Cargo.toml`, `requirements.txt`, `spin.toml`, and `wrangler.toml` against the live symbol reference graph. A package that appears in your manifest but never appears in a reachable import path is a zombie dependency — flagged before merge.

### Cryptographic Integrity Bonds

Every cleanup is sealed with an Ed25519 attestation covering `{timestamp}{file_path}{sha256_pre_cleanup}`. The verifying key (32 bytes) is embedded in the binary. Verification is a pure offline computation — a chain of custody for every line of code removed from production.

---

## PR Gate: Live Results

```
PRs analyzed (Godot Engine, Feb 2026) : 50
Unlinked PRs                           : 41  (82%)
Antipatterns flagged                   : 10
AI comment violations                  : 0
Highest slop score                     : 70  (PR #116833)
```

---

## How It Works

1. **Scan** — Static reference graph + 6-stage heuristic pipeline identifies every dead symbol.
2. **Simulate** — Shadow Tree overlays links to dead files. Your test suite runs against simulated deletion.
3. **Remove** — Tests pass? Byte-precise surgical removal, bottom-to-top. Tests fail? Full rollback, zero corruption.

## Quick Start

```bash
# Detect dead code (free)
janitor scan ./src

# Find duplicate functions (free)
janitor dedup ./src

# PR enforcement gate — score a diff (free)
janitor bounce ./src --patch diff.patch

# Shadow-simulate + remove dead code (free)
janitor clean ./src --force-purge

# Cleanup with cryptographic chain of custody (Team tier)
janitor clean ./src --force-purge --token $JANITOR_TOKEN
```

## Language Support

| Language | Dead Functions | Dead Classes | Dead Files | Duplicate Logic |
|----------|:---:|:---:|:---:|:---:|
| Python | ✓ | ✓ | ✓ | ✓ |
| Rust | ✓ | ✓ | ✓ | — |
| JavaScript / TypeScript | ✓ | ✓ | ✓ | — |
| C++ | ✓ | ✓ | ✓ | — |
| Go | ✓ | ✓ | ✓ | — |
| C# / Java | ✓ | ✓ | ✓ | — |

## Runtime Architecture

| Subsystem | Technology | Property |
|-----------|-----------|---------|
| **AST Engine** | Tree-sitter (9 grammars) | O(n) CST construction; byte-range precision per token |
| **Reference Graph** | Petgraph directed digraph | Topological dead-symbol filter; in-degree = 0 → candidate |
| **Pattern Matching** | Aho-Corasick (single automaton per group) | O(n+m) multi-pattern scan; zero allocation in hot path |
| **Registry Persistence** | rkyv + memmap2 | mmap-direct deserialization; no heap allocation for reads |
| **Structural Hashing** | BLAKE3 (alpha-normalized AST) | Logic-clone detection across identifier rename boundaries |
| **Fuzzy Dedup** | AstSimHasher (SimHash over CST tokens) | Classified as `Refactor`, `Zombie`, or `NewCode` |
| **PR Quality Gate** | MinHash LSH (64 hashes, 8-band index) | Lock-free ArcSwap index; sub-linear collision detection |
| **Deletion Engine** | Bottom-to-top byte-range splice | UTF-8 char-boundary hardened; zero re-parse overhead |
| **Simulation Layer** | Symlink overlay (Shadow Tree) | Zero additional disk usage; tests run against simulated state |
| **Audit Attestation** | Ed25519 remote signing | Binary carries only `VERIFYING_KEY_BYTES`; no private key embedded |

## Pricing

**The enforcement is free. The attestation is the product.**

| Tier | Cost | What You Get |
|:-----|:-----|:-------------|
| **Free** | $0 | Unlimited scan, clean, dedup, bounce, dashboard, report. No signed logs. |
| **[Team](INSERT_REAL_LEMONSQUEEZY_LINK_HERE)** | **$499/yr** | All free features + Ed25519 Integrity Bonds + CI/CD Compliance Attestation + The Governor GitHub App. Up to 25 seats. |
| **[Industrial](INSERT_REAL_LEMONSQUEEZY_LINK_HERE)** | **Custom** | On-Premises Token Server + Keypair Rotation Protocol + SOC 2 Audit Support + Enterprise SLA. Unlimited seats. |

[**Activate Attestation → thejanitor.lemonsqueezy.com**](INSERT_REAL_LEMONSQUEEZY_LINK_HERE)

## CI Integration

```yaml
# Structural scan on every PR (free)
- uses: GhrammR/the-janitor@v6
  with:
    path: ./src
    args: scan --format json

# PR enforcement gate (free)
- uses: GhrammR/the-janitor@v6
  with:
    args: bounce ./src --patch ${{ github.event.pull_request.diff_url }}

# Signed attestation (Team tier)
- uses: GhrammR/the-janitor@v6
  with:
    args: clean --force-purge --token ${{ secrets.JANITOR_TOKEN }}
    path: ./src
```

## Commands

```sh
# Structural dead symbol audit
janitor scan <path> [--library] [--format json]

# PR enforcement gate
janitor bounce <path> --patch <file> --pr-number <n> --author <handle> --pr-body "$BODY"

# Zombie dependency detection (output includes zombie_deps)
janitor scan <path> --format json

# Structural clone detection
janitor dedup <path>

# Shadow-simulate → test → remove dead code
janitor clean <path> --force-purge [--token <attestation-token>]

# Historical slop / clone / zombie intelligence report
janitor report [--repo <path>] [--top <n>] [--format markdown|json]

# Long-lived daemon (Unix socket, Physarum backpressure)
janitor serve [--socket <path>] [--registry <file>]

# Ratatui TUI dashboard
janitor dashboard <path>
```

## Installation

**From source (Rust 1.82+, `just` required):**

```sh
git clone https://github.com/GhrammR/the-janitor
cd the-janitor
just build
# Binary: target/release/janitor
```

**Pre-built binary:**

```sh
# Download from Releases, then:
chmod +x janitor && sudo mv janitor /usr/local/bin/
```

## The Proof

> **3.5 million lines. 33 seconds. 58 megabytes. Zero panics.**
>
> [Read the Godot Engine Autopsy →](https://thejanitor.app/case-studies/godot/)

## License

**Business Source License 1.1 (BUSL-1.1)** — Source Available. Converts to MIT on 2030-02-15.

Scan, cleanup, dedup, bounce, and dashboard are permanently free. Integrity attestation requires a [Team token](INSERT_REAL_LEMONSQUEEZY_LINK_HERE).
