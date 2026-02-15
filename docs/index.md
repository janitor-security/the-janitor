# The Janitor

**v5.4.0-GOLD — Rust-Native. Zero-Copy. Link-Time Excision.**

*"Code is Liability. Sovereignty is Metabolic."*

---

## I. THE DIAGNOSIS: METABOLIC BLOAT

Every codebase accumulates dead weight. Functions that were called once, classes that were subclassed by a deleted module, utilities from a refactoring that never shipped. Traditional linters flag style violations. They do not detect entropy.

The consequence is **Metabolic Bloat**: dead symbols that occupy binary space, extend build times, inflate cognitive load, and survive code review because no tool has the reference resolution to prove they are unreachable.

---

## II. THE CURE: THE SOVEREIGN STACK

The Janitor is not a linter. It is a fiduciary agent.

### The Anatomist

Parses Python source via Tree-sitter CST. Extracts every `def`, `class`, and top-level symbol as a zero-copy `Entity` with byte ranges, qualified names, decorator lists, and structural hashes. Builds a directed reference graph resolving imports, attribute calls, and `__all__` exports.

### The 6-Stage Dead Symbol Pipeline

| Stage | Filter | Guard |
|-------|--------|-------|
| 0 | Directory exclusion (`tests/`, `migrations/`, `venv/`) | `Protection::Directory` |
| 1 | Reference graph: in-degree > 0 | `Protection::Referenced` |
| 2+4 | Heuristic wisdom + `__all__` exports | Various |
| 3 | Library mode: all public symbols | `Protection::LibraryMode` |
| 5 | Aho-Corasick scan of non-`.py` files | `Protection::GrepShield` |

Anything that survives all five gates is a confirmed dead symbol.

### The Reaper

Executes surgical byte-range deletion. Sorts targets **descending by `start_byte`** (bottom-to-top splice) to preserve upstream offsets. UTF-8 hardened via `str::is_char_boundary()`. Atomic backup to `.janitor/ghost/` before first write.

### The Forge

Alpha-normalized BLAKE3 structural hashing detects duplicate functions with identical logic but different names. Injects Safe Proxy Pattern: duplicate bodies become one-line wrappers delegating to a shared canonical implementation.

### The Shadow

Symlink-based overlay of the source tree. Before any physical deletion, symlinks for dead-symbol files are unmapped and `pytest` is run in the shadow tree. Physical deletion proceeds only on a passing test suite; symlinks are restored on failure.

---

## III. THE ECONOMICS: UTILITY PRICING

The Audit is **Free**. The Purge is **Paid**.

| Tier | Cost | Scope |
|:-----|:-----|:------|
| **Bounty Hunter** | **$49/yr** | Individual. Pay-as-you-purge ($1.00/MB deleted). |
| **Sovereign Squad** | **$499/yr** | Team (5 users). Shared PoUD credit pool. |
| **Fiduciary Core** | **Custom** | Enterprise (>10M LOC). Priority support. |

Anti-gaming constraint: code must be >90 days old. Purging symbols created within 90 days incurs a **5× tax** and generates zero credits.

[Purchase a Token → thejanitor.app](https://thejanitor.app)

---

## IV. INSTALLATION

### From Source (Recommended)

Requires: **Rust 1.82+**, `just`.

```sh
git clone https://github.com/GhrammR/the-janitor
cd the-janitor
just build
# Binary at: target/release/janitor
```

Or with audit verification:

```sh
just audit   # fmt + clippy + check + 103 tests
just build
```

### Pre-built Binary

Download the stripped release binary from [Releases](https://github.com/GhrammR/the-janitor/releases).

```sh
chmod +x janitor
sudo mv janitor /usr/local/bin/
```

---

## V. COMMANDS

```sh
# Detect dead symbols (free, no token required)
janitor scan <path> [--library] [--verbose]

# Find structurally duplicate functions (free, report only)
janitor dedup <path>

# Apply Safe Proxy deduplication (token required)
janitor dedup <path> --apply --token <TOKEN>

# Shadow-simulate deletion + test, then physically purge (token required)
janitor clean <path> --token <TOKEN>

# Initialize symlink shadow tree
janitor shadow init <path>

# Load .janitor/symbols.rkyv and launch TUI dashboard (free)
janitor dashboard <path>
```

---

## VI. LEGACY DEPRECATION — PYTHON v4 IS DEAD

**Python v4.0 through v4.2 are permanently deprecated.**

The Python implementation relied on ChromaDB semantic search, external LLM API calls, and NetworkX graphs. Every component has been replaced:

| Python (v4) | Rust (v5.4.0) |
|-------------|---------------|
| NetworkX DiGraph | `petgraph` directed reference graph |
| Tree-sitter (Python binding) | Tree-sitter (Rust, zero-copy mmap) |
| ChromaDB + UniXcoder | BLAKE3 alpha-normalized structural hashing |
| LLM merge generation | Deterministic Safe Proxy Pattern |
| JSON manifests | `rkyv` zero-copy binary registry |
| SQLite cache | `.janitor/symbols.rkyv` mmap |

No migration path is provided. Purge your Python v4 source. Re-materialize in Rust.

---

> See [Sovereignty → Token Gate](sovereignty/tokens.md) for how the Ed25519 purge authorization works.
