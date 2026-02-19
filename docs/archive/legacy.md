# Archive: Python v4 Deprecation Record

> This page is preserved for historical reference. The Python implementation is permanently deprecated. No migration path exists. See the [Overview](../index.md) for the current Rust-native architecture.

---

## PYTHON v4 IS DEAD

**Python v4.0 through v4.2 are permanently deprecated.**

The Python implementation relied on ChromaDB semantic search, external LLM API calls, and NetworkX graphs. Every component has been replaced by a deterministic, zero-dependency Rust implementation:

| Python (v4) | Rust (v6.0.0+) |
|-------------|----------------|
| NetworkX DiGraph | `petgraph` directed reference graph |
| Tree-sitter (Python binding) | Tree-sitter (Rust, zero-copy mmap, 9 grammars) |
| ChromaDB + UniXcoder | BLAKE3 alpha-normalized structural hashing |
| LLM merge generation | Deterministic Safe Proxy Pattern |
| JSON manifests | `rkyv` zero-copy binary registry |
| SQLite cache | `.janitor/symbols.rkyv` mmap |
| Python-only analysis | C, C++, Rust, Go, Java, C#, JS, TS, Python |

No migration path is provided. Purge your Python v4 source. Re-materialize in Rust.

---

## Why the Rewrite Was Non-Negotiable

The Python implementation had three structural flaws that could not be patched:

1. **Non-determinism**: LLM-generated merge bodies varied between runs. Identical inputs produced different outputs. An integrity tool cannot be non-deterministic.
2. **External dependencies**: ChromaDB and the UniXcoder embedding model required network access and a GPU or paid API. The Janitor must work offline, on a CI runner with no GPU, for airgapped deployments.
3. **Single-language scope**: A Python-only dead-code tool is a liability in any polyglot codebase. The Rust rewrite supports 9 grammars from day one, with the same pipeline for all languages.

---

*This file is an archive. No further updates will be made here.*
