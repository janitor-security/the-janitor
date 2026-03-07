# Security Posture

> **Audience**: Security architects, procurement teams, and enterprise buyers conducting
> vendor due-diligence. This document maps each security control to the source-code
> construct that implements it.

---

## Executive Summary

The Janitor is a static-analysis engine that processes untrusted code at high volume.
Every architectural decision has been made under the assumption that the input is
adversarial. The result is a system with **no shell execution surface**, **no mutable
disk state during analysis**, **post-quantum signed audit trails**, and a **CI/CD
pipeline that continuously audits itself**.

---

## 1. Zero-Trust Parsing: RAM-Only, Zero-Copy AST Pipeline

### Threat Modelled

A developer submits a PR containing a weaponised source file: a polyglot document
designed to exploit a parser vulnerability, an oversized file intended to exhaust
memory, or a binary blob disguised as source code. A naive analysis engine materialises
the file to disk and invokes a subprocess — creating a reachable, executable attack
surface.

### The Control

All file reads in The Janitor's hot path use `memmap2::Mmap` — a read-only memory-mapped
view of the file. The operating system maps the file's pages into the process's virtual
address space with the `PROT_READ` flag only. **The file content is never copied into a
heap allocation.** Tree-sitter receives a `&[u8]` slice of the mmap'd region and
constructs the AST entirely in RAM.

```
  Disk                   Process Virtual Memory
  ─────                  ──────────────────────
  file.rs  ──PROT_READ──► &[u8] (mmap region)
                               │
                          tree-sitter parse()
                               │
                          AST nodes (heap, owned by tree-sitter)
                               │
                          Entity extraction ──► Vec<Entity> (heap)
                               │
                          mmap drop ──► OS reclaims pages
```

**No AST is written to disk.** No temporary file is created. The parsed representation
exists only for the duration of the analysis call. When the `Mmap` handle is dropped,
the OS reclaims the mapped pages.

### Circuit Breakers

Two hard limits prevent resource exhaustion before any parsing begins:

| Limit | Value | Location |
|-------|-------|----------|
| Max file size for parsing | 1 MiB | `slop_filter.rs` circuit breaker |
| Parse timeout | 100 ms | `parser.rs::PARSE_TIMEOUT_MICROS` |
| Panic containment | `catch_unwind(AssertUnwindSafe)` | `parser.rs::timed_parse()` |

A file that exceeds 1 MiB is skipped without ever reaching tree-sitter. A parse that
exceeds 100 ms is cancelled. A grammar-level panic is caught and converted to a
`ParseFailure` error — it never unwinds past the crate boundary.

### Attack Surface Eliminated

| Traditional Approach | The Janitor |
|----------------------|-------------|
| Write file to `/tmp/`, invoke linter subprocess | No subprocess. No `/tmp/` write. |
| Parse with full-heap copy of file bytes | PROT\_READ mmap: no copy, no write access |
| Persist intermediate AST to disk | AST lives in RAM for ≤ 100 ms, then reclaimed |
| No timeout on parser | 100 ms hard ceiling via progress callback |

---

## 2. Shadow Merger: Air-Gapped PR Simulation

### Threat Modelled

A hostile PR modifies `Makefile`, `CMakeLists.txt`, `setup.py`, or a GitHub Actions
workflow. An analysis pipeline that checks out the branch, builds the project, or runs
any tooling against the working tree **executes the attacker's code**.

### The Control

`crates/forge/src/shadow_git.rs` exposes `simulate_merge(repo, base_oid, head_oid)`.
This function uses libgit2's tree-diff API to compute the set of blobs that differ
between the base commit and the PR head — entirely within the git object store, which is
already on disk and read-only from The Janitor's perspective.

```
┌──────────────────────────────────────────────────────┐
│                   janitor bounce                      │
│                                                       │
│  simulate_merge(repo, base_oid, head_oid)             │
│       │                                               │
│  libgit2 tree-diff ── reads .git/objects/ (RO)        │
│       │                                               │
│  MergeSnapshot { blobs: HashMap<PathBuf, Vec<u8>> }   │
│       │           (pure heap allocation)              │
│  find_slop() ◄── tree-sitter parses &[u8]             │
│                  (never touches filesystem)           │
│                                                       │
│  ══ ISOLATION BOUNDARY: zero shell execution below ══ │
└──────────────────────────────────────────────────────┘
```

**No file is checked out. No working directory is written. No build tool is invoked.**
The `MergeSnapshot` is a `HashMap<PathBuf, Vec<u8>>` — a pure heap allocation. A
malicious `CMakeLists.txt` exists only as an inert byte array.

### Chemotaxis Prioritisation

`MergeSnapshot::iter_by_priority()` processes high-signal languages first
(`rs → py → go → js → ts → …`), ensuring that the analysis budget is spent on files
most likely to carry actionable findings before the bounce timeout terminates the run.
The prioritisation order is statically encoded in `shadow_git.rs` and is not influenced
by any content of the PR.

---

## 3. Post-Quantum Attestation: ML-DSA-65 (FIPS 204)

### Threat Modelled

A future adversary with access to a cryptographically relevant quantum computer
retroactively breaks ECDSA or RSA signatures on archived attestation logs, enabling
silent forgery of historical audit records.

### The Control

The Janitor's attestation pipeline is signed with **ML-DSA-65**, the Module Lattice
Digital Signature Algorithm standardised by NIST in August 2024 as FIPS 204. ML-DSA is
lattice-based; no known quantum algorithm provides a sub-exponential speedup for
signature forgery against it. The scheme provides **128-bit post-quantum security**.

### Key Architecture

| Component | Location | Role |
|-----------|----------|------|
| Verifying key (public) | Embedded in binary at compile time | Token verification (offline) |
| Signing key (private) | Held exclusively by thejanitor.app | Never in binary, never in repo |
| Token format | `base64(ml_dsa_65_sign("JANITOR_PURGE_AUTHORIZED", sk))` | Bearer authorisation |
| Verification | `vault::SigningOracle::verify_token()` — pure offline | No network call required |

The binary embeds **only `VERIFYING_KEY_BYTES`**. The corresponding private key does not
appear in the repository, binary, build artefact, or process memory at runtime. Running
`strings` or `objdump` against the binary will produce the public key and nothing else.

### Token Revocation

Revocation is achieved by keypair rotation, not by a revocation list:

1. `cargo run -p mint-token -- generate` produces a new ML-DSA-65 keypair.
2. The new verifying key is embedded in a patch release binary.
3. All tokens signed against the old private key are **cryptographically invalid** against
   the new verifying key — no database lookup, no network check, no revocation server.

Rotation cadence and emergency SLA are documented in [Safety Guarantees → Cryptographic
Key Rotation](safety.md#cryptographic-key-rotation--token-revocation).

### "Harvest Now, Decrypt Later" Resistance

Attestation logs signed today with ML-DSA-65 remain unforgeable under a future quantum
adversary. Classical ECDSA-signed audit trails collected over the next decade will be
retroactively forgeable once sufficiently powerful quantum computers exist. We made the
migration in 2024, before the threat materialised.

---

## 4. Supply Chain Integrity: Pinned Dependencies, Self-Audited CI

### GitHub Actions: SHA-Pinned, Harden-Runner Gated

Every action in `.github/workflows/` is pinned to a 40-character commit SHA — never a
mutable version tag. `step-security/harden-runner` is the **first step** of every job,
restricting the egress network policy to only the endpoints required by that workflow.

```yaml
- uses: step-security/harden-runner@5ef0c079ce82195b2a36a210272d6b661572d83e # v2.14.2
  with:
    egress-policy: audit
```

A tag-pinned action (`@v4`) is a mutable pointer — the action owner can silently
replace the tag with malicious code. A SHA-pinned action is immutable. The CI pipeline
will fail to resolve any action whose SHA has changed.

### Cargo Audit

`cargo audit` is a required gate in the `just audit` recipe (the Definition of Done for
every change). Any crate with a known advisory in the RustSec database causes the build
to fail. The workspace `deny.toml` policy additionally enforces licence compatibility and
bans crates with duplicate transitive dependencies.

### Docker: Digest-Pinned Base Images

The production `Dockerfile` pins both the builder and runtime images to `@sha256:<digest>`:

```dockerfile
FROM rust:1.85-slim@sha256:3490aa77... AS builder
FROM debian:bookworm-slim@sha256:6458e6ce... AS runtime
```

A tag (`rust:1.85-slim`) is mutable. A digest pin is not.

### The Janitor Scans The Janitor

The engine's own CI/CD pipeline runs `janitor scan` against the engine's own source tree
on every pull request via the `janitor-pr-gate.yml` GitHub Actions workflow. The
composite action (`action.yml`) downloads the release binary, runs `janitor bounce`
against the PR diff, and fails the gate if the slop score exceeds 100.

**The firewall audits itself.** Any PR that introduces dead symbols, zombie dependencies,
hallucinated security claims, or structural clones into the engine is blocked by the
engine — before a human reviewer sees it.

```
PR opened ──► janitor-pr-gate.yml
                    │
             janitor bounce <diff>
                    │
             slop_score ≥ 100 ? ──► CI FAIL (PR blocked)
                    │
             slop_score < 100 ? ──► CI PASS (review proceeds)
```

This creates a structural invariant: the production binary cannot contain classes of
defects that it is designed to detect in others.

---

## 5. RAM Pressure Management: Physarum Backpressure

### Threat Modelled

A burst of concurrent bounce requests causes heap allocation to grow without bound,
leading to OOM-killer termination and denial of service.

### The Control

`crates/common/src/physarum.rs` implements `SystemHeart::beat()`, which samples total
RAM utilisation on every request. The daemon acquires a concurrency semaphore before
processing:

| RAM Utilisation | Semaphore | Max Concurrent Requests |
|-----------------|-----------|------------------------|
| ≤ 75% | `flow_semaphore` | 4 |
| 75 – 90% | `constrict_semaphore` | 2 |
| > 90% | Busy-wait until < 90% | 0 (backpressure) |

Requests that arrive when RAM utilisation exceeds 90% are held — not dropped, not
errored — until the system returns to the `Constrict` or `Flow` band. This prevents OOM
termination without requiring manual capacity planning.

---

## 6. Responsible Disclosure

Security issues in The Janitor should be reported to
**security@thejanitor.app**. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (proof-of-concept code or a minimal diff is helpful).
- Your preferred contact method for follow-up.

We commit to acknowledging receipt within 24 hours and providing an initial assessment
within 72 hours. Critical vulnerabilities (RCE, token forgery, audit log tampering) are
treated as P0 with a target patch cadence of 48 hours from confirmation.

We do not operate a bug bounty programme at this time. Responsible disclosers are
credited in the release changelog unless they request anonymity.

---

## Compliance Mapping

| Framework | Relevant Control | The Janitor Implementation |
|-----------|-----------------|---------------------------|
| SOC 2 Type II — CC6 | Logical access controls | ML-DSA-65 token gate on all destructive commands |
| SOC 2 Type II — CC7 | System monitoring | Remote attestation POST to `/v1/attest` on every excision |
| NIST FIPS 204 | Post-quantum signature | ML-DSA-65 (`pqcrypto-mldsa` crate, verified against NIST KATs) |
| SLSA Level 2 | Build provenance | GitHub Actions release workflow with SHA-pinned steps |
| CIS Benchmark — 14.2 | Encrypt data in transit | All API calls use HTTPS; `ureq` enforces TLS |
| OWASP — A08:2021 | Software and data integrity | `cargo audit` + `cargo deny` in CI; SHA-pinned Docker images |
