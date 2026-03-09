# Benchmarks — 20-Repo Ultimate Gauntlet

Results from **v6.9.0**. All repos scanned with `janitor scan --library` and 100 PRs
bounced per repo via `janitor bounce --patch`. Scan excludes: `tests/`, `vendor/`,
`thirdparty/`, `node_modules/`, `generated/`, `docs/`.

**Hardware**: AMD64 / WSL2, Linux 6.6.87. 8 GB RAM. Single-threaded scan per repo.

---

## 20-Repo Gauntlet Summary

| Repo | Lang | Peak RSS | Dead Symbols | Clone Groups | PRs Bounced | Unlinked | Antipatterns |
|:-----|:-----|:--------:|-------------:|:------------:|:-----------:|:--------:|:------------:|
| **godotengine/godot** | C++ | **58 MB** | 717 | 2 | 98/100 | 70 | 15 |
| electron/electron | C++/JS | 30 MB | 10 | 2 | 100/100 | 97 | 68 |
| microsoft/vscode | TS | 107 MB | 2,827 | 0 | 99/100 | 75 | 68 |
| DefinitelyTyped/DefinitelyTyped | TS | 110 MB | 13 | 0 | 99/100 | 99 | 32 |
| vercel/next.js | JS/TS | 51 MB | 0 | 0 | 97/100 | 91 | 42 |
| ansible/ansible | Python | 25 MB | 894 | 2 | 100/100 | 79 | 22 |
| home-assistant/core | Python | 101 MB | 8,311 | 9 | 98/100 | 84 | 9 |
| kubernetes/kubernetes | Go | 166 MB | 73 | 2 | 98/100 | 86 | 16 |
| moby/moby | Go | 34 MB | 0 | 0 | 100/100 | 95 | 29 |
| **rust-lang/rust** | **Rust** | **235 MB** | 30 | 2 | 100/100 | 100 | 54 |
| tauri-apps/tauri | Rust/JS | 29 MB | 1 | 0 | 100/100 | 68 | 52 |
| spring-projects/spring-boot | Java | 55 MB | 0 | 0 | 99/100 | 89 | 21 |
| elastic/elasticsearch | Java | 315 MB | 21 | 0 | 96/100 | 92 | 35 |
| redis/redis | C | 23 MB | 87 | 2 | 98/100 | 95 | 15 |
| NixOS/nixpkgs | Nix | 29 MB | 199 | 2 | 100/100 | 97 | 42 |
| dotnet/aspnetcore | C# | 142 MB | 4 | 0 | 98/100 | 83 | 42 |
| apache/kafka | Java | 72 MB | 1 | 3 | 100/100 | 100 | 27 |
| ohmyzsh/ohmyzsh | Bash | 10 MB | 0 | 0 | 100/100 | 92 | 42 |
| pytorch/pytorch | C++/Py | 164 MB | 8,247 | 24 | 99/100 | 89 | 4 |
| langchain-ai/langchain | Python | 20 MB | 1,483 | 2 | 100/100 | 53 | 17 |

**Total PRs bounced**: 1,979 / 2,000 across 20 repos
**Total dead symbols found**: 22,918
**Total clone groups detected**: 55
**OOM events**: 0 / 20
**Errors**: 1 (dotnet/aspnetcore, one timeout)

---

## The Anchor Stats

### Godot Engine — C++ at Scale (58 MB)

> **717 dead symbols (library mode). 58 MB peak RSS. 33 seconds static scan. Zero OOM.**

Godot is the polyglot stress anchor: C++, C#, Java, Objective-C, GLSL, Python — 1,200+
source files, complex template hierarchies, `#include` networks, and shader pipelines.

The Janitor processes the full symbol graph in a single streaming pass:

- 0 panics on `.glsl` and `.mm` (Objective-C) files
- 0 false positives on engine lifecycle callbacks (`_ready`, `_process`, `_physics_process`)
- 58 MB peak RSS: well inside any CI runner's memory budget
- **15 antipatterns** caught across 98 bounced PRs — raw `new` usage flagged in C++ PRs

```
Peak RSS   : 58 MB
Static scan: 33 seconds
PRs bounced: 98 / 100
Antipatterns caught: 15
Clone groups: 2
```

### rust-lang/rust — 235 MB Ceiling Test

> **235 MB peak RSS. 4m4s. 100/100 PRs bounced. 54 vacuous-`unsafe` antipatterns.**

The Rust compiler repo is the RAM stress test: 30+ crates, stdarch, library/, compiler/,
and the entire standard library. Peak RSS stabilised at 235 MB — the highest in the corpus.
**Zero OOM.** The Physarum backpressure governor (`SystemHeart::beat()`) prevented runaway
allocation throughout the full 4-minute session.

The slop signal was loud: 54 antipatterns across 100 PRs, all vacuous `unsafe` blocks
containing no raw pointer dereferences, FFI calls, or inline assembly. The worst offender:

| PR | Author | Score | Finding |
|----|--------|------:|:--------|
| #153239 | `asder8215` | **1,235** | 8× vacuous `unsafe` block |
| #153270 | `jhpratt` | 515 | 7× vacuous `unsafe` block |
| #153277 | `jhpratt` | 505 | 7× vacuous `unsafe` block |

---

## PR Bounce Highlights

### Kafka — Java Slop Detected

`apache/kafka` produced the highest-quality Java slop signal in the corpus. PR #21580 by
`aliehsaeedii` was caught adding `System.out.println` debug logging in production Java:

```
Score: 800 | Antipattern: System.out.println: console debug logging in production
           | — use a structured logger (SLF4J, Log4j, etc.)
```

100% of Kafka PRs were unlinked to issues — zero PRs in the sample referenced a ticket.

### LangChain — Highest Zombie Dep Density

`langchain-ai/langchain` had the most aggressive zombie dependency signal. PR #35416 by
`sadilet` introduced a hallucinated import (`otel_context` imported inside a function, never
used) and 39 zombie dependencies in a single patch:

```
Score: 1,095 | Antipattern: Hallucinated import: 'otel_context' imported inside function
             | but never used
             | Zombie deps: 39
```

### PyTorch — Clone Epidemic

`pytorch/pytorch` registered **24 clone groups** — the highest dedup signal in the corpus.
55 zombie deps were introduced across the 99 bounced PRs.

---

## Methodology

> Measured via `time -v` on 8 GB Dell Inspiron (2019). Zero-Copy `rkyv` architecture.

```bash
# Ultimate Gauntlet runner (tools/ultimate_gauntlet.sh)
for REPO in "${REPOS[@]}"; do
  git clone --depth 1 "https://github.com/${REPO}" /tmp/gauntlet_repo
  /usr/bin/time -v janitor scan /tmp/gauntlet_repo \
      --library --format json > scan.json 2> time.log
  # Peak RSS from "Maximum resident set size (kbytes)" in GNU time -v output
  janitor dedup /tmp/gauntlet_repo
  # Bounce last 100 PRs via gh pr diff (no local git history required)
  for PR in $(gh pr list --repo "$REPO" --limit 100 --json number -q '.[].number'); do
    gh pr diff "$PR" --repo "$REPO" > pr.patch
    janitor bounce /tmp/gauntlet_repo --patch pr.patch --format json
  done
  rm -rf /tmp/gauntlet_repo   # Immediate teardown for disk budget
done
```

All scans run cold (no `.janitor/symbols.rkyv` cache). Peak RSS from
`Maximum resident set size (kbytes)` in GNU `time -v` output.
The `--library` flag promotes all `pub` symbols to `Protection::LibraryMode`,
making dead-symbol counts reflect genuine unreferenced internal helpers only.

---

## Why Local-First Architecture Matters

Cloud-based SCA tools operate by shipping your code to a remote analysis cluster,
waiting for results, and returning a report over a network round-trip.  The Janitor
inverts this model entirely.

**Everything runs on the machine that owns the code:**

- `rkyv` zero-copy deserialization means the 235 MB rust-lang/rust registry is
  memory-mapped and query-ready in under 300 ms — no serialization overhead, no
  network latency, no cold start.
- `memmap2::Mmap` provides OS-backed file access at page-fault granularity: the
  kernel only loads the bytes your query actually touches.
- The symbol registry is a single flat binary blob, not a graph database.  A
  `HashSet<&str>` lookup against 30,000 registry entries takes ~5 µs.
- The Physarum governor (`SystemHeart::beat()`) enforces RAM budgets locally,
  preventing OOM on any CI runner without a remote rate-limiter or quota system.

**Consequence**: The 33-second Godot scan is a cold-start number with zero warm
cache, on consumer hardware, inside WSL2.  Cloud tools advertising "real-time"
analysis are paying the network and RPC tax on every invocation.  The Janitor pays
it once — during grammar compilation — and amortises it across the lifetime of the
process via `OnceLock<Language>` statics.

**Privacy corollary**: your source code never leaves the machine.  The only
outbound traffic is the optional audit attestation POST to
`https://api.thejanitor.app/v1/attest`, which carries only a cryptographic summary
(PR metadata + score), never file contents.

---

## Language Support Matrix

| Language | Grammar | Status | Gauntlet Repo |
|:---------|:--------|:-------|:--------------|
| Python | `tree-sitter-python` | Production | ansible, home-assistant, pytorch, langchain |
| Rust | `tree-sitter-rust` | Production | rust-lang/rust, tauri |
| JavaScript | `tree-sitter-javascript` | Production | electron, next.js |
| TypeScript | `tree-sitter-typescript` | Production | vscode, DefinitelyTyped |
| C++ | `tree-sitter-cpp` | Production | godot, electron, pytorch |
| C | `tree-sitter-c` | Production | redis |
| Java | `tree-sitter-java` | Production | kafka, elasticsearch, spring-boot |
| C# | `tree-sitter-c-sharp` | Production | dotnet/aspnetcore |
| Go | `tree-sitter-go` | Production | kubernetes, moby |
| Bash | `tree-sitter-bash` | Production | ohmyzsh/ohmyzsh |
| GLSL / VERT / FRAG | `tree-sitter-glsl` | Production | godot shaders |
| Objective-C / Obj-C++ | `tree-sitter-objc` | Production | godot platform |
