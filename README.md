# The Janitor: Automated Technical Debt Excision
**Current Version:** v5.5.1

**Stop paying for code you don't use.**

The Janitor creates a Shadow Tree to verify deletion safety, then surgically excises dead code at the symbol level — functions, classes, and entire orphan files — across Python, Rust, JavaScript/TypeScript, and C++ codebases.

## How It Works

1. **Scan** — Static reference graph + 6-stage heuristic pipeline identifies every dead symbol.
2. **Simulate** — Shadow Tree overlays symlinks to the dead files. Your test suite runs against the simulated deletion.
3. **Excise** — Tests pass? Dead code is removed bottom-to-top (byte-precise, UTF-8 hardened). Tests fail? Full rollback, zero corruption.

## Quick Start

```bash
# Free: detect dead code
janitor scan ./src

# Free: find duplicate functions (structural clone detection)
janitor dedup ./src

# Paid: simulate + excise
janitor clean ./src --token <YOUR_TOKEN>
```

## Language Support

| Language | Dead Functions | Dead Classes | Dead Files | Duplicate Logic |
|----------|---------------|--------------|------------|-----------------|
| Python   | ✓             | ✓            | ✓          | ✓               |
| Rust     | ✓             | ✓            | ✓          | —               |
| JavaScript / TypeScript | ✓ | ✓       | ✓          | —               |
| C++      | ✓             | ✓            | ✓          | —               |

## False-Positive Protection

17-variant protection system. Heuristics cover:

- FastAPI route decorators, dependency injection, lifespan teardown
- Pydantic validators, forward references, alias generators
- SQLAlchemy metaprogramming, hybrid properties, polymorphic mappers
- pytest fixtures, conftest.py, test fingerprinting
- Qt auto-connection slots, ORM lifecycle methods
- Plugin directories (Scrapy, Celery, Django management commands)
- Grep shield: Aho-Corasick scan of all non-Python files

## Pricing

**The Audit is Free. The Purge is Paid.**

| Tier | Cost | Includes |
|------|------|----------|
| **Scan** | Free forever | Dead code detection, dedup report, TUI dashboard |
| **Bounty Hunter** | First 50 MB deleted **free**, then $1.00/MB | `janitor clean` on any codebase |
| **Sovereign Squad** | $499/yr (5 seats) | Shared purge credit pool, CI integration |
| **Fiduciary Core** | Custom | Monoliths >10M LOC, SLA, PQC attestation |

**Anti-Gaming Policy:** Code must be >90 days old. Deleting code created within 90 days incurs a 5× surcharge.

[Purchase tokens at thejanitor.app](https://thejanitor.app)

## CI Integration

```yaml
- uses: GhrammR/the-janitor@v5
  with:
    path: ./src
    args: scan --verbose
```

For automated purge in CI, pass your token via a secret:

```yaml
- uses: GhrammR/the-janitor@v5
  with:
    args: clean --token ${{ secrets.JANITOR_TOKEN }}
    path: ./src
```

## Commands

| Command | Auth | Purpose |
|---------|------|---------|
| `janitor scan <path>` | Free | Detect dead symbols, save `.janitor/symbols.rkyv` |
| `janitor dedup <path>` | Free | Report structural clone groups |
| `janitor dedup <path> --apply --token <tok>` | Paid | Inject safe proxy pattern |
| `janitor clean <path> --token <tok>` | Paid | Shadow simulate → test → excise |
| `janitor dashboard <path>` | Free | Ratatui TUI — Top 10 dead symbols by size |

## License

**Sovereign Proprietary License (SPL v1.0)** — Source Available, Paid Execution.

Analysis is free. Execution (`clean`, `dedup --apply`) requires a PQC-signed token from [thejanitor.app](https://thejanitor.app). Redistribution of purge logic or ghost-file output is prohibited.
