# The Janitor: Automated Dead Symbol Detection & Code Cleanup
**Current Version:** v5.9.5

**Stop paying for code you don't use.**

The Janitor creates a Shadow Tree to verify deletion safety, then surgically removes dead code at the symbol level — functions, classes, and entire orphan files — across Python, Rust, JavaScript/TypeScript, and C++ codebases.

## How It Works

1. **Scan** — Static reference graph + 6-stage heuristic pipeline identifies every dead symbol.
2. **Simulate** — Shadow Tree overlays links to the dead files. Your test suite runs against the simulated deletion.
3. **Remove** — Tests pass? Dead code is removed bottom-to-top (byte-precise, UTF-8 hardened). Tests fail? Full rollback, zero corruption.

## Quick Start

```bash
# Free: detect dead code
janitor scan ./src

# Free: find duplicate functions (structural clone detection)
janitor dedup ./src

# Free: simulate + remove (no token required)
janitor clean ./src --force-purge
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

**Cleanup is Free. Integrity Attestations are Paid.**

| Tier | Cost | Includes |
|------|------|----------|
| **Junior Janitor** | **Free** | Scan, cleanup, dedup, badge, TUI dashboard — unlimited. |
| **Lead Specialist** | **$499/yr** | Signed audit logs, PQC attestation, CI integration token. |
| **Industrial Core** | **Custom** | SLA, on-prem token server, >10M LOC support. |

[Get started at thejanitor.app](https://thejanitor.app)

## CI Integration

```yaml
- uses: GhrammR/the-janitor@v5
  with:
    path: ./src
    args: scan --verbose
```

For automated cleanup in CI (free):

```yaml
- uses: GhrammR/the-janitor@v5
  with:
    args: clean --force-purge
    path: ./src
```

For signed attestation in CI (Lead Specialist tier):

```yaml
- uses: GhrammR/the-janitor@v5
  with:
    args: clean --force-purge --token ${{ secrets.JANITOR_TOKEN }}
    path: ./src
```

## Commands

| Command | Auth | Purpose |
|---------|------|---------|
| `janitor scan <path>` | Free | Detect dead symbols, save `.janitor/symbols.rkyv` |
| `janitor dedup <path>` | Free | Report structural clone groups |
| `janitor dedup <path> --apply --force-purge` | Free | Inject safe proxy pattern |
| `janitor clean <path> --force-purge` | Free | Shadow simulate → test → remove dead code |
| `janitor clean <path> --force-purge --token <tok>` | Lead Specialist | Clean + signed integrity attestation |
| `janitor badge <path>` | Free | Generate code health SVG badge |
| `janitor undo <path>` | Free | Reverse last cleanup (git stash or ghost restore) |
| `janitor dashboard <path>` | Free | Ratatui TUI — Top 10 dead symbols by size |

## License

**Business Source License 1.1 (BSL 1.1)** — Source Available. Converts to MIT on 2030-02-15.

Scan, cleanup, badge, and dashboard are permanently free. Integrity attestation (signed audit logs, PQC compliance reports) requires a [Lead Specialist token](https://thejanitor.app).
