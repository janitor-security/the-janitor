# The Janitor: Automated Dead Symbol Detection & Code Cleanup
**Current Version:** v6.5.0

**Stop paying for code you don't use.**

The Janitor creates a Shadow Tree to verify deletion safety, then surgically removes dead code at the symbol level — functions, classes, and entire orphan files — across Python, Rust, JavaScript/TypeScript, and C++ codebases.

Don't guess your technical debt. The Janitor generates a verifiable **Code Health Badge** so your team can surgically monitor the decay of the monolith before it impacts production.

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

**Automated Cleanup is Free. Integrity Proof is the Standard.**

| Tier | Cost | Includes |
|------|------|----------|
| **Junior Janitor** | **Free** | Unlimited Scan, Cleanup, Dedup, Badge, Dashboard. No signed logs. No PQC attestation. |
| **Lead Specialist** | **$4,900/yr** | All free features + PQC-Signed Audit Logs + Sovereign Status Badges + CI/CD Compliance Attestation. Up to 10 seats. |
| **Industrial Core** | **From $50,000/yr** | For monoliths >1M LOC. On-Prem Token Server + Keypair Rotation Protocol + Enterprise SLA. Unlimited seats. |

[Get Certified → thejanitor.lemonsqueezy.com](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)

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

Scan, cleanup, badge, and dashboard are permanently free. Integrity attestation (PQC-Signed Audit Logs, CI/CD Compliance Attestation) requires a [Lead Specialist token](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key).
