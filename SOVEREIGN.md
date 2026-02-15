# SOVEREIGN.md
**VERSION:** 5.5.0-SOVEREIGN
**DATE:** 2026-02-15
**CONTEXT:** Polyglot Blade — C++ Integration (Phase 3.6), Flask/Requests Live-Fire Verified

---

## I. THE ANATOMIST: CST PARSING & ENTITY EXTRACTION

**Status**: **[COMPLETE]** — Phase 1

**Role**: Converts Python source into zero-copy `Entity` facts for the pipeline.

### 1.1 Core Architecture

- **Parser Host**: Tree-sitter (Python grammar) + mmap zero-copy parsing.
- **CST Generation**: Builds Concrete Syntax Tree preserving all tokens.
- **Entity Extraction**: Converts CST nodes → `Entity` structs with byte ranges, qualified names, parent classes, decorators, structural hashes.
- **Graph Building**: Directed reference graph (Symbol A references Symbol B).
- **Reference Linking**: Resolves imports, attribute access, function calls.

### 1.2 Entity Struct

**Zero-Copy Design** (defined in `crates/anatomist/src/lib.rs`):

```rust
pub struct Entity {
    pub name: String,
    pub entity_type: EntityType,
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub file_path: String,
    pub qualified_name: String,
    pub parent_class: Option<String>,
    pub base_classes: Vec<String>,
    pub protected_by: Option<Protection>,
    pub decorators: Vec<String>,
    pub structural_hash: Option<u64>,
}
```

---

## II. DEAD SYMBOL PIPELINE: THE 6-STAGE GATE SYSTEM

**Status**: **[COMPLETE]** — Phase 3

| Stage | Filter | Protection |
|-------|--------|------------|
| 0 | Directory filter (tests/, migrations/, etc.) | `Directory` |
| 1 | Reference graph (in-degree > 0) | `Referenced` |
| 2+4 | Wisdom heuristics + `__all__` exports (single mmap pass) | Various |
| 3 | Library mode: public symbols | `LibraryMode` |
| 5 | Grep shield: Aho-Corasick scan of non-.py files | `GrepShield` |

### 2.1 Protection Enum (17 variants, `common::Protection`, `#[repr(u8)]`)

`Directory=0, Referenced=1, WisdomRule=2, LibraryMode=3, PackageExport=4,
ConfigReference=5, MetaprogrammingDanger=6, LifecycleMethod=7, EntryPoint=8,
QtAutoSlot=9, SqlAlchemyMeta=10, OrmLifecycle=11, PydanticAlias=12,
FastApiOverride=13, PytestFixture=14, GrepShield=15, TestReference=16`

---

## III. THE REAPER: TEST FINGERPRINTING & SAFE DELETION

**Status**: **[COMPLETE]** — Phase 4

### 3.1 SafeDeleter Protocol

1. Backup source to `.janitor/ghost/{ts}_{filename}.bak` on first touch.
2. Sort targets **descending** by `start_byte` (bottom-to-top splice).
3. Drain byte ranges (`delete_symbols`) or splice-replace (`replace_symbols`).
4. UTF-8 hardened: `snap_char_boundary_bwd/fwd` via `str::is_char_boundary()`.
5. `commit()` → delete backups. `restore_all()` → copy backups back.

### 3.2 Test Fingerprinting

- `collect_test_ids()` runs `pytest --collect-only -q`.
- Test names matched to symbol names → `Protection::TestReference`.

---

## IV. THE FORGE: STRUCTURAL HASHING & SAFE PROXY PATTERN

**Status**: **[COMPLETE]** — Phase 5

### 4.1 Structural Hashing

- Alpha-normalized BLAKE3 over function body CST (identifiers, strings, comments stripped).
- Two functions with identical logic but different names → same `u64` hash.

### 4.2 Safe Proxy Pattern (`janitor dedup --apply`)

```python
# Before: 2 duplicate functions
def calculate_tax_us(amount, rate):
    subtotal = amount * rate
    return subtotal

def calculate_tax_ca(amount, rate):
    subtotal = amount * rate
    return subtotal

# After: proxies + single impl
def calculate_tax_us(amount, rate):
    return _calculate_tax_us_impl(amount, rate)

def calculate_tax_ca(amount, rate):
    return _calculate_tax_us_impl(amount, rate)

def _calculate_tax_us_impl(amount, rate):
    subtotal = amount * rate
    return subtotal
```

---

## V. THE SHADOW: SYMLINK OVERLAY

**Status**: **[COMPLETE]** — Phase 6

### 5.1 Shadow Tree (`crates/shadow`)

- `ShadowManager::initialize(source, shadow)` — creates `.janitor/shadow_src/` with symlinks.
- `ShadowManager::open(source, shadow)` — opens existing shadow tree.
- `ShadowManager::unmap(rel)` — removes symlink (simulation step).
- `ShadowManager::remap(rel)` — restores symlink on failure.
- `ShadowManager::move_to_ghost(rel)` — Ghost Protocol: real file → `.janitor/ghost/`.

### 5.2 Clean Command (`janitor clean <path> --token <token>`)

1. Verify Ed25519 token.
2. Run 6-stage pipeline → get kill list.
3. Initialize (or open) shadow tree.
4. Unmap symlinks for dead-symbol files.
5. Run pytest in shadow tree.
6. **Pass**: `SafeDeleter::delete_symbols` on source files → `commit()`.
7. **Fail**: `remap()` all unmapped symlinks → abort.

---

## VI. ECONOMIC PROTOCOL: THE SOVEREIGN VAULT

**Status**: **[COMPLETE]** — Phase 7

### 6.1 Token Gate (`crates/vault`)

- `SigningOracle::verify_token(token: &str) -> bool`
- Token = base64-encoded Ed25519 signature of `"JANITOR_PURGE_AUTHORIZED"`.
- Embedded verifying key derived from the thejanitor.app signing key.
- Required by: `janitor clean --token`, `janitor dedup --apply --token`.

### 6.2 Freemium Model

| Operation | Auth Required |
|-----------|--------------|
| `janitor scan` | Free |
| `janitor dedup` (report only) | Free |
| `janitor dedup --apply` | Token required |
| `janitor clean` | Token required |
| `janitor dashboard` | Free |

### 6.3 Price Table

| Tier | Cost | Scope |
|------|------|-------|
| **Bounty Hunter** | **$49/yr** | Individual. Pay-as-you-purge ($1.00/MB deleted). |
| **Sovereign Squad** | **$499/yr** | Team (5 users). Shared PoUD credit pool. |
| **Fiduciary Core** | **Custom** | Enterprise (>10M LOC). Priority support. |

---

## VII. THE DASHBOARD: TUI REPORTING

**Status**: **[COMPLETE]** — Phase 7

- `janitor scan <path>` → saves `.janitor/symbols.rkyv` (rkyv zero-copy).
- `janitor dashboard <path>` → loads registry → launches Ratatui TUI.
- Panels: Sovereign Status bar, symbol count overview, Top 10 largest dead functions.
- Press `q` to exit.

---

## VIII. ROADMAP — ALL PHASES COMPLETE

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Anatomist Core: Tree-sitter parsing, Entity extraction | **[COMPLETE]** |
| **2** | Reference Linking: directed graph, import resolution | **[COMPLETE]** |
| **3** | Dead Symbol Pipeline: 6-stage gate, WisdomRegistry | **[COMPLETE]** |
| **4** | Reaper: UTF-8 SafeDeleter, test fingerprinting | **[COMPLETE]** |
| **5** | Forge: BLAKE3 structural hashing, Safe Proxy Pattern | **[COMPLETE]** |
| **6** | Shadow: symlink overlay, Ghost Protocol, shadow simulation | **[COMPLETE]** |
| **7** | Vault: Ed25519 token gate, TUI dashboard, SOVEREIGN.md refresh | **[COMPLETE]** |

---

## IX. THE GUERRILLA MANDATE

All engineering decisions are constrained by the target hardware (Dell Inspiron 15 3000, 8GB RAM).

1. **Lazy/Streaming Only**: Never collect a full file tree into memory. `walkdir` iterators, `BufReader` line-by-line.
2. **Absolute Paths Only**: No relative path resolution. `dunce::canonicalize` at ingestion boundaries.
3. **Symlinks Over Copies**: Shadow tree uses zero additional disk for source files.
4. **Zero-Copy Serialization**: `rkyv` for all IPC/registry persistence. No `serde_json`, no `protobuf`.
5. **No Batch Allocation**: Process entities one-at-a-time. No `Vec<Entity>` larger than a single file.
6. **Safety**: No `unwrap()`. `anyhow` for binaries, `thiserror` for libs.
7. **UTF-8 Hardened**: All byte-range operations guarded by `str::is_char_boundary()`.

---

**THE CODE IS THE ASSET. THE JANITOR IS THE FIDUCIARY.**
**VERSION: 5.4.0-GOLD**
