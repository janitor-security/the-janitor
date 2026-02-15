# LEGACY HANDOVER: Python v4.2.0 -> Rust v5.x (Project Sovereign Janitor)

**CLASSIFICATION:** Engineering Handover Dossier
**FROM:** Python v4.2.0 (Final Production Build)
**TO:** Next AI Architect (Rust-Native Rewrite)
**DATE:** 2026-02-10
**PURPOSE:** Transfer every hard-won lesson so you start at Level 10, not Level 1.

---

## TABLE OF CONTENTS

1. [Architecture Overview: What Actually Ships](#1-architecture-overview)
2. [The Logic Mapping: Python Module -> Rust Crate](#2-the-logic-mapping)
3. [The Blood-Written Laws: Bugs That Cost Us Weeks](#3-the-blood-written-laws)
4. [The Intelligence Assets: $300 of Harvested Rules](#4-the-intelligence-assets)
5. [The Sovereign Review: Feature Parity Gap Analysis](#5-the-sovereign-review)
6. [The Dead Symbol Detection Pipeline: Complete Specification](#6-the-dead-symbol-detection-pipeline)
7. [The Safe Proxy Pattern: Dedup Refactoring Engine](#7-the-safe-proxy-pattern)
8. [Appendix: File Manifest and Data Formats](#appendix)

---

## 1. ARCHITECTURE OVERVIEW

### What Actually Ships (v4.2.0)

The Python Janitor is a CLI tool (`python -m src.main`) with three commands:

| Command | Purpose | Pipeline |
|---------|---------|----------|
| `audit` | Scan and report dead code | Phases 1-2-3, then display |
| `clean` | Delete dead code with test safety | Phases 1-2-3, then Sandbox + SafeDeleter |
| `dedup` | Find and merge duplicate functions | Phases 1-2-3, then Phase 4 (ChromaDB semantic search + LLM merge) |

### The 3-Phase Core Pipeline (IMMUTABLE)

```
Phase 1: Graph Building (Structure)
  src/analyzer/graph_builder.py -> DependencyGraphBuilder
  Uses: Tree-sitter parser, NetworkX DiGraph
  Output: Directed graph where edge(A,B) = "file A imports file B"

Phase 2: Symbol Extraction (Intelligence)
  src/analyzer/extractor.py -> EntityExtractor
  Uses: Tree-sitter CST traversal
  Output: List[Entity] with name, type, full_text, decorators, qualified_name, base_classes

Phase 3: Reference Linking (Context)
  src/analyzer/reference_tracker.py -> ReferenceTracker
  Uses: Tree-sitter CST, WisdomRegistry, ConfigParser, AdvancedHeuristics
  Output: Dict[symbol_id -> List[Reference]], with dead symbols identified

Phase 4: Semantic Comparison (DEDUP ONLY)
  src/brain/memory.py -> SemanticMemory (ChromaDB + UniXcoder)
  src/brain/refactor.py -> SemanticRefactor (structural hashing, Safe Proxy Pattern)
  Output: RefactorPlan with merged_code using Safe Proxy Pattern
```

### The PHASE_MAP Registry

```python
PHASE_MAP = {
    1: "Graph Building (Structure)",
    2: "Symbol Extraction (Intelligence)",
    3: "Reference Linking (Context)",
    # Phase 4 is ONLY for dedup command (semantic comparison)
}
```

**RULE:** The Rust rewrite MUST preserve this 3-phase numbering. The `dedup`/`forge` equivalent appends Phase 4 as an optional step. Never renumber or merge phases.

---

## 2. THE LOGIC MAPPING

### 2.1 `src/analyzer/` -> `crates/anatomist`

#### Entity Dataclass -> Rust Struct

The core data structure for every function/class in the codebase:

```rust
// Port of src/analyzer/extractor.py Entity dataclass
pub struct Entity {
    pub name: String,
    pub entity_type: EntityType,     // function_definition, class_definition, etc.
    pub full_text: String,           // ENTIRE node text (def keyword -> end of body)
    pub start_line: u32,
    pub end_line: u32,
    pub file_path: PathBuf,
    pub qualified_name: Option<String>,  // "ClassName.method_name"
    pub parent_class: Option<String>,
    pub base_classes: Option<Vec<String>>,
    pub protected_by: Option<String>,    // Which shield saved this symbol
    pub decorators: Option<Vec<String>>, // v4.2.0: ["@property", "@staticmethod"]
}
```

**CRITICAL:** The `full_text` field must capture the ENTIRE CST node text including decorators. The Python version does `source_code[node.start_byte:node.end_byte]`. The Rust version must do the equivalent with tree-sitter byte ranges.

#### ReferenceTracker -> Anatomist Crate

This is the most complex module. Here is the complete reference resolution strategy:

**Symbol ID Format:** `"{file_path}::{qualified_name}"`

**Reference Resolution Strategies (in order of priority):**

1. **Cross-Module Import Matching**: When `target_file` is specified, resolve by matching file path AND symbol name. Uses `SymbolResolver` for compiler-level import path resolution.

2. **Self/Cls Method Matching**: When `class_context` is specified (from `self.method()` or `cls.method()` calls), match methods within the class. Also triggers Inheritance Mapper to protect the entire method family.

3. **Name Matching Fallback**: For top-level calls and heuristic references, match by simple name across all definitions.

**Constructor Shield:** When ANY class is referenced (imported, instantiated), ALL its dunder methods (`__init__`, `__new__`, `__call__`, `__enter__`, `__exit__`, etc.) are implicitly marked as referenced. Implementation: `_activate_constructor_shield()`.

**Inheritance Mapper:** When `BaseClass.method()` is called, ALL overrides in child classes are protected. Uses bidirectional parent/child maps. Implementation: `InheritanceMap` class with `get_method_family()` traversal.

**Type Inference Engine:** Tracks `variable = ClassName()` assignments to resolve `variable.method()` calls. Uses `VariableTypeMap` with scope-aware narrowing for `isinstance()` checks.

#### Implicit Reference Heuristics (THE CRITICAL ONES)

These are the heuristics that prevent false-positive deletions in real-world codebases. **Every single one must be ported to Rust.**

##### Heuristic 1: FastAPI/Pydantic Type Hint Analysis
**File:** `reference_tracker.py:_extract_type_hint_references()`
**Pattern:** `Annotated[str, Depends(get_token)]`
**Logic:** Walk CST for `subscript` nodes where base is `Annotated`. Extract all `Depends()`, `Security()`, `Inject()` call arguments and mark them as references.
**Why:** FastAPI dependency injection only appears in type annotations. Static analysis sees `get_token` as "never called."

##### Heuristic 2: String-to-Symbol Resolution (Celery/Django)
**File:** `reference_tracker.py:_extract_string_symbol_references()`
**Pattern:** `signature('tasks.process_data')`, `get_model('app.ModelName')`
**Logic:** Detect calls to `signature`, `s`, `si`, `task`, `get_model`, `get_task`. Extract the string argument, split by `.`, take the last part, and check if it matches any known definition.
**Why:** Task queues and ORMs reference symbols by string name, invisible to import tracking.

##### Heuristic 3: Qt Auto-Connection Slots
**File:** `reference_tracker.py:_check_qt_auto_connection()`
**Pattern:** Methods matching `on_<object>_<signal>` in classes inheriting from QWidget/QMainWindow/QDialog
**Logic:** Regex `^on_[a-zA-Z0-9]+_[a-zA-Z0-9]+$`. Check inheritance map for Qt base classes OR file content for PySide/PyQt imports.
**Why:** Qt's `connectSlotsByName` auto-connects these methods at runtime. Never explicitly called.

##### Heuristic 4: SQLAlchemy Metaprogramming
**File:** `reference_tracker.py:_check_sqlalchemy_metaprogramming()`
**Pattern:** `@declared_attr`, `@hybrid_property`, `__abstract__`, `__tablename__`, `__table_args__`
**Logic:** Check entity `full_text` for decorator strings. Check entity `name` against special SQLAlchemy class variables.
**Why:** SQLAlchemy metaclass magic reads these at class creation time.

##### Heuristic 5: Inheritance Context (ORM Lifecycle)
**File:** `reference_tracker.py:_check_inheritance_context()`
**Pattern:** `save()`, `delete()`, `update()`, `create()`, `get()`, `filter()` in classes inheriting from Model/Base/Document
**Logic:** Check if method name is in the context-sensitive set AND if parent class inherits from ORM bases (`Model`, `Base`, `Document`, `db.Model`).
**Why:** Django/SQLAlchemy models override these from base classes. They're called by the framework, not by user code.

##### Heuristic 6: Pydantic v2 Alias Generator Fields
**File:** `reference_tracker.py:_check_pydantic_alias_generator()`
**Pattern:** Fields in `BaseModel` subclasses with `model_config = ConfigDict(alias_generator=to_camel)`
**Logic:** Check if entity is a class variable, parent class exists, file imports `BaseModel`/`pydantic`, and file contains `alias_generator` + `model_config`.
**Why:** Incoming JSON uses camelCase. Python model uses snake_case. Field looks unused.

##### Heuristic 7: FastAPI Dependency Overrides
**File:** `reference_tracker.py:_check_fastapi_dependency_override()`
**Pattern:** `app.dependency_overrides[get_current_user] = override_auth`
**Logic:** Check if function's file contains `dependency_overrides` and if the function name appears in a `dependency_overrides[...] = function_name` pattern.
**Why:** Override functions are assigned to a dict, never called directly. Common in test files.

##### Heuristic 8: pytest Fixture Detection
**File:** `reference_tracker.py:_check_pytest_fixture()`
**Pattern:** `@pytest.fixture` or `@fixture` decorators, or functions in `conftest.py`
**Logic:** Check entity `full_text` for fixture decorators. Also protect all functions in conftest.py files that import pytest.
**Why:** Fixtures are injected by name matching, never explicitly called.

##### Heuristic 9: Pydantic Forward References
**File:** `heuristics.py:apply_pydantic_forward_ref_heuristic()`
**Pattern:** `x: List['User']` (string literal in type annotation)
**Logic:** Walk CST for `type` nodes containing `string` children. Strip quotes, mark the class name as a reference.
**Why:** Forward references use strings that resolve to real classes at runtime.

##### Heuristic 10: Lifespan/Teardown Detection (FastAPI)
**File:** `heuristics.py:apply_lifespan_teardown_heuristic()`
**Pattern:** `@asynccontextmanager` functions with code after `yield`
**Logic:** Find `decorated_definition` nodes with `@asynccontextmanager`. Locate the `yield` statement. Mark ALL identifiers used AFTER the yield as immortal.
**Why:** FastAPI lifespan functions have startup code before yield and teardown code after. The teardown code is invisible to normal reference analysis.

##### Heuristic 11: Polymorphic ORM (SQLAlchemy)
**File:** `heuristics.py:apply_polymorphic_orm_heuristic()`
**Pattern:** Classes with `__mapper_args__` containing `polymorphic_identity`
**Logic:** Find class definitions containing `__mapper_args__` with `polymorphic_identity`. Mark the entire class and all its methods as immortal.
**Why:** SQLAlchemy polymorphic classes are loaded by the ORM mapper. The subclass "looks unused" but is resolved at query time.

### 2.2 `src/reaper/` -> `crates/reaper`

#### Test Fingerprinting (THE SAFETY MECHANISM)

This is the logic that prevents the clean command from breaking codebases. **Do not skip this.**

```
ALGORITHM: Test Fingerprinting

1. BASELINE:
   - Run tests on untouched repo
   - Parse output with _parse_failures() to get Set<TestID>
   - This is the baseline_failures_set

2. AFTER EACH DELETION:
   - Run tests again
   - Parse output to get current_failures_set
   - Compute: new_failures = current_failures - baseline_failures_set

3. VERDICT:
   - If new_failures is EMPTY -> Deletion is SAFE (no new breakage)
   - If new_failures is NOT EMPTY -> ROLLBACK immediately
   - SPECIAL CASE: pytest exit code 2 = Collection Error -> ALWAYS rollback
     (imports failed, syntax errors - regex might miss these)
```

**Failure Parsing Regexes (polyglot):**
```
Python/Pytest:  r'(?:FAILED|ERROR) ([^\s]+::[^\s]+)'        # FAILED tests/test_file.py::test_name
Python/Collect: r'(?:FAILED|ERROR) ([^\s]+\.py)(?:\s|$)'    # ERROR src/file.py (no ::)
JS/Mocha/Jest:  r'^\s*(?:\d+\)|✖|●)\s+(.+?)$'  (MULTILINE) # "1) test name" or "● test name"
```

**The `--force` Flag:** Added in v4.2.0 to bypass rollback for environmental baseline errors (Windows symlink failures). When `--force` is True, test failures print a warning but do NOT trigger rollback or exit.

#### Safe Deletion Pattern

Files are NEVER permanently deleted. The flow is:

```
1. SafeDeleter.delete(file_path, reason)
   -> Generate unique deletion_id (secrets.token_hex)
   -> Create .janitor_trash/{deletion_id}/ directory
   -> shutil.move(file -> trash directory)
   -> Record in Manifest (JSON log with original_path, trash_path, file_hash, timestamp)
   -> Return deletion_id

2. SafeDeleter.restore(deletion_id)
   -> Read manifest entry
   -> shutil.move(trash -> original_path)
   -> Verify file hash matches

3. SafeDeleter.restore_all(deletion_ids)
   -> Bulk restore for rollback scenarios
```

**Rust Equivalent:** The `crates/reaper` must implement this same trash-and-restore pattern. The SOVEREIGN.md's "Symlink Shadow Tree" concept is fine for the advanced version, but the MVP MUST support safe rollback.

### 2.3 `src/brain/` -> `crates/forge`

#### The Safe Proxy Pattern (Dedup Refactoring)

When two functions are >80% similar, the dedup command generates merged code using this pattern:

```python
# BEFORE: Two duplicate functions
def calculate_price(items):
    total = sum(item.price for item in items)
    return total * 1.1

def compute_total(products):
    total = sum(p.price for p in products)
    return total * 1.1

# AFTER: Safe Proxy Pattern
def _merged_logic(items):
    """Internal helper with shared logic."""
    total = sum(item.price for item in items)
    return total * 1.1

def calculate_price(items):
    return _merged_logic(items)

def compute_total(products):
    return _merged_logic(products)
```

**Key Safety Rules (from v4.2.0 LLM Prompt):**

1. Original function signatures MUST be preserved exactly (zero call-site changes)
2. The `_merged_logic` helper is INTERNAL ONLY (never exported, never decorated)
3. ALL decorators (`@property`, `@staticmethod`, `@lru_cache`) stay on the wrapper functions
4. Private members (`self.__var`) must be passed as explicit arguments to avoid Python name mangling
5. The wrapper functions must be thin pass-throughs (1-2 lines max)

#### Global State Leak Detection (v4.2.0)

The `_check_global_state_leak()` static analyzer in `refactor.py` validates merged code:

```
ALGORITHM:
1. Parse merged code with ast.parse()
2. Find helper function (name starts with '_', contains 'merge' or 'shared')
3. Extract all parameter names from function signature
4. Walk AST for all Name nodes with Load context
5. Check each variable against:
   - Function parameters (SAFE)
   - SAFE_GLOBALS whitelist: builtins, os, sys, json, time, datetime, math, re, Path, typing (SAFE)
   - Everything else = UNSAFE GLOBAL STATE LEAK
6. If ANY unsafe refs detected -> Reject the refactor plan
```

**Rust Port:** The `crates/forge` crate must implement equivalent validation. Use tree-sitter to parse the merged output and verify no unbound variables exist.

#### AST Structural Pre-Filter

Before sending to LLM, the `ASTStructuralAnalyzer` compares control-flow profiles:

```
Count: {if, for, while, return} nodes in each function
Divergence = sum(abs(count1[k] - count2[k])) / avg(total_nodes)
If divergence > 0.20 (20%) -> REJECT (structurally incompatible)
```

This prevents merging functions that are textually similar but logically different.

---

## 3. THE BLOOD-WRITTEN LAWS

### 3.1 Windows Pathing and Encoding Nightmares

**BUG 1: UTF-16 BOM Crashes**
Windows files sometimes have `\xef\xbb\xbf` (UTF-8 BOM) or UTF-16 LE BOMs. The Python version handles this with `encoding='utf-8', errors='ignore'` everywhere. Tree-sitter expects raw bytes.

**RUST DIRECTIVE:** Use `std::fs::read()` (raw bytes) for tree-sitter input. Use `String::from_utf8_lossy()` for display. NEVER assume UTF-8 without a fallback path.

**BUG 2: cp1252 Console Crashes**
Windows Command Prompt defaults to cp1252 encoding. Rich library emoji/Unicode spinners crash with `UnicodeEncodeError`. We built `SafeConsole` that:
- Detects UTF-8 capability via `sys.stdout.encoding`
- Replaces Unicode icons with ASCII equivalents on non-UTF-8 terminals
- Forces Rich's `legacy_windows=True` mode
- Uses ASCII spinner (`line` spinner: `- \ | /`) instead of Unicode dots

**RUST DIRECTIVE:** Use `indicatif` with ASCII-only progress bars by default. Detect `TERM`/code page and only enable Unicode if confirmed. The `console` crate handles some of this, but test on Windows `cmd.exe` specifically.

**BUG 3: Path Separator Hell (`\` vs `/`)**
Tree-sitter CST provides file paths. NetworkX graph stores paths as strings. Python's `Path.resolve()` normalizes, but string comparisons break when mixing `/` and `\`.

The Python version normalizes with `Path(x).resolve()` before ALL comparisons. Critical locations:
- `_resolve_module_to_file()` in ReferenceTracker
- Symbol ID generation: `f"{entity.file_path}::{qualified_name}"`
- Cross-file reference matching

**RUST DIRECTIVE:** Use `std::path::PathBuf` everywhere. Use `.canonicalize()` for comparisons. NEVER store paths as raw strings. Use `dunce::canonicalize()` on Windows to avoid `\\?\` prefix issues.

### 3.2 Dependency Bloat: Why We Rejected ChromaDB/Torch

The `dedup` command uses ChromaDB + UniXcoder (microsoft/unixcoder-base) for semantic similarity. This pulled in:
- `chromadb` (SQLite + HTTP server)
- `torch` (PyTorch CPU = ~2GB)
- `transformers` (HuggingFace = ~500MB)
- `sentence-transformers` (wrapper)
- `numpy`, `scipy`, etc.

**Total Docker image: 14GB.** For a dead-code detector.

The Python code also monkey-patches ChromaDB telemetry (PostHog) at import time because it phones home by default.

**RUST DIRECTIVE:** The Sovereign plan calls for `sqlite-vec` (SQLite with vector extensions) and structural hashing instead. This is the correct approach. Do NOT port ChromaDB. Instead:
1. Use `tree-sitter` CST to extract structural features (control flow shape, parameter count, return type)
2. Hash the structural features with BLAKE3
3. Store hashes in SQLite via `rusqlite`
4. Compare by Hamming distance on structural hashes
5. Only invoke LLM for merge generation, not for similarity detection

### 3.3 Tree-sitter Binding Hell

**The PyCapsule Crash (v0.22 -> v0.25):**
Tree-sitter Python bindings changed their API between versions. Before v0.25:
```python
parser.set_language(language)  # OLD API - crashes on v0.25
```
After v0.25:
```python
language = Language(tspython.language())  # Returns PyCapsule
parser.language = language  # NEW API
```

The transition caused cryptic `TypeError: argument is not a Language` errors. The fix required pinning exact versions in requirements.txt.

**RUST DIRECTIVE:** Tree-sitter Rust bindings are more stable, but version mismatches between `tree-sitter` (core) and `tree-sitter-python`/`tree-sitter-javascript` (grammars) still cause linking errors. Pin exact versions in `Cargo.toml`. Test grammar loading in CI before anything else. The current workspace uses:
```toml
tree-sitter = "0.24"
tree-sitter-rust = "0.23"
```
You will also need: `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript`. Verify ABI compatibility between the core and grammar crates before writing any parsing code.

### 3.4 The SQLite Cache Concurrency Issue

**Bug:** Multiple Janitor runs on the same project simultaneously would corrupt the SQLite cache (`.janitor_cache/analysis.db`). Python's `sqlite3` module doesn't handle concurrent writes gracefully.

**Python Mitigation:** Use `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000`.

**RUST DIRECTIVE:** Use `rusqlite` with WAL mode enabled. Consider `r2d2` connection pooling if the Rust version supports concurrent analysis of multiple projects.

### 3.5 The `conftest.py` False Positive

**Bug:** Functions in pytest `conftest.py` files were being marked as dead because they're injected by name, never explicitly imported.

**Fix:** The `_check_pytest_fixture()` heuristic protects ALL functions in `conftest.py` files that contain `pytest` or `@fixture` in any form.

**RUST DIRECTIVE:** Port this exact heuristic. Check file name for `conftest.py`. If found and file contains pytest references, protect all functions.

---

## 4. THE INTELLIGENCE ASSETS

### 4.1 Wisdom Rules Location and Format

The rules live at `rules/` in the project root:

```
rules/
  community/                    # MIT Licensed - always shipped
    immortality_rules.json      # Decorator-based patterns (FastAPI, Flask, Django, Typer, Click, Celery, etc.)
    meta_patterns.json          # Suffix/prefix/exact patterns (test_, _test, setUp, tearDown, etc.)
    js_wisdom.json              # JavaScript/TypeScript framework patterns
  premium/                      # Proprietary - $300 invested in harvesting
    fastapi.json                # FastAPI middleware, exception handlers, ASGI
    django.json                 # Django views, middleware, signals, management commands
    celery.json                 # Celery tasks, signals, beat schedules
    sqlalchemy.json             # SQLAlchemy mappers, events, hybrid properties
    pydantic.json               # Pydantic validators, model_config, field aliases
    airflow.json                # Airflow DAGs, operators, hooks
    aws_cloud.json              # AWS Lambda handlers, SAM templates
    cloud.json                  # Cloud function handlers
    marshmallow.json            # Marshmallow schemas, fields, pre/post hooks
    invenio.json                # Invenio framework patterns (CERN)
    graphene_strawberry.json    # GraphQL resolvers, mutations, subscriptions
```

### 4.2 JSON Format Specification

There are THREE JSON formats used. The Rust `WisdomRegistry` must handle all three via `serde_json`.

**Format 1: Immortality Rules (decorator-based)**
```json
{
  "immortality_rules": [
    {
      "framework": "FastAPI",
      "patterns": ["@app.get", "@app.post", "@app.websocket"],
      "type": "decorator",
      "action": "PROTECT_FUNCTION"
    }
  ]
}
```

**Format 2: Meta Patterns (suffix/prefix/exact/syntax)**
```json
{
  "exact_matches": ["dispatch", "__call__", "lifespan"],
  "suffix_matches": [".middleware", "Middleware", "Response"],
  "prefix_matches": ["test_", "setUp"],
  "syntax_markers": ["BaseHTTPMiddleware", "add_middleware"]
}
```

**Format 3: Framework-Keyed Rules (JS/TS)**
```json
{
  "React": {
    "syntax_markers": ["useEffect", "useState", "useCallback"]
  },
  "Express": {
    "syntax_markers": ["router.get", "app.listen"]
  }
}
```

### 4.3 Matching Algorithm

The `WisdomRegistry.is_immortal()` method checks in this order:

```
1. Exact match:    symbol_name == pattern
2. Prefix match:   symbol_name.starts_with(pattern)
                   ALSO check after last '.' for qualified names
3. Decorator:      pattern IN entity.full_text (e.g., "@app.get" in source)
4. Suffix match:   pattern IN any decorator line of full_text
5. Syntax marker:  pattern IN entity.full_text
6. Dunder method:  name starts/ends with __ and len > 4
7. Property/etc:   @property, @staticmethod, @classmethod in full_text
```

**Rust Implementation:** Build `HashMap<String, (String, Tier)>` lookup tables at startup. Use `phf` (perfect hash function) for the exact-match tables if performance is critical. For syntax markers, use `memchr` or `aho-corasick` for multi-pattern string searching.

### 4.4 Library Mode vs App Mode

**Library Mode** (`--library` flag):
- ALL public symbols (not starting with `_`) are immortal
- Rationale: Libraries expose APIs that external consumers call. We can't see those consumers.
- Implementation: `_is_public_symbol()` check at Stage 2.5 of the pipeline

**App Mode** (default):
- Only symbols with actual cross-file references survive
- Enables aggressive tree-shaking of unused exports
- For JS/TS: Only `export default` is protected. Named exports CAN be dead.

**RUST DIRECTIVE:** Expose this as a CLI flag: `--library` for library mode, default is app mode. The logic is simple: if library mode and symbol name doesn't start with `_`, protect it.

---

## 5. THE SOVEREIGN REVIEW

### 5.1 Current SOVEREIGN.md Assessment

The SOVEREIGN.md describes an ambitious architecture including eBPF probes, LLVM-IR analysis, Z3 SMT solving, post-quantum cryptography, and DNA-based archival. Here is the reality check:

| SOVEREIGN Feature | Python Equivalent | Port Priority | Assessment |
|---|---|---|---|
| Shadow Tree (symlink VFS) | `.janitor_trash/` directory | LOW | Python uses simple file moves. Symlinks add complexity for MVP. |
| Agentic Slop Harvesting | `dedup` command (ChromaDB + LLM) | HIGH | Core revenue feature. Port structural hashing, NOT ChromaDB. |
| Amnesia Protocol | Not implemented | LOW | Variable renaming + comment stripping. Nice-to-have. |
| Lazarus Linker (kill_list.ld) | `clean` command (file/symbol deletion) | HIGH | Core functionality. Port SafeDeleter + TestSandbox. |
| PQC Cryptography | Not implemented | NONE | Not needed for MVP. No customer has asked for this. |
| Notary Kernel (LSM) | Not implemented | NONE | eBPF LSM hooks are Linux-only. Breaks Windows/macOS. |
| Boltzmann Gate (VRM) | Not implemented | NONE | Thermodynamic voltage starvation is not a real product feature. |
| Metabolic Hypervisor | Not implemented | NONE | Microfluidic thermal redirect is not a real product feature. |
| DNA Archival | Not implemented | NONE | Enzymatic synthesis is not a real product feature. |
| Datalog Engine | Not implemented | MEDIUM | Global reachability analysis via Datalog IS valuable. Consider `crepe` crate. |
| Z3 SMT Solver | Not implemented | LOW | Local proofs are interesting but not needed for dead-code detection. |

### 5.2 What MUST Be Ported (Revenue-Critical)

1. **`audit` command** -> `crates/anatomist` + `crates/cli`
   - 3-phase pipeline (Graph -> Extract -> Link)
   - ALL implicit reference heuristics (Section 2.1)
   - WisdomRegistry with JSON rule loading
   - ConfigParser for infrastructure-as-code
   - SQLite caching for repeat audits

2. **`clean` command** -> `crates/reaper` + `crates/cli`
   - Test Fingerprinting (baseline vs new failures)
   - SafeDeleter (trash + restore + manifest)
   - Symbol remover (surgically remove functions from files)
   - `--force` flag for environmental baseline errors

3. **`dedup` command** -> `crates/forge` + `crates/cli`
   - Structural hash comparison (replace ChromaDB)
   - Safe Proxy Pattern code generation
   - AST structural pre-filter (control-flow divergence)
   - Global state leak detection
   - Decorator preservation (v4.2.0)

4. **Wisdom Rules** -> Embedded in `crates/anatomist` or separate `crates/wisdom`
   - Load all JSON from `rules/community/` and `rules/premium/`
   - Support all three JSON formats
   - Community/Premium tier distinction

### 5.3 What Can Be Skipped for MVP

- eBPF probes (Phases 2, 9 of SOVEREIGN roadmap)
- LLVM-IR analysis
- Z3 SMT proofs
- Post-quantum cryptography
- Symlink shadow trees
- Amnesia Protocol
- DNA archival
- Insurance Bridge API
- Anything in Sections VI-IX of SOVEREIGN.md

---

## 6. THE DEAD SYMBOL DETECTION PIPELINE

This is the complete, ordered pipeline from `find_dead_symbols()`. Every stage is a gate. If a symbol passes a gate, it skips to the next. If it fails all gates, it's DEAD.

```
STAGE 0: CONTEXTUAL IMMORTALITY
  IF file_path contains any of: tests/, examples/, docs_src/, sandbox/, bin/, docs/,
     requirements/, scripts/, tutorial/, benchmarks/
  THEN -> PROTECTED (reason: "Directory: {dir_name}/")

STAGE 1: CROSS-FILE REFERENCES
  IF symbol has ANY external references (from different files) -> ALIVE
  IF symbol has ANY internal references (from same file) -> ALIVE

STAGE 2: FRAMEWORK/META IMMORTALITY (WisdomRegistry)
  IF WisdomRegistry.is_immortal(name, full_text, language) returns True
  THEN -> PROTECTED (reason: "[Premium Protection] Rule: {framework}" or "Rule: {framework}")

STAGE 2.5: LIBRARY MODE PUBLIC SYMBOL SHIELD
  IF --library mode AND symbol doesn't start with '_'
  THEN -> PROTECTED (reason: "Library Mode")

STAGE 2.6: PACKAGE EXPORT SHIELD
  IF symbol is imported into any __init__.py (tracked via _track_package_export)
  THEN -> PROTECTED (reason: "Package Export")

STAGE 2.7: CONFIG FILE REFERENCES
  IF symbol name appears in YAML/JSON/Python config files
     (serverless.yml, template.yaml, Django settings, Docker compose, Airflow DAGs)
  THEN -> PROTECTED (reason: "[Premium] Config Reference: {reason}")

STAGE 2.8: METAPROGRAMMING DANGER SHIELD
  IF symbol's file contains: getattr(, setattr(, hasattr(, delattr(,
     eval(, exec(, compile(, importlib., __import__(, type(, .__dict__
  THEN -> PROTECTED (reason: "[Premium] Metaprogramming Danger")

STAGE 3: LIFECYCLE METHODS
  Dunder methods are protected by Constructor Shield (applied during reference collection)
  IF we reach here with a dunder method -> its parent class is unused -> DEAD

STAGE 4: ENTRY POINT
  IF symbol name is 'main' OR full_text contains '@app.command' or '@app.callback'
  THEN -> PROTECTED (reason: "Entry Point")

STAGE 4.1-4.3: ENTERPRISE HEURISTICS
  Qt Auto-Connection Slots      -> "[Premium] Qt Auto-Connection Slot"
  SQLAlchemy Metaprogramming     -> "[Premium] SQLAlchemy Metaprogramming"
  ORM Inheritance Context        -> "[Premium] ORM Lifecycle Method"

STAGE 4.4-4.6: ADVANCED FRAMEWORK HEURISTICS
  Pydantic v2 Alias Generator    -> "[Premium] Pydantic v2 Alias Generator"
  FastAPI Dependency Overrides   -> "[Premium] FastAPI Dependency Override"
  pytest Fixture Detection       -> "[Premium] pytest Fixture"

STAGE 5: GREP SHIELD (optional, --grep-shield flag)
  IF symbol name appears as a string in ANY other file in the project
  THEN -> PROTECTED (reason: "Found in global string search")
  WARNING: Can be slow on codebases with 3000+ files.

FINAL: DEAD
  Symbol passed all shields with ZERO references -> Append to dead_symbols list
```

### Heuristics Applied During Reference Extraction (Phase 3)

These run during `extract_references_from_file()`, NOT during `find_dead_symbols()`:

```
Python Files:
  - Pydantic Forward Reference Heuristic (string literals in type annotations)
  - Lifespan Teardown Heuristic (@asynccontextmanager post-yield identifiers)
  - Polymorphic ORM Heuristic (__mapper_args__ with polymorphic_identity)

JavaScript/TypeScript Files:
  - React Hook Heuristic (useEffect/useCallback/useMemo dependency arrays)
  - Express Route Heuristic (router.get/app.post handler functions)
  - Export Heuristic (Library mode: protect ALL exports. App mode: only export default)
```

---

## 7. THE SAFE PROXY PATTERN

### The LLM Prompt (Condensed)

The merge generation prompt used by the Safe Proxy Pattern engine:

```
RULES:
1. Create internal helper function (_merged_logic or _shared_impl)
2. PRESERVE original function signatures EXACTLY
3. Original functions become thin wrappers calling the helper
4. Helper function is PRIVATE (starts with _)
5. ALL imports needed by both functions must be present
6. Include BOTH original function names as wrappers
7. Include ALL required imports at top of response
8. Maintain variable scope - no global variable leaks

METADATA PRESERVATION (v4.2.0):
9. PRESERVE all decorators on wrapper functions
10. Private attributes (self.__var): Pass as explicit arguments to helper
    (avoids Python name mangling: _ClassName__var)
```

### Rust Forge Crate Strategy

For the Rust rewrite, the LLM integration should:
1. Apply the same prompt structure with decorator context
2. Send the same prompt structure with decorator context
3. Validate output with the same structural checks:
   - AST-parse the merged code
   - Verify helper function exists
   - Verify both wrapper functions exist
   - Run global state leak detection
   - Verify decorator preservation
4. Use `syn` crate for Rust AST validation if analyzing Rust code

---

## APPENDIX

### A. File Manifest (Python v4.2.0)

```
src/
  __init__.py
  main.py                     # CLI entry point (Typer), 3-phase pipeline, audit/clean/dedup commands
  config.py                   # Version string, configuration constants
  analyzer/
    __init__.py
    parser.py                 # Tree-sitter language detection and parsing
    extractor.py              # Entity/Import extraction from CST
    graph_builder.py          # NetworkX dependency graph (Phase 1)
    reference_tracker.py      # Reference linking + dead symbol detection (Phase 3) [2010 lines]
    resolver.py               # Compiler-level import path resolution
    wisdom_registry.py        # JSON rule loading and matching
    config_parser.py          # YAML/JSON/Python config file scanning
    heuristics.py             # Python advanced heuristics (Pydantic, FastAPI, SQLAlchemy)
    js_heuristics.py          # JavaScript/TypeScript heuristics (React, Express)
    js_import_tracker.py      # JS import alias tracking
    orphan_detector.py        # Dead file detection (zero incoming graph edges)
    cache.py                  # SQLite cache for repeat audits
  brain/
    __init__.py
    memory.py                 # ChromaDB + UniXcoder semantic similarity [DO NOT PORT - use structural hashing]
    llm.py                    # Merge engine [DO NOT PORT — replaced by structural hashing]
    refactor.py               # Safe Proxy Pattern generation + validation
  reaper/
    __init__.py
    sandbox.py                # Test Fingerprinting + baseline comparison
    safe_delete.py            # Trash-based file deletion with restore
    manifest.py               # JSON deletion manifest
    symbol_remover.py         # Surgical function/class removal from files
    js_remover.py             # JavaScript symbol removal
  utils/
    __init__.py
    safe_console.py           # Windows Unicode safety wrapper
    logger.py                 # Terminal sanitization utilities
    ui.py                     # Progress bars and display utilities
rules/
  community/                  # 3 JSON files (MIT)
  premium/                    # 11 JSON files (Proprietary)
```

### B. SQLite Cache Schema (analysis.db)

```sql
-- File hash cache (Phase 1 + 2 fast path)
CREATE TABLE file_cache (
    file_path TEXT PRIMARY KEY,
    file_hash TEXT,
    last_modified REAL,
    dependencies TEXT,        -- JSON array of import paths
    entities TEXT,            -- JSON array of serialized Entity objects
    references TEXT           -- JSON array of serialized Reference objects
);

-- Metaprogramming danger cache
CREATE TABLE metaprogramming_cache (
    file_path TEXT PRIMARY KEY,
    is_dangerous INTEGER,     -- 0 or 1
    file_hash TEXT
);

-- Full analysis result cache (O(1) fast path)
CREATE TABLE analysis_cache (
    project_hash TEXT PRIMARY KEY,
    dead_symbols TEXT,        -- JSON array
    orphan_files TEXT,        -- JSON array
    timestamp REAL
);
```

### C. Existing Rust Crate Stubs

The following Rust code already exists in `the-janitor-rust/`:

**`crates/common/src/lib.rs`:** Defines `ClrFact` (Definition, Reference, SlopMarker), `ClrGraph`, `TemporalDebtBond`, and traits `Anatomist`, `Reaper`, `Oracle`. Uses `rkyv` for zero-copy serialization.

**`crates/cli/src/main.rs`:** Placeholder CLI with `clap`.

**`crates/supervisor/src/lib.rs`:** Supervisor crate (authentication/licensing).

**`crates/shadow/src/lib.rs` + `interceptor.rs`:** VFS overlay stubs.

### D. Critical Rust Dependencies

```toml
# KEEP (needed for MVP)
tree-sitter = "0.24"       # CST parsing
clap = "4.5"               # CLI
anyhow = "1.0"             # Error handling (binaries)
serde = "1.0"              # JSON rule deserialization
serde_json = "..."         # WisdomRegistry JSON loading
rusqlite = "..."           # Cache (replace Python sqlite3)
blake3 = "1.5"             # Structural hashing (replace ChromaDB)
tokio = "1.40"             # Async runtime (for LLM API calls)

# EVALUATE (may be needed)
petgraph = "..."           # Dependency graph (replace NetworkX)
indicatif = "..."          # Progress bars (replace Rich)
console = "..."            # Terminal detection (replace SafeConsole)
dunce = "..."              # Windows path canonicalization
aho-corasick = "..."       # Multi-pattern string matching (WisdomRegistry)
reqwest = "..."            # HTTP client
regex = "..."              # Test failure parsing

# DROP (from current Cargo.toml - not needed for MVP)
z3 = "0.12"                # SMT solver - not needed
souffle-rs = "0.2"         # Datalog - nice to have, not MVP
llvm-sys = "181"           # LLVM-IR analysis - not needed
plonky3 = "..."            # ZK-SNARKs - not needed
pqcrypto-dilithium = "0.4" # PQC - not needed
libbpf-rs = "0.24"         # eBPF - not needed
aya = "0.13"               # eBPF - not needed
rkyv = "0.7"               # Zero-copy - evaluate if needed for IPC
```

### E. OS-Agnostic Checklist

Before shipping the Rust version, verify on all three platforms:

- [ ] Path handling: `PathBuf` everywhere, `dunce::canonicalize()` on Windows
- [ ] File encoding: Handle UTF-8 BOM, UTF-16, cp1252 gracefully
- [ ] Console output: ASCII-only progress bars on Windows cmd.exe
- [ ] Tree-sitter grammar loading: Test on Windows, macOS, Linux
- [ ] SQLite WAL mode: Works on all platforms
- [ ] Trash directory: `.janitor_trash/` with platform-appropriate permissions
- [ ] Test runner: Detect pytest, npm test, cargo test based on project files
- [ ] Line endings: Handle CRLF (Windows) vs LF (Unix) in source files
- [ ] Process spawning: `std::process::Command` with proper shell detection
- [ ] Symlinks: Do NOT rely on symlinks. Windows requires admin or developer mode.

---

**END OF HANDOVER**

**The code is the asset. The intelligence is in the heuristics. Port them faithfully.**
