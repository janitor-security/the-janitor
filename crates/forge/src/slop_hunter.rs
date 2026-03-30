//! # Slop Hunter — Structural Security Antipattern Detection
//!
//! Detects security-critical and architectural antipatterns in source file bytes.
//! The Janitor is a structural security hypervisor, not a stylistic linter —
//! only rules with direct security or architectural impact are active.
//!
//! ## Active Rules
//!
//! | Language | Pattern | Description |
//! |----------|---------|-------------|
//! | YAML | Wildcard Kubernetes host | `VirtualService`/`Ingress` with `hosts: ["*"]` — exposes all routes publicly |
//! | C/C++ | `gets()`, `strcpy()`, `sprintf()`, `scanf()` calls | Removed in C11 or known buffer-overflow sources |
//! | C/C++ | `strcpy()` / `sprintf()` / `scanf()` | Unsafe string functions (CERT-C) |
//! | HCL/Terraform | Open CIDR `0.0.0.0/0` | Wildcard ingress rule exposes resource to the entire internet |
//! | HCL/Terraform | `public-read` S3 ACL | Public S3 bucket exposes data to the internet |
//! | Python | `subprocess` with `shell=True` | Potential shell injection when combined with string concatenation |
//! | JS/TS | `innerHTML` assignment | Direct DOM XSS vector — use `textContent` or sanitize input |
//! | JS/TS | `.__proto__`, `["__proto__"]`, `[constructor][prototype]` | Prototype pollution via direct proto key access (Layer A AhoCorasick) |
//! | JS/TS | `_.merge`, `Object.assign` etc. with `JSON.parse`/`body`/`query` arg | Prototype pollution merge sink (Layer B AST walk, Phase 3 Tier 1) |
//! | Python | `exec`, `pickle.loads/load`, `os.system`, `__import__` | Dangerous call AST walk — Phase 2 (Tier 1); `eval` at Warning, suppressed in `test_*` scope |
//! | Java | `ObjectInputStream.readObject`, `XMLDecoder.readObject`, `Runtime.getRuntime().exec`, `InitialContext.lookup` (dynamic only) | Deserialization gadget chains + JNDI — Phase 2 AST walk (Tier 1) |
//! | Java | `new ObjectInputStream(`, `XStream().fromXML(`, `.readObject()`, `Runtime.getRuntime().exec(`, `InitialContext().lookup(` | Same patterns — Phase 1 AhoCorasick (Tier 2) backup |
//! | C# | `TypeNameHandling.Auto/All/Objects` in assignment, `new BinaryFormatter()` | Unsafe deserialization — Phase 3 AST walk (Tier 1); `TypeNameHandling.None` explicitly excluded |
//! | C# | `new BinaryFormatter()`, `TypeNameHandling.Auto/All/Objects`, `LosFormatter`, `ObjectStateFormatter` | Same patterns — Phase 1 AhoCorasick (Tier 2) backup |
//!
//! ## Removed Rules (v7.6.0 — Linter Annihilation)
//!
//! The following language-specific stylistic rules were removed because they
//! generated high false-positive volumes at scale (vacuous `unsafe` at FFI
//! boundaries, goroutine closures in idiomatic Go, `eval()` in test harnesses).
//! The engine now delegates signal detection to the NCD Entropy Gate, Unicode
//! Gate, LotL Hunter, LSH Swarm Collider, and Necrotic Pruning Matrix.
//!
//! - Python: hallucinated imports
//! - Rust: vacuous `unsafe` blocks
//! - Go: goroutine closure traps
//! - Java: empty catch blocks, `System.out.println`
//! - C#: `async void` methods
//! - Bash: unquoted variable expansions
//! - JavaScript / TypeScript: `eval()` calls
//!
//! ## Usage
//! ```ignore
//! let findings = slop_hunter::find_slop("yaml", source_bytes);
//! for f in findings {
//!     eprintln!("[SLOP] {}:{}-{}", f.description, f.start_byte, f.end_byte);
//! }
//! ```

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::OnceLock;
use std::time::Instant;

use aho_corasick::{AhoCorasick, MatchKind};
use tree_sitter::{Language, Node};

use crate::metadata::{DOMAIN_ALL, DOMAIN_FIRST_PARTY};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Severity tier governing how many points a [`SlopFinding`] contributes.
///
/// All currently active rules fire at [`Severity::Critical`].  `Warning` and
/// `Lint` are retained in the public API for backwards compatibility.
///
/// | Tier           | Points |
/// |----------------|--------|
/// | `KevCritical`  | 150    |
/// | `Exhaustion`   | 100    |
/// | `Critical`     |  50    |
/// | `Warning`      |  10    |
/// | `Lint`         |   0    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// CISA Known Exploited Vulnerability — contributes 150 points.
    ///
    /// Fired for patterns confirmed to be actively exploited in the wild per the
    /// CISA KEV catalog: SQL injection via string concatenation, SSRF via dynamic
    /// URL construction, and path traversal via string concatenation.  This tier
    /// is above [`Exhaustion`][Self::Exhaustion] because confirmed exploitation
    /// evidence elevates the finding above a speculative DoS risk.
    KevCritical,
    /// Parser exhaustion — contributes 100 points.
    ///
    /// Fired when the tree-sitter parse of a single file exceeds
    /// [`PARSER_TIMEOUT_MICROS`] (500 ms).  Indicates a probable AST Bomb:
    /// an adversarially crafted deeply-nested source file designed to exhaust
    /// the parser and stack-overflow the GitHub Action runner.
    Exhaustion,
    /// Security-critical finding — contributes 50 points.
    ///
    /// Examples: Kubernetes wildcard hosts, open-world CIDR rules, `gets()` calls,
    /// Unicode injection, LotL execution.
    Critical,
    /// Code-quality warning — contributes 10 points.
    Warning,
    /// Style lint — contributes 0 points.
    Lint,
}

impl Severity {
    /// Points contributed to [`crate::slop_filter::SlopScore::antipattern_score`]
    /// by one finding of this severity.
    pub fn points(self) -> u32 {
        match self {
            Self::KevCritical => 150,
            Self::Exhaustion => 100,
            Self::Critical => 50,
            Self::Warning => 10,
            Self::Lint => 0,
        }
    }
}

/// Hard timeout applied to every tree-sitter `parse()` call (500 ms).
///
/// Prevents adversarially crafted deeply-nested AST Bombs from exhausting the
/// parser and stack-overflowing the GitHub Action runner.  When `parse()` returns
/// `None` after this deadline, [`parser_exhaustion_finding`] is emitted instead.
pub const PARSER_TIMEOUT_MICROS: u64 = 500_000;

/// Construct a [`SlopFinding`] representing a parser timeout on `lang_hint`.
///
/// Called at every tree-sitter parse site when `parser.parse()` returns `None`
/// after [`PARSER_TIMEOUT_MICROS`] have elapsed.
pub fn parser_exhaustion_finding(lang_hint: &str) -> SlopFinding {
    SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: format!(
            "security:parser_exhaustion_anomaly — tree-sitter parse of .{lang_hint} file \
             exceeded 500 ms timeout; probable AST Bomb (deeply nested adversarial input \
             designed to exhaust the parser); file rejected"
        ),
        domain: DOMAIN_ALL,
        severity: Severity::Exhaustion,
    }
}

/// Parse `source` with a hard timeout of [`PARSER_TIMEOUT_MICROS`] (500 ms).
///
/// Uses `tree_sitter::ParseOptions::progress_callback` to abort the parse when
/// the deadline has elapsed.  Returns `None` both on timeout and on cancellation;
/// callers must emit [`parser_exhaustion_finding`] when `None` is returned after
/// setting up this guard (as opposed to the legacy `parser.parse()` which also
/// returns `None` on complete parse failure — that case is handled by the
/// `tree.root_node().has_error()` guard that follows).
pub(crate) fn parse_with_timeout(
    parser: &mut tree_sitter::Parser,
    source: &[u8],
) -> Option<tree_sitter::Tree> {
    let start = Instant::now();
    let mut timeout_cb = |_: &tree_sitter::ParseState| -> ControlFlow<()> {
        if start.elapsed().as_micros() as u64 >= PARSER_TIMEOUT_MICROS {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let len = source.len();
    let opts = tree_sitter::ParseOptions::new().progress_callback(&mut timeout_cb);
    parser.parse_with_options(
        &mut |i, _| if i < len { &source[i..] } else { b"" },
        None,
        Some(opts),
    )
}

/// A single antipattern finding within a source file.
#[derive(Debug, Clone)]
pub struct SlopFinding {
    /// Byte offset of the finding's start in the source.
    pub start_byte: usize,
    /// Byte offset of the finding's end in the source.
    pub end_byte: usize,
    /// Human-readable description of the antipattern.
    pub description: String,
    /// Domain bitmask indicating which file origins this finding is relevant for.
    ///
    /// Most antipatterns are [`crate::metadata::DOMAIN_FIRST_PARTY`] — they flag
    /// issues that only apply to code you own.  Infrastructure and supply-chain
    /// rules use [`crate::metadata::DOMAIN_ALL`] so they fire on vendored files too.
    pub domain: u8,
    /// Severity tier — governs point contribution and test-domain suppression.
    pub severity: Severity,
}

// ---------------------------------------------------------------------------
// Query constants (documentary — direct AST walking used instead)
// ---------------------------------------------------------------------------

// Equivalent to queries/kubernetes.scm — documents the targeted structure.
// Direct AST walking is used instead of this query because tree-sitter
// predicates cannot correlate sibling pairs (kind: X AND hosts: ["*"]) in a
// single match expression.
#[allow(dead_code)]
const YAML_K8S_WILDCARD_HOSTS_QUERY: &str = r#"
; Matches a block-sequence item whose scalar value is the bare wildcard "*".
; Used to locate wildcard host entries inside Kubernetes VirtualService/Ingress specs.
(block_sequence_item
  (flow_node
    (plain_scalar
      (string_scalar) @wildcard_host)))
"#;

// ---------------------------------------------------------------------------
// Singleton query engine
// ---------------------------------------------------------------------------

struct QueryEngine {
    /// YAML grammar handle — used for Kubernetes VirtualService/Ingress detection.
    yaml_lang: Language,
    /// Plain C grammar — AST walk for banned libc calls.
    c_lang: Language,
    /// JavaScript grammar — used for `innerHTML` assignment, SQLi, SSRF, and
    /// path-traversal detection.
    js_lang: Language,
    /// Python grammar — used for CISA KEV AST gates (SQLi, SSRF, PathTraversal)
    /// and Phase 2 R&D dangerous-call AST walk (exec, eval, pickle, os.system).
    python_lang: Language,
    /// Java grammar — used for Phase 2 R&D deserialization/JNDI AST walk.
    java_lang: Language,
    /// C# grammar — used for Phase 3 R&D TypeNameHandling/BinaryFormatter AST walk.
    csharp_lang: Language,
    /// Go grammar — used for Phase 4 R&D exec.Command shell injection + TLS bypass.
    go_lang: Language,
    /// Ruby grammar — used for Phase 4 R&D dynamic eval/Marshal.load AST walk.
    ruby_lang: Language,
    /// Bash grammar — used for Phase 4 R&D curl|bash + eval injection AST walk.
    bash_lang: Language,
}

impl QueryEngine {
    fn new() -> anyhow::Result<Self> {
        let yaml_lang: Language = tree_sitter_yaml::LANGUAGE.into();
        let c_lang: Language = tree_sitter_c::LANGUAGE.into();
        let js_lang: Language = tree_sitter_javascript::LANGUAGE.into();
        let python_lang: Language = tree_sitter_python::LANGUAGE.into();
        let java_lang: Language = tree_sitter_java::LANGUAGE.into();
        let csharp_lang: Language = tree_sitter_c_sharp::LANGUAGE.into();
        let go_lang: Language = tree_sitter_go::LANGUAGE.into();
        let ruby_lang: Language = tree_sitter_ruby::LANGUAGE.into();
        let bash_lang: Language = tree_sitter_bash::LANGUAGE.into();
        Ok(Self {
            yaml_lang,
            c_lang,
            js_lang,
            python_lang,
            java_lang,
            csharp_lang,
            go_lang,
            ruby_lang,
            bash_lang,
        })
    }
}

static ENGINE: OnceLock<Option<QueryEngine>> = OnceLock::new();

fn engine() -> Option<&'static QueryEngine> {
    ENGINE.get_or_init(|| QueryEngine::new().ok()).as_ref()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect structural security antipatterns in `source`.
///
/// `language` should be the file extension (`"yaml"`, `"c"`, `"tf"`).
/// Returns an empty [`Vec`] for unsupported languages — never an error.
pub fn find_slop(language: &str, source: &[u8]) -> Vec<SlopFinding> {
    let Some(eng) = engine() else {
        return Vec::new();
    };

    let mut findings = match language {
        "yaml" | "yml" => find_yaml_slop(eng, source),
        "c" | "h" => find_c_slop(eng, source),
        "cpp" | "cxx" | "cc" | "hpp" => find_cpp_slop(eng, source),
        "hcl" | "tf" => find_hcl_slop(source),
        "py" => {
            let mut f = find_python_slop(source);
            // CISA KEV gates — AST-based (Python grammar)
            f.extend(find_python_sqli_slop(eng, source));
            f.extend(find_python_ssrf_slop(eng, source));
            f.extend(find_python_path_traversal_slop(eng, source));
            // Phase 2 R&D: dangerous-call AST walk (exec/eval/pickle/os.system/__import__)
            f.extend(find_python_slop_ast(eng, source));
            f
        }
        "js" | "jsx" | "ts" | "tsx" => {
            let mut f = find_js_slop(eng, source);
            // CISA KEV gates — AST-based (JS grammar)
            f.extend(find_js_sqli_slop(eng, source));
            f.extend(find_js_ssrf_slop(eng, source));
            f.extend(find_js_path_traversal_slop(eng, source));
            // Phase 1 R&D: prototype pollution Layer A (AhoCorasick)
            f.extend(find_prototype_pollution_slop(source));
            // Phase 3 R&D: prototype pollution Layer B — merge sink AST walk
            f.extend(find_prototype_merge_sink_slop(eng, source));
            f
        }
        // Phase 1 byte-level Tier 2 + Phase 2 AST-walk Tier 1 for Java
        "java" => {
            let mut f = find_java_sqli_slop(source);
            f.extend(find_java_slop_fast(source));
            // Phase 2 R&D: method_invocation AST walk (deser + JNDI + runtime exec)
            f.extend(find_java_slop(eng, source));
            f
        }
        "go" => {
            let mut f = find_go_sqli_slop(source);
            f.extend(find_go_ssrf_slop(source));
            // Phase 4 R&D: exec.Command shell injection + TLS bypass AST walk
            f.extend(find_go_slop(eng, source));
            f
        }
        "rb" => find_ruby_slop(eng, source),
        "sh" | "bash" | "zsh" => find_bash_slop(eng, source),
        "cs" => {
            let mut f = find_csharp_sqli_slop(source);
            f.extend(find_csharp_slop_fast(source));
            // Phase 3 R&D: TypeNameHandling/BinaryFormatter AST walk (Tier 1)
            f.extend(find_csharp_slop(eng, source));
            f
        }
        _ => Vec::new(),
    };
    // Language-agnostic: credential header scan runs on every source file
    // regardless of detected language.  Secrets can appear in any file type.
    findings.extend(find_credential_slop(source));
    // Language-agnostic: supply-chain integrity scan runs on every source file.
    // Catches external script loading without SRI and GitHub Pages URL embedding.
    findings.extend(find_supply_chain_slop(source));
    findings
}

// ---------------------------------------------------------------------------
// YAML: Kubernetes wildcard-host misconfiguration
// ---------------------------------------------------------------------------

/// Kubernetes resource kinds that govern traffic routing.
const K8S_ROUTING_KINDS: &[&str] = &["VirtualService", "Ingress", "HTTPRoute", "Gateway"];

fn find_yaml_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files that can't possibly contain the pattern.
    let has_k8s_kind = K8S_ROUTING_KINDS
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()));
    if !has_k8s_kind {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.yaml_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("yaml")];
    };

    let mut findings = Vec::new();
    detect_k8s_wildcard_hosts(tree.root_node(), source, &mut findings);
    findings
}

/// Walk the YAML AST looking for Kubernetes documents where a routing resource
/// (`VirtualService`, `Ingress`, etc.) exposes a wildcard host (`"*"` or `*`).
///
/// Strategy (two-pass per document):
/// 1. Walk the top-level block mapping to extract the `kind` scalar.
/// 2. If `kind` is a routing resource, walk the same mapping depth-first to
///    find any sequence item whose scalar is `*` or `"*"`.
fn detect_k8s_wildcard_hosts(root: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    let mut doc_cursor = root.walk();
    for child in root.children(&mut doc_cursor) {
        walk_yaml_document(child, source, findings);
    }
}

fn walk_yaml_document(doc_node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    let Some(mapping) = find_first_block_mapping(doc_node) else {
        return;
    };

    let kind = extract_mapping_scalar(mapping, source, "kind");
    let is_routing_kind = kind
        .as_deref()
        .is_some_and(|k| K8S_ROUTING_KINDS.contains(&k));

    if !is_routing_kind {
        return;
    }

    let mut cursor = mapping.walk();
    for pair in mapping.children(&mut cursor) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        let Some(key_text) = pair_key_text(pair, source) else {
            continue;
        };
        if key_text == "hosts" {
            if let Some(start) = find_wildcard_in_sequence(pair, source, findings) {
                findings.push(SlopFinding {
                    start_byte: start,
                    end_byte: start + 1,
                    description: format!(
                        "Kubernetes wildcard host: `{k}` exposes all routes publicly via \
                         `hosts: [\"*\"]`; restrict to explicit hostnames",
                        k = kind.as_deref().unwrap_or("unknown")
                    ),
                    domain: DOMAIN_ALL,
                    severity: Severity::Critical,
                });
            }
        } else if key_text == "spec" {
            if let Some(inner_mapping) = find_first_block_mapping(pair) {
                let mut inner_cursor = inner_mapping.walk();
                for inner_pair in inner_mapping.children(&mut inner_cursor) {
                    if inner_pair.kind() != "block_mapping_pair" {
                        continue;
                    }
                    if pair_key_text(inner_pair, source).as_deref() == Some("hosts") {
                        if let Some(start) = find_wildcard_in_sequence(inner_pair, source, findings)
                        {
                            findings.push(SlopFinding {
                                start_byte: start,
                                end_byte: start + 1,
                                description: format!(
                                    "Kubernetes wildcard host: `{k}` exposes all routes publicly \
                                     via `spec.hosts: [\"*\"]`; restrict to explicit hostnames",
                                    k = kind.as_deref().unwrap_or("unknown")
                                ),
                                domain: DOMAIN_ALL,
                                severity: Severity::Critical,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Return the scalar text of the value for a given `key` in a `block_mapping` node.
fn extract_mapping_scalar<'a>(mapping: Node<'a>, source: &'a [u8], key: &str) -> Option<String> {
    let mut cursor = mapping.walk();
    for pair in mapping.children(&mut cursor) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        if pair_key_text(pair, source).as_deref() == Some(key) {
            return pair_value_scalar(pair, source);
        }
    }
    None
}

/// Extract the text of a `block_mapping_pair`'s key.
fn pair_key_text(pair: Node<'_>, source: &[u8]) -> Option<String> {
    let key_node = pair.child_by_field_name("key")?;
    scalar_text(key_node, source)
}

/// Extract the scalar text of a `block_mapping_pair`'s value.
fn pair_value_scalar(pair: Node<'_>, source: &[u8]) -> Option<String> {
    let val_node = pair.child_by_field_name("value")?;
    scalar_text(val_node, source)
}

/// Walk a node tree to find the first string scalar text.
fn scalar_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "string_scalar" | "plain_scalar" | "double_quote_scalar" | "single_quote_scalar"
    ) {
        return node
            .utf8_text(source)
            .ok()
            .map(|s| s.trim_matches('"').trim_matches('\'').to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(text) = scalar_text(child, source) {
            return Some(text);
        }
    }
    None
}

/// Find the first `block_mapping` node that is a descendant of `node`.
fn find_first_block_mapping(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "block_mapping" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(m) = find_first_block_mapping(child) {
            return Some(m);
        }
    }
    None
}

/// Search a `block_mapping_pair`'s value for a sequence item whose scalar is `*`.
/// Returns the start byte of the wildcard item when found.
///
/// Iterative (stack-based) traversal — never recurses.  Aborts at depth > 512
/// and pushes a `security:ast_bomb_anomaly` finding to prevent stack overflow.
fn find_wildcard_in_sequence(
    pair: Node<'_>,
    source: &[u8],
    findings: &mut Vec<SlopFinding>,
) -> Option<usize> {
    let mut stack: Vec<(Node<'_>, u32)> = Vec::with_capacity(32);
    stack.push((pair, 0));

    while let Some((node, depth)) = stack.pop() {
        if depth > 512 {
            findings.push(SlopFinding {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                description: "security:ast_bomb_anomaly".to_string(),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            });
            return None;
        }
        if matches!(
            node.kind(),
            "string_scalar" | "plain_scalar" | "double_quote_scalar" | "single_quote_scalar"
        ) {
            if let Ok(text) = node.utf8_text(source) {
                let trimmed = text.trim_matches('"').trim_matches('\'');
                if trimmed == "*" {
                    return Some(node.start_byte());
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// C: banned libc functions
// ---------------------------------------------------------------------------

/// Detect calls to dangerous libc functions in C/C-header source.
///
/// Banned functions: `gets` (removed in C11), `strcpy` (unbounded copy),
/// `sprintf` (unbounded format write), `scanf` (unbounded input read).
fn find_c_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_banned = [b"gets".as_slice(), b"strcpy", b"sprintf", b"scanf"]
        .iter()
        .any(|pat| source.windows(pat.len()).any(|w| w == *pat));
    if !has_banned {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.c_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("c")];
    };
    let mut findings = Vec::new();
    find_banned_c_calls(tree.root_node(), source, &mut findings);
    findings
}

/// Detect calls to dangerous libc functions in C++ source.
///
/// Reuses the C grammar for call detection — C++ is a superset of C at the
/// function-call level.  The C++ grammar is not used here because the C grammar
/// is sufficient for detecting simple function call expressions and avoids
/// grammar-version lag on C++ template syntax.
fn find_cpp_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    find_c_slop(eng, source)
}

/// Walk the C AST reporting calls to functions banned by C11 / CERT-C.
///
/// Banned functions and their replacements:
/// - `gets`    → `fgets(buf, sizeof(buf), stdin)` (removed in C11)
/// - `strcpy`  → `strncpy` or `strlcpy` (unbounded buffer copy)
/// - `sprintf` → `snprintf` (unbounded format write)
/// - `scanf`   → `fgets` + `sscanf` with explicit width (unbounded input read)
fn find_banned_c_calls(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(source) {
                    let desc: Option<&'static str> = match name {
                        "gets" => Some(
                            "security:unsafe_string_function — gets(): removed in C11; \
                             unbounded buffer read — use fgets(buf, sizeof(buf), stdin)",
                        ),
                        "strcpy" => Some(
                            "security:unsafe_string_function — strcpy(): unbounded buffer \
                             copy — use strncpy or strlcpy with explicit size limit",
                        ),
                        "sprintf" => Some(
                            "security:unsafe_string_function — sprintf(): unbounded format \
                             write — use snprintf with explicit buffer size",
                        ),
                        "scanf" => Some(
                            "security:unsafe_string_function — scanf(): unbounded input \
                             read — use fgets + sscanf with explicit field width",
                        ),
                        _ => None,
                    };
                    if let Some(d) = desc {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: d.to_string(),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::Critical,
                        });
                        return;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_banned_c_calls(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// HCL / Terraform: open-world CIDR detection (byte-scan, no grammar needed)
// ---------------------------------------------------------------------------

/// Detect wildcard CIDR `0.0.0.0/0` inside a security-group context in HCL.
///
/// Uses a byte-level scan rather than tree-sitter parsing — the signal is
/// unambiguous enough without AST structure.  A finding is only emitted when
/// the file also contains an ingress/security-group marker, reducing false
/// positives on non-IaC TOML.
fn find_hcl_slop(source: &[u8]) -> Vec<SlopFinding> {
    let mut findings = Vec::new();
    find_hcl_open_cidr(source, &mut findings);
    find_hcl_s3_public_acl(source, &mut findings);
    findings
}

/// Detect wildcard CIDR `0.0.0.0/0` inside a security-group context in HCL.
///
/// Uses a byte-level scan rather than tree-sitter parsing — the signal is
/// unambiguous enough without AST structure.  A finding is only emitted when
/// the file also contains an ingress/security-group marker, reducing false
/// positives on non-IaC TOML.
fn find_hcl_open_cidr(source: &[u8], findings: &mut Vec<SlopFinding>) {
    const WILDCARD: &[u8] = b"0.0.0.0/0";
    if !source.windows(WILDCARD.len()).any(|w| w == WILDCARD) {
        return;
    }

    const SECURITY_MARKERS: &[&[u8]] = &[
        b"ingress",
        b"security_group",
        b"aws_security_group",
        b"cidr_blocks",
    ];
    let has_context = SECURITY_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m));
    if !has_context {
        return;
    }

    for (i, _) in source
        .windows(WILDCARD.len())
        .enumerate()
        .filter(|(_, w)| *w == WILDCARD)
    {
        findings.push(SlopFinding {
            start_byte: i,
            end_byte: i + WILDCARD.len(),
            description: "Open CIDR `0.0.0.0/0` in security group rule: \
                          exposes resource to the entire internet — \
                          restrict to specific IP ranges"
                .to_string(),
            domain: DOMAIN_ALL,
            severity: Severity::Critical,
        });
    }
}

/// Detect `public-read` S3 bucket ACL in HCL / Terraform source.
///
/// Uses a byte-level scan — the signal is unambiguous without grammar support.
/// A finding is only emitted when the file also contains `aws_s3_bucket` or
/// `acl` to reduce false positives on unrelated HCL configs.
fn find_hcl_s3_public_acl(source: &[u8], findings: &mut Vec<SlopFinding>) {
    const PUBLIC_READ: &[u8] = b"public-read";
    if !source.windows(PUBLIC_READ.len()).any(|w| w == PUBLIC_READ) {
        return;
    }

    const S3_MARKERS: &[&[u8]] = &[b"aws_s3_bucket", b"acl"];
    let has_context = S3_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m));
    if !has_context {
        return;
    }

    for (i, _) in source
        .windows(PUBLIC_READ.len())
        .enumerate()
        .filter(|(_, w)| *w == PUBLIC_READ)
    {
        findings.push(SlopFinding {
            start_byte: i,
            end_byte: i + PUBLIC_READ.len(),
            description: "security:s3_public_acl — S3 bucket ACL set to \
                          `public-read`: bucket contents are accessible to \
                          the entire internet — use private ACL and S3 bucket \
                          policies for controlled access"
                .to_string(),
            domain: DOMAIN_ALL,
            severity: Severity::Critical,
        });
    }
}

// ---------------------------------------------------------------------------
// Python: subprocess shell=True injection detection (byte-scan heuristic)
// ---------------------------------------------------------------------------

/// Detect `subprocess.run/call/Popen` with `shell=True` in Python source.
///
/// Uses a byte-level scan (no grammar required) because the AST structure for
/// keyword arguments varies significantly between Python grammar versions and
/// the byte-level signal is unambiguous.  A finding is emitted when:
/// 1. The source contains `shell=True`.
/// 2. The source contains at least one of `subprocess.run`, `subprocess.call`,
///    or `subprocess.Popen`.
///
/// This is a conservative heuristic — it fires on any file that contains both
/// patterns regardless of whether they appear on the same line.  The false-
/// positive rate in practice is negligible (subprocess + shell=True in the
/// same file almost always indicates intentional use).
fn find_python_slop(source: &[u8]) -> Vec<SlopFinding> {
    const SHELL_TRUE: &[u8] = b"shell=True";
    const SUBPROCESS_CALLS: &[&[u8]] =
        &[b"subprocess.run", b"subprocess.call", b"subprocess.Popen"];

    if !source.windows(SHELL_TRUE.len()).any(|w| w == SHELL_TRUE) {
        return Vec::new();
    }

    let has_subprocess = SUBPROCESS_CALLS
        .iter()
        .any(|pat| source.windows(pat.len()).any(|w| w == *pat));
    if !has_subprocess {
        return Vec::new();
    }

    // Emit one finding at the first occurrence of `shell=True`.
    source
        .windows(SHELL_TRUE.len())
        .enumerate()
        .find(|(_, w)| *w == SHELL_TRUE)
        .map(|(i, _)| {
            vec![SlopFinding {
                start_byte: i,
                end_byte: i + SHELL_TRUE.len(),
                description: "security:subprocess_shell_injection — subprocess with \
                    shell=True: command string is evaluated by the OS shell — \
                    avoid shell=True or validate/sanitize all inputs"
                    .to_string(),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            }]
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript: innerHTML assignment detection
// ---------------------------------------------------------------------------

/// Detect `element.innerHTML = ...` assignments in JavaScript / TypeScript source.
///
/// Direct `innerHTML` assignment is a well-known DOM XSS vector when the
/// right-hand side contains user-controlled data.  This rule flags any
/// assignment to a property named `innerHTML`, regardless of the target object.
///
/// Uses the JavaScript grammar, which covers `.js`, `.jsx`, `.ts`, and `.tsx`
/// files (TypeScript is a superset of JavaScript at the assignment level and
/// shares compatible AST structure for member expressions).
fn find_js_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    const INNER_HTML: &[u8] = b"innerHTML";
    if !source.windows(INNER_HTML.len()).any(|w| w == INNER_HTML) {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("js")];
    };

    let mut findings = Vec::new();
    find_inner_html_assignments(tree.root_node(), source, &mut findings);
    findings
}

/// Walk the JS/TS AST looking for `assignment_expression` where the left-hand
/// side is a `member_expression` whose `property` field is the identifier
/// `innerHTML`.
fn find_inner_html_assignments(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "assignment_expression" {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "member_expression" {
                if let Some(prop) = left.child_by_field_name("property") {
                    if prop.utf8_text(source).ok() == Some("innerHTML") {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: "security:dom_xss_innerHTML — direct \
                                `innerHTML` assignment is a DOM XSS vector; \
                                use `textContent` for plain text or sanitize \
                                input with DOMPurify before assignment"
                                .to_string(),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::Critical,
                        });
                        return;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_inner_html_assignments(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// NCD Entropy Gate
// ---------------------------------------------------------------------------

/// Compression ratio threshold below which a patch is flagged as
/// `antipattern:ncd_anomaly`. A ratio of 0.15 means the patch compresses
/// to <15% of its original size — achievable only by extreme repetition
/// (e.g. hundreds of identical lines, machine-generated boilerplate).
///
/// CALIBRATION (v7.9.2 — 2026-03-23): Recalibrated from 0.05 → 0.15.
/// The 33K-PR gauntlet corpus showed 0 NCD hits at the 0.05 threshold
/// (`janitor report --global` returned 0/0 NCD findings), confirming the
/// threshold was too tight to fire on any real-world PR. Raising to 0.15
/// captures genuine verbosity-bomb PRs (e.g. repeated boilerplate blocks)
/// without false-positive exposure.
pub const MIN_ENTROPY_RATIO: f64 = 0.15;

/// Minimum input size (bytes) before the entropy gate engages.
///
/// `zstd` carries a fixed dictionary + frame header overhead of ~50 bytes.
/// On tiny inputs this overhead dominates, producing spurious low ratios that
/// would trigger false positives on one-liner patches.  Patches smaller than
/// this threshold are unconditionally exempt.
const ENTROPY_MIN_BYTES: usize = 256;

/// Compute the NCD entropy ratio for `patch_bytes`.
///
/// Compresses `patch_bytes` with `zstd` at level 3 (the lowest level that
/// fully engages the LZ77 back-reference window) and returns:
///
/// ```text
/// ratio = compressed_len / raw_len
/// ```
///
/// Lower values indicate more repetitive (lower-entropy) content.
/// Returns `1.0` when the input is too small to yield a meaningful ratio
/// (fewer than [`ENTROPY_MIN_BYTES`] bytes) or on compression failure —
/// both conservative defaults that avoid false positives.
///
/// ## Complexity
/// O(N) in `patch_bytes.len()` — `zstd` streaming is a single linear pass.
pub fn check_entropy(patch_bytes: &[u8]) -> f64 {
    if patch_bytes.len() < ENTROPY_MIN_BYTES {
        return 1.0;
    }
    match zstd::encode_all(patch_bytes, 3) {
        Ok(compressed) => compressed.len() as f64 / patch_bytes.len() as f64,
        Err(_) => 1.0,
    }
}

// ---------------------------------------------------------------------------
// Logic Erasure Detector (Structural Regression)
// ---------------------------------------------------------------------------

/// Patch-level Logic Erasure Detector — structural regression signal.
///
/// Counts conditional branch keywords in removed lines (`-`) vs. added lines (`+`)
/// of a unified diff.  A PR that reduces branch density by more than 20% while
/// keeping total code volume similar (+/− 10%) is flagged as
/// `architecture:logic_erasure` — the structural signature of an AI model
/// silently "optimising" away edge-case safety checks.
///
/// ## Detection thresholds
/// - `base_branches ≥ 3` — avoids firing on trivial single-branch changes.
/// - `head_branches < base_branches × 0.8` — >20% branch count reduction.
/// - `|head_lines − base_lines| ≤ base_lines / 10` — code volume stays similar;
///   prevents false positives on large net-deletions where branch loss is trivially
///   explained by the removal itself.
///
/// ## Language coverage
/// Keyword counting is language-agnostic: covers `if`/`match`/`switch`/`guard`/
/// `case`/`elif`/`elsif`/`else if` in every language supported by the pipeline.
///
/// Returns `None` for add-only patches, delete-only patches, or patches that do
/// not meet the combined thresholds.
pub fn check_logic_regression(patch: &str) -> Option<SlopFinding> {
    // Branch keyword prefixes (ASCII).  Each needle must be followed by a
    // non-ident char in practice, but a literal substring count is sufficient
    // for this density-based heuristic — rare false hits do not cross the 20%
    // threshold on real code.
    const BRANCH_NEEDLES: &[&[u8]] = &[
        b"if ", b"if(", b"match ", b"match{", b"match(", b"switch ", b"switch(", b"switch{",
        b"case ", b"guard ", b"elif ", b"elsif ", b"else if",
    ];

    let count_branches_in_line = |line: &str| -> u32 {
        let b = line.as_bytes();
        BRANCH_NEEDLES
            .iter()
            .map(|needle| {
                let n = needle.len();
                let mut count = 0u32;
                let mut i = 0;
                while i + n <= b.len() {
                    if b[i..i + n] == **needle {
                        count += 1;
                        i += n;
                    } else {
                        i += 1;
                    }
                }
                count
            })
            .sum()
    };

    let mut base_branches: u32 = 0;
    let mut head_branches: u32 = 0;
    let mut base_lines: u32 = 0;
    let mut head_lines: u32 = 0;

    for line in patch.lines() {
        if line.starts_with('-') && !line.starts_with("---") {
            let content = &line[1..];
            if !content.trim().is_empty() {
                base_lines += 1;
                base_branches += count_branches_in_line(content);
            }
        } else if line.starts_with('+') && !line.starts_with("+++") {
            let content = &line[1..];
            if !content.trim().is_empty() {
                head_lines += 1;
                head_branches += count_branches_in_line(content);
            }
        }
    }

    // Minimum base branch count — avoid triggering on trivial single-branch changes.
    if base_branches < 3 {
        return None;
    }
    // Both sides must have substantive code.
    if base_lines == 0 || head_lines == 0 {
        return None;
    }
    // Total code volume must stay within 10%: detects neutral rewrites, not deletions.
    let tolerance = (base_lines / 10).max(1);
    if head_lines.abs_diff(base_lines) > tolerance {
        return None;
    }
    // Branch reduction must exceed 20%.
    // head < base * 0.8  ⟺  head * 10 < base * 8
    if head_branches * 10 >= base_branches * 8 {
        return None;
    }

    let pct = 100u32.saturating_sub(head_branches * 100 / base_branches.max(1));
    Some(SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: format!(
            "architecture:logic_erasure — conditional branch count reduced by {pct}% \
(base: {base_branches} → head: {head_branches}) while code volume remained similar \
(base: {base_lines} lines, head: {head_lines} lines); \
probable AI erasure of edge-case safety checks. \
Risk: significant loss of technical signal — sparse branch coverage degrades \
documentation search relevance and may trigger low-quality content classifiers \
on public repositories."
        ),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::Critical,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Recursive Boilerplate — topology-hash collision detector
// ---------------------------------------------------------------------------

/// Number of functions with identical AST topology required to trigger the
/// Recursive Boilerplate penalty.
const BOILERPLATE_THRESHOLD: u32 = 5;

/// Produce a BLAKE3-derived u64 topology fingerprint for a tree-sitter node
/// subtree.  Only node kinds are serialised — token text is ignored — so two
/// functions with the same structural skeleton but different identifier names
/// produce the same fingerprint.
fn topology_hash(node: Node<'_>) -> u64 {
    let mut buf = String::with_capacity(256);
    build_topology(node, &mut buf);
    let hash = blake3::hash(buf.as_bytes());
    let bytes = hash.as_bytes();
    u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]))
}

fn build_topology(node: Node<'_>, out: &mut String) {
    if node.is_extra() {
        // Skip comments and other extras — they are cosmetic noise.
        return;
    }
    out.push_str(node.kind());
    out.push('|');
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        build_topology(child, out);
    }
}

/// Walk `node` depth-first, collecting topology hashes of every function-like
/// node whose kind is listed in `fn_kinds`.
fn collect_fn_topologies<'a>(
    node: Node<'a>,
    fn_kinds: &[&str],
    counts: &mut HashMap<u64, u32>,
    first_bytes: &mut HashMap<u64, usize>,
) {
    if fn_kinds.contains(&node.kind()) {
        let h = topology_hash(node);
        *counts.entry(h).or_insert(0) += 1;
        first_bytes.entry(h).or_insert(node.start_byte());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_fn_topologies(child, fn_kinds, counts, first_bytes);
    }
}

/// Detect Recursive Boilerplate — more than [`BOILERPLATE_THRESHOLD`] functions
/// added in the same source blob with identical AST topology.
///
/// A PR that floods the codebase with structurally identical functions (the
/// canonical AI context-bloat signature) triggers a Critical (+50 pt) finding.
///
/// Language coverage: Rust, Python, C/C++, JavaScript/TypeScript.
/// Returns `None` for unsupported languages or if no threshold breach is found.
pub fn detect_recursive_boilerplate(language: &str, source: &[u8]) -> Option<SlopFinding> {
    let ts_lang: tree_sitter::Language = match language {
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        "py" => tree_sitter_python::LANGUAGE.into(),
        "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" => tree_sitter_c::LANGUAGE.into(),
        "js" | "jsx" | "ts" | "tsx" => tree_sitter_javascript::LANGUAGE.into(),
        _ => return None,
    };

    let fn_kinds: &[&str] = match language {
        "rs" => &["function_item"],
        "py" => &["function_definition"],
        "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" => &["function_definition"],
        "js" | "jsx" | "ts" | "tsx" => &[
            "function_declaration",
            "arrow_function",
            "method_definition",
        ],
        _ => return None,
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&ts_lang).is_err() {
        return None;
    }
    let tree = match parse_with_timeout(&mut parser, source) {
        Some(t) => t,
        None => return Some(parser_exhaustion_finding(language)),
    };
    if tree.root_node().has_error() {
        return None;
    }

    let mut counts: HashMap<u64, u32> = HashMap::new();
    let mut first_bytes: HashMap<u64, usize> = HashMap::new();
    collect_fn_topologies(tree.root_node(), fn_kinds, &mut counts, &mut first_bytes);

    let worst = counts
        .iter()
        .filter(|(_, &c)| c > BOILERPLATE_THRESHOLD)
        .max_by_key(|(_, &c)| c);

    let (&hash_key, &count) = worst?;
    let first_byte = first_bytes.get(&hash_key).copied().unwrap_or(0);

    Some(SlopFinding {
        start_byte: first_byte,
        end_byte: first_byte,
        description: format!(
            "antipattern:recursive_boilerplate — {count} functions share identical AST topology \
             (SimHash distance=0); structural boilerplate flood detected"
        ),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::Critical,
    })
}

// ---------------------------------------------------------------------------
// Credential Leak Detection — Language-Agnostic
// ---------------------------------------------------------------------------

/// Credential header patterns indexed by AhoCorasick pattern ID.
///
/// Uses deterministic string prefixes where possible to stay within the
/// AhoCorasick performance envelope.  Each pattern maps to a human-readable
/// description containing the `security:credential_leak` antipattern label.
const CREDENTIAL_PATTERNS: &[(&[u8], &str)] = &[
    // AWS IAM Access Key IDs always begin with `AKIA` followed by 16 uppercase
    // alphanumeric characters.  `AKIA` is the deterministic AhoCorasick trigger.
    (
        b"AKIA",
        "security:credential_leak — AWS IAM Access Key ID prefix (AKIA…); rotate this key immediately",
    ),
    // Full PEM header — fixed string, zero false-positive surface.
    (
        b"-----BEGIN RSA PRIVATE KEY-----",
        "security:credential_leak — RSA private key PEM header detected; never commit private keys",
    ),
    // Stripe live secret key prefix.  Test-mode keys (`sk_test_`) are not flagged.
    (
        b"sk_live_",
        "security:credential_leak — Stripe live secret key prefix (sk_live_…); revoke immediately",
    ),
];

static CREDENTIAL_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn credential_automaton() -> &'static AhoCorasick {
    CREDENTIAL_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(CREDENTIAL_PATTERNS.iter().map(|(p, _)| p))
            .expect("slop_hunter: credential AhoCorasick build cannot fail on static patterns")
    })
}

/// Scan `source` bytes for known credential header patterns.
///
/// Language-agnostic — called from [`find_slop`] on every source file
/// regardless of detected language.  Secrets can appear in any file type.
/// Returns one [`SlopFinding`] per match; never panics or errors.
pub fn find_credential_slop(source: &[u8]) -> Vec<SlopFinding> {
    let ac = credential_automaton();
    ac.find_iter(source)
        .map(|mat| SlopFinding {
            start_byte: mat.start(),
            end_byte: mat.end(),
            description: CREDENTIAL_PATTERNS[mat.pattern().as_usize()].1.to_owned(),
            domain: DOMAIN_ALL,
            severity: Severity::Critical,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Supply Chain Integrity Detection — Language-Agnostic
// ---------------------------------------------------------------------------

/// Supply-chain threat patterns indexed by AhoCorasick pattern ID.
///
/// Detects external script loading without Subresource Integrity (SRI) and
/// GitHub Pages URLs embedded in production source — both are supply-chain
/// attack vectors that bypass traditional dependency auditing.
///
/// | Pattern                  | Threat Class                                          |
/// |--------------------------|-------------------------------------------------------|
/// | `<script src="http`      | External script without SRI — CDN hijack vector       |
/// | `.github.io/`            | GitHub Pages URL in production — no SLA or integrity  |
const SUPPLY_CHAIN_PATTERNS: &[(&[u8], &str)] = &[
    // `<script src="http` fires on both `http://` (always wrong — cleartext
    // resource loading) and `https://` (acceptable only with SRI).  Any external
    // script loaded without `integrity="sha…"` lets CDN/DNS compromise silently
    // replace the payload delivered to every page consumer.
    (
        b"<script src=\"http",
        "security:unpinned_asset — <script src=\"http\u{2026}\" loads an external script without \
         Subresource Integrity (integrity=\"sha\u{2026}\"); CDN or DNS hijack can inject arbitrary \
         code into all consumers of this page",
    ),
    // GitHub Pages URLs coupled into production source have no SLA, can be taken
    // over if the owning org is renamed, and carry no content-integrity guarantee.
    (
        b".github.io/",
        "security:unpinned_asset — .github.io/ URL embedded in production source; \
         GitHub Pages is not a CDN and has no integrity guarantee — \
         use a versioned package dependency instead",
    ),
];

static SUPPLY_CHAIN_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn supply_chain_automaton() -> &'static AhoCorasick {
    SUPPLY_CHAIN_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(SUPPLY_CHAIN_PATTERNS.iter().map(|(p, _)| p))
            .expect("slop_hunter: supply_chain AhoCorasick build cannot fail on static patterns")
    })
}

/// Scan `source` bytes for supply-chain integrity violations.
///
/// Language-agnostic — called from [`find_slop`] on every source file
/// regardless of detected language.  Detects external script loading without
/// Subresource Integrity and GitHub Pages URL embedding in production code.
///
/// Returns one [`SlopFinding`] per match at [`Severity::Critical`] (+50 pts).
/// Never panics or returns an error.
pub fn find_supply_chain_slop(source: &[u8]) -> Vec<SlopFinding> {
    let ac = supply_chain_automaton();
    ac.find_iter(source)
        .map(|mat| SlopFinding {
            start_byte: mat.start(),
            end_byte: mat.end(),
            description: SUPPLY_CHAIN_PATTERNS[mat.pattern().as_usize()].1.to_owned(),
            domain: DOMAIN_ALL,
            severity: Severity::Critical,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// CISA KEV Constants — SQL Injection / SSRF / Path Traversal
// ---------------------------------------------------------------------------

/// Database execution method names targeted by the SQL injection AST gate.
/// A `call`/`call_expression` whose callee text matches or ends with one of
/// these is subject to the string-concatenation SQL argument check.
const SQL_EXEC_METHODS: &[&str] = &[
    "execute",
    "executemany",
    "query",
    "raw",
    "do",
    "exec",
    "execute_query",
];

/// SQL keywords whose presence in a string literal indicates a SQL query context
/// (used by [`has_sql_string_leaf`] to confirm injection risk).
const SQL_KEYWORDS_STR: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE",
];

/// Python HTTP client callees targeted by the SSRF AST gate.
const SSRF_HTTP_CALLEES_PY: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.head",
    "requests.patch",
    "requests.request",
    "urllib.request.urlopen",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
];

/// JavaScript HTTP client callees targeted by the SSRF AST gate.
const SSRF_HTTP_CALLEES_JS: &[&str] = &[
    "fetch",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "axios.patch",
    "axios.request",
    "got.get",
    "got.post",
    "superagent.get",
    "superagent.post",
    "request",
];

/// Node.js filesystem callees targeted by the path-traversal AST gate.
const FS_OPEN_CALLEES_JS: &[&str] = &[
    "fs.readFile",
    "fs.readFileSync",
    "fs.writeFile",
    "fs.writeFileSync",
    "fs.appendFile",
    "fs.appendFileSync",
    "fs.createReadStream",
    "fs.createWriteStream",
    "fs.open",
    "fs.openSync",
];

// ---------------------------------------------------------------------------
// CISA KEV — Shared AST helpers
// ---------------------------------------------------------------------------

/// Return `true` if `node` (a `binary_operator` or `binary_expression`) uses
/// `+` as its operator.  Handles Python (`binary_operator` with named `operator`
/// field) and JavaScript (`binary_expression`, same field name) tree-sitter
/// grammars, with an unnamed-child fallback for other grammars.
fn binary_node_has_plus_op(node: Node<'_>, source: &[u8]) -> bool {
    if let Some(op) = node.child_by_field_name("operator") {
        return op.utf8_text(source).ok() == Some("+");
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() && child.utf8_text(source).ok() == Some("+") {
            return true;
        }
    }
    false
}

/// Recursively search `node` and its descendants for a string literal that
/// contains any [`SQL_KEYWORDS_STR`] entry.  Returns `true` on first match.
fn has_sql_string_leaf(node: Node<'_>, source: &[u8]) -> bool {
    if matches!(
        node.kind(),
        "string" | "string_literal" | "interpreted_string_literal"
    ) {
        if let Ok(text) = node.utf8_text(source) {
            return SQL_KEYWORDS_STR.iter().any(|kw| text.contains(kw));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if has_sql_string_leaf(child, source) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// CISA KEV — Python AST gates (tree-sitter Python grammar)
// ---------------------------------------------------------------------------

/// SQL injection detection for Python: flags [`SQL_EXEC_METHODS`] calls whose
/// first argument is a `binary_operator` (`+`) containing a SQL keyword literal.
fn find_python_sqli_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_sql = SQL_KEYWORDS_STR
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()));
    if !has_sql {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b" + ") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.python_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("py")];
    };
    let mut findings = Vec::new();
    find_sqli_calls_py(tree.root_node(), source, &mut findings);
    findings
}

fn find_sqli_calls_py(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            let is_db_call = SQL_EXEC_METHODS
                .iter()
                .any(|m| func_text == *m || func_text.ends_with(&format!(".{m}")));
            if is_db_call {
                let mut ac = args_node.walk();
                for arg in args_node.children(&mut ac) {
                    if arg.kind() == "binary_operator"
                        && binary_node_has_plus_op(arg, source)
                        && has_sql_string_leaf(arg, source)
                    {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: format!(
                                "security:sqli_concatenation — `{func_text}()` called with a \
                                 SQL query built by string concatenation (`+`); use \
                                 parameterized queries (e.g. cursor.execute(sql, params)) \
                                 to prevent SQL injection — CISA KEV class"
                            ),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                        return; // one finding per call node; siblings handled by recursion
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_sqli_calls_py(child, source, findings);
    }
}

/// SSRF detection for Python: flags [`SSRF_HTTP_CALLEES_PY`] calls whose URL
/// argument is a `binary_operator` (`+`), indicating dynamic URL construction.
fn find_python_ssrf_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_http = SSRF_HTTP_CALLEES_PY
        .iter()
        .any(|c| source.windows(c.len()).any(|w| w == c.as_bytes()));
    if !has_http {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.python_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("py")];
    };
    let mut findings = Vec::new();
    find_ssrf_calls_py(tree.root_node(), source, &mut findings);
    findings
}

fn find_ssrf_calls_py(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            if SSRF_HTTP_CALLEES_PY.contains(&func_text) {
                let first_named = {
                    let mut ac = args_node.walk();
                    let x = args_node.children(&mut ac).find(|c| c.is_named());
                    x
                };
                if let Some(arg) = first_named {
                    if arg.kind() == "binary_operator" && binary_node_has_plus_op(arg, source) {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: format!(
                                "security:ssrf_dynamic_url — `{func_text}()` called with a \
                                 URL constructed via string concatenation (`+`); if any \
                                 component is user-controlled this is an SSRF vector — \
                                 validate and allowlist URL hosts before issuing HTTP \
                                 requests — CISA KEV class"
                            ),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_ssrf_calls_py(child, source, findings);
    }
}

/// Path traversal detection for Python: flags `open()` calls whose first
/// argument is a `binary_operator` (`+`) instead of `os.path.join()`.
fn find_python_path_traversal_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    if !source.windows(5).any(|w| w == b"open(") {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b" + ") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.python_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("py")];
    };
    let mut findings = Vec::new();
    find_path_traversal_py(tree.root_node(), source, &mut findings);
    findings
}

fn find_path_traversal_py(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            let is_open = matches!(func_text, "open" | "io.open" | "codecs.open")
                || func_text.ends_with(".open");
            if is_open {
                let mut ac = args_node.walk();
                for arg in args_node.children(&mut ac) {
                    if arg.kind() == "binary_operator" && binary_node_has_plus_op(arg, source) {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description:
                                "security:path_traversal_concatenation — `open()` called with \
                                 a path built by string concatenation (`+`); use \
                                 `os.path.join()` and validate the resolved path against an \
                                 allowed base directory to prevent directory traversal — \
                                 CISA KEV class"
                                    .to_string(),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                        return;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_path_traversal_py(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// Phase 2 R&D: Python dangerous-call AST walk (Tier 1)
// ---------------------------------------------------------------------------

/// Python dangerous API targets for the Phase 2 AST walk.
///
/// Each entry is `(callee_text, label_fragment, severity)`.
/// `eval` is rated [`Severity::Warning`] (10 pts) because bare `eval` is idiomatic
/// in test harnesses; all other targets fire at [`Severity::Critical`] (50 pts).
/// `eval` findings are additionally suppressed inside `test_*` function scopes and
/// when the call line contains a `# noqa` comment.
const PYTHON_DANGER_CALLS: &[(&str, &str, Severity)] = &[
    (
        "exec",
        "security:code_execution — Python `exec()` executes an arbitrary string as \
         code; if the argument is user-controlled this achieves RCE; use a safe \
         interpreter (e.g. `ast.literal_eval`) or an explicit allow-list instead",
        Severity::Critical,
    ),
    (
        "eval",
        "security:dynamic_eval — Python `eval()` evaluates an arbitrary expression; \
         user-controlled input enables RCE; prefer `ast.literal_eval()` for data \
         parsing or refactor to avoid dynamic evaluation",
        Severity::Warning,
    ),
    (
        "pickle.loads",
        "security:unsafe_deserialization — `pickle.loads()` deserializes arbitrary \
         Python objects; attacker-controlled bytes enable RCE; use JSON or \
         `ast.literal_eval` for data exchange",
        Severity::Critical,
    ),
    (
        "pickle.load",
        "security:unsafe_deserialization — `pickle.load()` deserializes arbitrary \
         Python objects from a file object; same RCE risk as `pickle.loads()`",
        Severity::Critical,
    ),
    (
        "os.system",
        "security:os_command_injection — `os.system()` executes a shell command string; \
         if any component is user-controlled this is a command injection vector; \
         use `subprocess.run([...], shell=False)` with an explicit argument array",
        Severity::Critical,
    ),
    (
        "__import__",
        "security:dynamic_import — `__import__()` performs a dynamic module import by \
         name string; if the module name is user-controlled an attacker can load \
         arbitrary code; use explicit static imports instead",
        Severity::Critical,
    ),
];

/// Return `true` if the source line containing `byte_offset` contains `# noqa`.
fn line_has_noqa(source: &[u8], byte_offset: usize) -> bool {
    let line_start = source[..byte_offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let line_end = source[byte_offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| byte_offset + p)
        .unwrap_or(source.len());
    let line = &source[line_start..line_end];
    line.windows(6).any(|w| w == b"# noqa")
}

/// Walk the Python AST for dangerous call expressions.
///
/// `in_test_scope` is set to `true` when recursing into a `function_definition`
/// whose name starts with `test_`; within such a scope `eval` findings are
/// suppressed (test harnesses routinely call `eval` for coverage purposes).
fn find_python_danger_calls(
    node: Node<'_>,
    source: &[u8],
    findings: &mut Vec<SlopFinding>,
    in_test_scope: bool,
) {
    // When entering a function_definition, check if it is a test_ function.
    let next_in_test_scope = if node.kind() == "function_definition" {
        let name_is_test = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .is_some_and(|name| name.starts_with("test_"));
        // Once inside a test scope we stay in it for all nested calls.
        in_test_scope || name_is_test
    } else {
        in_test_scope
    };

    if node.kind() == "call" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            for &(callee, description, severity) in PYTHON_DANGER_CALLS {
                if func_text != callee {
                    continue;
                }
                // `eval` suppression: inside a test_ scope or `# noqa` on the line.
                if callee == "eval" {
                    if next_in_test_scope {
                        break;
                    }
                    if line_has_noqa(source, node.start_byte()) {
                        break;
                    }
                }
                // General `# noqa` suppression for all dangerous calls.
                if line_has_noqa(source, node.start_byte()) {
                    break;
                }
                findings.push(SlopFinding {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    description: description.to_owned(),
                    domain: DOMAIN_FIRST_PARTY,
                    severity,
                });
                break;
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_python_danger_calls(child, source, findings, next_in_test_scope);
    }
}

/// Scan Python source for dangerous call expressions via tree-sitter AST walk.
///
/// Covers `exec`, `eval`, `pickle.loads`, `pickle.load`, `os.system`, and
/// `__import__`.  `eval` findings are suppressed inside `test_*` function scopes
/// and on lines containing `# noqa`.
///
/// Phase 2 R&D upgrade per `docs/R_AND_D_ROADMAP.md` Section I (Shallow Language 1).
fn find_python_slop_ast(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files that can't contain any dangerous call.
    let has_any = PYTHON_DANGER_CALLS.iter().any(|(callee, _, _)| {
        let needle = callee.as_bytes();
        source.windows(needle.len()).any(|w| w == needle)
    });
    if !has_any {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.python_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("py")];
    };
    let mut findings = Vec::new();
    find_python_danger_calls(tree.root_node(), source, &mut findings, false);
    findings
}

// ---------------------------------------------------------------------------
// Phase 2 R&D: Java deserialization / JNDI AST walk (Tier 1)
// ---------------------------------------------------------------------------

/// Scan Java source for dangerous `method_invocation` patterns via tree-sitter.
///
/// Detects:
/// - `ObjectInputStream` / `XMLDecoder` receiver + `readObject()` call
/// - `Runtime.getRuntime()` receiver + `exec()` call (shell injection)
/// - `InitialContext` receiver + `lookup()` call **only when the argument is not
///   a string literal** (dynamic JNDI injection; static config lookups are safe)
///
/// For JNDI, receivers declared as `InitialContext varName = ...` are tracked at
/// the file level so that `varName.lookup(dynamic)` correctly fires even when the
/// receiver text does not literally contain `"InitialContext"`.
///
/// Phase 2 R&D upgrade per `docs/R_AND_D_ROADMAP.md` Section I (Shallow Language 2).
fn find_java_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: at least one dangerous class or method name present.
    const JAVA_MARKERS: &[&[u8]] = &[
        b"ObjectInputStream",
        b"XMLDecoder",
        b"readObject",
        b"getRuntime",
        b"InitialContext",
        b"lookup",
    ];
    if !JAVA_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m))
    {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.java_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("java")];
    };

    // Collect variable names by declared type so that short variable names
    // (e.g. `ois`, `ctx`) resolve to their dangerous type at invocation sites.
    let deser_var_names: Vec<String> = ["ObjectInputStream", "XMLDecoder", "XStream"]
        .iter()
        .flat_map(|t| collect_java_typed_vars(source, t))
        .collect();
    let ctx_var_names = collect_java_typed_vars(source, "InitialContext");

    let mut findings = Vec::new();
    find_java_danger_invocations(
        tree.root_node(),
        source,
        &deser_var_names,
        &ctx_var_names,
        &mut findings,
    );
    findings
}

/// Scan `source` for Java variable declarations `TypeName varName` where the type
/// contains `type_substr`.  Returns all matching variable names (lowercase-first
/// identifiers) to enable file-level type resolution without full type inference.
///
/// Example: `collect_java_typed_vars(src, "InitialContext")` returns `["ctx"]` for
/// `InitialContext ctx = new InitialContext();`.
fn collect_java_typed_vars(source: &[u8], type_substr: &str) -> Vec<String> {
    let needle = type_substr.as_bytes();
    let mut names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    while pos + needle.len() <= source.len() {
        if &source[pos..pos + needle.len()] == needle {
            let after_type = pos + needle.len();
            // Skip whitespace after the type token.
            let name_start = source[after_type..]
                .iter()
                .position(|&b| b == b' ' || b == b'\t')
                .map(|p| after_type + p + 1)
                .unwrap_or(after_type);
            let name_end = source[name_start..]
                .iter()
                .position(|&b| !b.is_ascii_alphanumeric() && b != b'_')
                .map(|p| name_start + p)
                .unwrap_or(source.len());
            if name_end > name_start {
                if let Ok(name) = std::str::from_utf8(&source[name_start..name_end]) {
                    let name = name.trim();
                    // Only accept lowercase-first identifiers (variable names, not class names).
                    if !name.is_empty()
                        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    {
                        names.push(name.to_owned());
                    }
                }
            }
        }
        pos += 1;
    }
    names
}

/// Return `true` if `arg_list` (a Java `argument_list` node) has its first
/// argument as a `string_literal` — i.e. the JNDI lookup target is a static
/// constant rather than a user-controlled value.
fn java_first_arg_is_string_literal(arg_list: Node<'_>) -> bool {
    let mut cursor = arg_list.walk();
    for child in arg_list.children(&mut cursor) {
        if child.is_named() {
            return child.kind() == "string_literal";
        }
    }
    false
}

fn find_java_danger_invocations(
    node: Node<'_>,
    source: &[u8],
    deser_var_names: &[String],
    ctx_var_names: &[String],
    findings: &mut Vec<SlopFinding>,
) {
    if node.kind() == "method_invocation" {
        let name_text = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        let object_text = node
            .child_by_field_name("object")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("")
            .to_owned();

        match name_text {
            "readObject" => {
                // Fire when the receiver type is ObjectInputStream or XMLDecoder,
                // either by literal class name in the receiver expression OR by
                // matching a variable name declared with one of those types.
                let is_deser_receiver = object_text.contains("ObjectInputStream")
                    || object_text.contains("XMLDecoder")
                    || object_text.contains("XStream")
                    || deser_var_names.iter().any(|v| v == &object_text);
                if is_deser_receiver {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: format!(
                            "security:unsafe_deserialization — `{object_text}.readObject()` \
                             deserializes arbitrary Java objects; attacker-controlled bytes \
                             enable RCE via gadget chains (CVE-2015-4852 class); apply \
                             `ObjectInputFilter` allow-list or migrate to a safe format"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
            "exec" => {
                // Fire when the receiver chain contains `getRuntime` — i.e. the
                // pattern is `Runtime.getRuntime().exec(...)`.
                if object_text.contains("getRuntime") {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: format!(
                            "security:runtime_exec — `{object_text}.exec()` executes an OS \
                             command; if the command string contains user input this is a \
                             command injection vector; use ProcessBuilder with an explicit \
                             argument array instead"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
            "lookup" => {
                // Fire only when:
                // (a) Receiver text directly names an InitialContext/JNDI context class, OR
                // (b) Receiver variable was declared as InitialContext in this file, AND
                // (c) First argument is NOT a string literal (dynamic JNDI injection).
                let is_jndi_receiver = object_text.contains("InitialContext")
                    || object_text.contains("Context")
                    || ctx_var_names.iter().any(|v| v == &object_text);
                if is_jndi_receiver {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if !java_first_arg_is_string_literal(args) {
                            findings.push(SlopFinding {
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                                description: format!(
                                    "security:jndi_injection — `{object_text}.lookup()` with a \
                                     dynamic (non-literal) argument is the Log4Shell \
                                     (CVE-2021-44228) JNDI injection vector; restrict to \
                                     static config strings and disable remote JNDI class loading"
                                ),
                                domain: DOMAIN_FIRST_PARTY,
                                severity: Severity::Critical,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_java_danger_invocations(child, source, deser_var_names, ctx_var_names, findings);
    }
}

// ---------------------------------------------------------------------------
// CISA KEV — JavaScript / TypeScript AST gates
// ---------------------------------------------------------------------------

/// SQL injection detection for JS/TS: flags [`SQL_EXEC_METHODS`] calls whose
/// argument list contains a `binary_expression` (`+`) with a SQL string leaf.
fn find_js_sqli_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_sql = SQL_KEYWORDS_STR
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()));
    if !has_sql {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b" + ") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("js")];
    };
    let mut findings = Vec::new();
    find_sqli_calls_js(tree.root_node(), source, &mut findings);
    findings
}

fn find_sqli_calls_js(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            let is_db_call = SQL_EXEC_METHODS
                .iter()
                .any(|m| func_text == *m || func_text.ends_with(&format!(".{m}")));
            if is_db_call {
                let mut ac = args_node.walk();
                for arg in args_node.children(&mut ac) {
                    if arg.kind() == "binary_expression"
                        && binary_node_has_plus_op(arg, source)
                        && has_sql_string_leaf(arg, source)
                    {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: format!(
                                "security:sqli_concatenation — `{func_text}()` called with a \
                                 SQL query built by string concatenation (`+`); use \
                                 parameterized queries with `?` or `$N` placeholders \
                                 to prevent SQL injection — CISA KEV class"
                            ),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                        return;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_sqli_calls_js(child, source, findings);
    }
}

/// SSRF detection for JS/TS: flags [`SSRF_HTTP_CALLEES_JS`] calls whose first
/// argument is a `binary_expression` or `template_string` (dynamic URL).
fn find_js_ssrf_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_http = SSRF_HTTP_CALLEES_JS
        .iter()
        .any(|c| source.windows(c.len()).any(|w| w == c.as_bytes()));
    if !has_http {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("js")];
    };
    let mut findings = Vec::new();
    find_ssrf_calls_js(tree.root_node(), source, &mut findings);
    findings
}

fn find_ssrf_calls_js(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            if SSRF_HTTP_CALLEES_JS.contains(&func_text) {
                let first_named = {
                    let mut ac = args_node.walk();
                    let x = args_node.children(&mut ac).find(|c| c.is_named());
                    x
                };
                if let Some(arg) = first_named {
                    if matches!(arg.kind(), "binary_expression" | "template_string") {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: format!(
                                "security:ssrf_dynamic_url — `{func_text}()` called with a \
                                 dynamically constructed URL (string concatenation or template \
                                 literal); if any component is user-controlled this is an SSRF \
                                 vector — validate and allowlist URL hosts — CISA KEV class"
                            ),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_ssrf_calls_js(child, source, findings);
    }
}

/// Path traversal detection for JS/TS: flags [`FS_OPEN_CALLEES_JS`] calls
/// whose first argument is a `binary_expression` (`+`) instead of
/// `path.join()`.
fn find_js_path_traversal_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let has_fs = FS_OPEN_CALLEES_JS.iter().any(|c| {
        let method = c.split('.').next_back().unwrap_or("");
        source.windows(method.len()).any(|w| w == method.as_bytes())
    });
    if !has_fs {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b" + ") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("js")];
    };
    let mut findings = Vec::new();
    find_path_traversal_js(tree.root_node(), source, &mut findings);
    findings
}

fn find_path_traversal_js(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            let is_fs_call = FS_OPEN_CALLEES_JS.contains(&func_text)
                || func_text.ends_with(".readFile")
                || func_text.ends_with(".readFileSync")
                || func_text.ends_with(".writeFile")
                || func_text.ends_with(".writeFileSync");
            if is_fs_call {
                let first_named = {
                    let mut ac = args_node.walk();
                    let x = args_node.children(&mut ac).find(|c| c.is_named());
                    x
                };
                if let Some(arg) = first_named {
                    if arg.kind() == "binary_expression" && binary_node_has_plus_op(arg, source) {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: format!(
                                "security:path_traversal_concatenation — `{func_text}()` \
                                 called with a path built by string concatenation (`+`); use \
                                 `path.join()` or `path.resolve()` and validate the result \
                                 against an allowed base directory — CISA KEV class"
                            ),
                            domain: DOMAIN_FIRST_PARTY,
                            severity: Severity::KevCritical,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_path_traversal_js(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// CISA KEV — Java / Go / C# byte-level Tier 2 gates
//
// Grammars for these languages are loaded in `crates/polyglot` but have no
// active AST-walk branch in this module yet.  The byte-level approach (marker
// co-occurrence check) is the Tier 2 interim gate per the CVE-to-AST protocol
// in `docs/R_AND_D_ROADMAP.md`.  Phase 1 upgrade (full AST walk) is tracked there.
// ---------------------------------------------------------------------------

/// SQL injection — Java: DB execution method + SQL keyword + string concat
/// close-quote pattern all present in the same file.
fn find_java_sqli_slop(source: &[u8]) -> Vec<SlopFinding> {
    const JAVA_EXEC: &[&[u8]] = &[
        b"executeQuery(",
        b"executeUpdate(",
        b"execute(\"",
        b"prepareStatement(",
    ];
    if !JAVA_EXEC
        .iter()
        .any(|p| source.windows(p.len()).any(|w| w == *p))
    {
        return Vec::new();
    }
    if !SQL_KEYWORDS_STR
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()))
    {
        return Vec::new();
    }
    // `" +` — string literal close-quote immediately followed by concatenation
    if !source.windows(3).any(|w| w == b"\" +") {
        return Vec::new();
    }
    vec![SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: "security:sqli_concatenation — SQL query assembled via string \
                      concatenation in a Java database execution call; use \
                      PreparedStatement with `?` placeholders to prevent SQL \
                      injection — CISA KEV class"
            .to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::KevCritical,
    }]
}

/// SQL injection — Go: `database/sql` method + SQL keyword + concat pattern.
fn find_go_sqli_slop(source: &[u8]) -> Vec<SlopFinding> {
    const GO_DB: &[&[u8]] = &[
        b"db.Query(",
        b"db.QueryRow(",
        b"db.Exec(",
        b"tx.Query(",
        b"tx.Exec(",
    ];
    if !GO_DB
        .iter()
        .any(|p| source.windows(p.len()).any(|w| w == *p))
    {
        return Vec::new();
    }
    if !SQL_KEYWORDS_STR
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()))
    {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b"\" +") {
        return Vec::new();
    }
    vec![SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: "security:sqli_concatenation — SQL query assembled via string \
                      concatenation in a Go database/sql call; use `$1/$2` \
                      placeholders with `db.Query(sql, args...)` to prevent SQL \
                      injection — CISA KEV class"
            .to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::KevCritical,
    }]
}

/// SSRF — Go: `net/http` call where the URL argument does not begin with a
/// string literal (next byte after `(` is not `"` or `` ` ``).
fn find_go_ssrf_slop(source: &[u8]) -> Vec<SlopFinding> {
    const GO_HTTP: &[&[u8]] = &[b"http.Get(", b"http.Post(", b"http.Head("];
    let mut findings = Vec::new();
    'outer: for pattern in GO_HTTP {
        for (i, _) in source
            .windows(pattern.len())
            .enumerate()
            .filter(|(_, w)| w == pattern)
        {
            let after = i + pattern.len();
            if let Some(&nb) = source.get(after) {
                if nb != b'"' && nb != b'`' {
                    findings.push(SlopFinding {
                        start_byte: i,
                        end_byte: i + pattern.len(),
                        description: "security:ssrf_dynamic_url — Go `http.Get/Post/Head()` \
                                      called with a dynamic URL argument; if user-controlled \
                                      this is an SSRF vector — validate and allowlist URL \
                                      hosts before issuing HTTP requests — CISA KEV class"
                            .to_string(),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::KevCritical,
                    });
                    continue 'outer;
                }
            }
        }
    }
    findings
}

/// SQL injection — C#: SqlCommand/MySqlCommand + SQL keyword + concat pattern.
fn find_csharp_sqli_slop(source: &[u8]) -> Vec<SlopFinding> {
    const CS_EXEC: &[&[u8]] = &[
        b"ExecuteNonQuery()",
        b"ExecuteReader()",
        b"ExecuteScalar()",
        b"new SqlCommand(",
        b"new MySqlCommand(",
        b"CommandText =",
    ];
    if !CS_EXEC
        .iter()
        .any(|p| source.windows(p.len()).any(|w| w == *p))
    {
        return Vec::new();
    }
    if !SQL_KEYWORDS_STR
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()))
    {
        return Vec::new();
    }
    if !source.windows(3).any(|w| w == b"\" +") {
        return Vec::new();
    }
    vec![SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: "security:sqli_concatenation — SQL query assembled via string \
                      concatenation in a C# database command; use SqlParameter \
                      objects with parameterized queries to prevent SQL injection — \
                      CISA KEV class"
            .to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::KevCritical,
    }]
}

// ---------------------------------------------------------------------------
// Phase 1 R&D: Java deserialization gadget chain detection (AhoCorasick Tier 2)
//
// Covers CVE-2015-4852 (Apache Commons Collections ObjectInputStream gadget),
// CVE-2021-44228 (Log4Shell JNDI InitialContext.lookup), XStream RCE class,
// and Runtime.exec shell injection.  Full AST walk (Tier 1) is Phase 2.
// ---------------------------------------------------------------------------

/// Java dangerous API patterns — deserialization gadget chains and runtime exec.
///
/// | Pattern                        | Label                            | CVE class          |
/// |--------------------------------|----------------------------------|--------------------|
/// | `new ObjectInputStream(`       | `security:unsafe_deserialization`| CVE-2015-4852 class|
/// | `XMLDecoder(`                  | `security:unsafe_deserialization`| Java XML deser RCE |
/// | `XStream().fromXML(`           | `security:unsafe_deserialization`| XStream RCE class  |
/// | `.readObject()`                | `security:unsafe_deserialization`| Generic deser sink |
/// | `Runtime.getRuntime().exec(`   | `security:runtime_exec`          | Shell exec via Java |
/// | `InitialContext().lookup(`     | `security:jndi_injection`        | CVE-2021-44228 class|
const JAVA_DANGER_PATTERNS: &[(&[u8], &str)] = &[
    (
        b"new ObjectInputStream(",
        "security:unsafe_deserialization — `new ObjectInputStream(` instantiates a Java \
         object deserializer; attacker-controlled bytes fed into `readObject()` enable \
         RCE via gadget chains (CVE-2015-4852 class); use Jackson with type restrictions \
         or schema validation instead",
    ),
    (
        b"XMLDecoder(",
        "security:unsafe_deserialization — `XMLDecoder(` deserializes arbitrary Java \
         objects from XML; attacker-controlled XML enables RCE; replace with JAXB \
         with explicit class allow-list",
    ),
    (
        b"XStream().fromXML(",
        "security:unsafe_deserialization — `XStream().fromXML(` deserializes arbitrary \
         Java objects from XML without type restrictions; enable XStream security \
         framework `allowTypesByWildcard` or migrate to Jackson",
    ),
    (
        b".readObject()",
        "security:unsafe_deserialization — `.readObject()` is a Java deserialization sink; \
         if the stream source is user-controlled this enables RCE via gadget chains; \
         validate the source and apply `ObjectInputFilter` allow-list",
    ),
    (
        b"Runtime.getRuntime().exec(",
        "security:runtime_exec — `Runtime.getRuntime().exec(` executes an OS command; \
         if the command string contains user input this is a command injection vector; \
         use ProcessBuilder with an explicit argument array instead",
    ),
    (
        b"InitialContext().lookup(",
        "security:jndi_injection — `InitialContext().lookup(` with a user-controlled \
         name string is the Log4Shell (CVE-2021-44228) JNDI injection vector; \
         restrict to static config strings and disable remote JNDI class loading",
    ),
];

static JAVA_DANGER_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn java_danger_automaton() -> &'static AhoCorasick {
    JAVA_DANGER_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(JAVA_DANGER_PATTERNS.iter().map(|(p, _)| p))
            .expect("slop_hunter: java_danger AhoCorasick build cannot fail on static patterns")
    })
}

/// Scan `.java` source bytes for unsafe deserialization and runtime exec patterns.
///
/// Phase 1 AhoCorasick (Tier 2) gate per `docs/R_AND_D_ROADMAP.md` Section III.
/// Returns one [`SlopFinding`] per match at [`Severity::Critical`] (+50 pts).
pub fn find_java_slop_fast(source: &[u8]) -> Vec<SlopFinding> {
    let ac = java_danger_automaton();
    ac.find_iter(source)
        .map(|mat| SlopFinding {
            start_byte: mat.start(),
            end_byte: mat.end(),
            description: JAVA_DANGER_PATTERNS[mat.pattern().as_usize()].1.to_owned(),
            domain: DOMAIN_FIRST_PARTY,
            severity: Severity::Critical,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Phase 1 R&D: C# deserialization detection (AhoCorasick Tier 2)
//
// Covers Newtonsoft.Json TypeNameHandling RCE class (multiple CVEs 2019-2023),
// BinaryFormatter (SYSLIB0011 deprecated, still active in legacy projects), and
// LosFormatter/ObjectStateFormatter (legacy ASP.NET ViewState deser sinks).
// `TypeNameHandling.None` is the safe value — explicitly excluded.
// ---------------------------------------------------------------------------

/// C# dangerous deserialization patterns.
///
/// | Pattern                  | Label                            | Notes                     |
/// |--------------------------|----------------------------------|---------------------------|
/// | `new BinaryFormatter()`  | `security:unsafe_deserialization`| SYSLIB0011, banned .NET 5+|
/// | `TypeNameHandling.Auto`  | `security:unsafe_deserialization`| Newtonsoft.Json RCE class |
/// | `TypeNameHandling.All`   | `security:unsafe_deserialization`| Newtonsoft.Json RCE class |
/// | `TypeNameHandling.Objects`| `security:unsafe_deserialization`| Newtonsoft.Json RCE class |
/// | `LosFormatter`           | `security:unsafe_deserialization`| Legacy ASP.NET ViewState  |
/// | `ObjectStateFormatter`   | `security:unsafe_deserialization`| Legacy ASP.NET ViewState  |
///
/// `TypeNameHandling.None` is safe and is NOT in this list.
const CSHARP_DANGER_PATTERNS: &[(&[u8], &str)] = &[
    (
        b"new BinaryFormatter()",
        "security:unsafe_deserialization — `new BinaryFormatter()` is banned in .NET 5+ \
         (SYSLIB0011) and enables RCE via gadget chains on attacker-controlled bytes; \
         replace with System.Text.Json or XmlSerializer with type restrictions",
    ),
    (
        b"TypeNameHandling.Auto",
        "security:unsafe_deserialization — `TypeNameHandling.Auto` in Newtonsoft.Json \
         enables arbitrary type deserialization; attacker-controlled JSON containing \
         `$type` fields yields RCE on servers with gadget-bearing assemblies; \
         set `TypeNameHandling.None` (the safe default)",
    ),
    (
        b"TypeNameHandling.All",
        "security:unsafe_deserialization — `TypeNameHandling.All` in Newtonsoft.Json \
         unconditionally deserializes every `$type` annotation; equivalent attack \
         surface to `TypeNameHandling.Auto` — set `TypeNameHandling.None` instead",
    ),
    (
        b"TypeNameHandling.Objects",
        "security:unsafe_deserialization — `TypeNameHandling.Objects` in Newtonsoft.Json \
         deserializes `$type` annotations on object properties; partial exposure to the \
         same RCE gadget chain as `TypeNameHandling.All` — set `TypeNameHandling.None`",
    ),
    (
        b"LosFormatter",
        "security:unsafe_deserialization — `LosFormatter` is a legacy ASP.NET ViewState \
         formatter that deserializes arbitrary .NET objects; superseded by \
         `MachineKey`-protected ViewState — do not use in new code",
    ),
    (
        b"ObjectStateFormatter",
        "security:unsafe_deserialization — `ObjectStateFormatter` is a legacy ASP.NET \
         formatter that deserializes arbitrary .NET objects; superseded by \
         `DataProtection` API — do not use in new code",
    ),
];

static CSHARP_DANGER_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn csharp_danger_automaton() -> &'static AhoCorasick {
    CSHARP_DANGER_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(CSHARP_DANGER_PATTERNS.iter().map(|(p, _)| p))
            .expect("slop_hunter: csharp_danger AhoCorasick build cannot fail on static patterns")
    })
}

/// Scan `.cs` source bytes for unsafe deserialization patterns.
///
/// Phase 1 AhoCorasick (Tier 2) gate per `docs/R_AND_D_ROADMAP.md` Section III.
/// `TypeNameHandling.None` is NOT in the pattern list — it is the safe value.
/// Returns one [`SlopFinding`] per match at [`Severity::Critical`] (+50 pts).
pub fn find_csharp_slop_fast(source: &[u8]) -> Vec<SlopFinding> {
    let ac = csharp_danger_automaton();
    ac.find_iter(source)
        .map(|mat| SlopFinding {
            start_byte: mat.start(),
            end_byte: mat.end(),
            description: CSHARP_DANGER_PATTERNS[mat.pattern().as_usize()]
                .1
                .to_owned(),
            domain: DOMAIN_FIRST_PARTY,
            severity: Severity::Critical,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Phase 3 R&D: C# deserialization AST walk (Tier 1)
//
// Upgrades the Phase 1 AhoCorasick (Tier 2) byte scan to a full AST walk:
// - `assignment_expression` where the right-hand side is `TypeNameHandling.Auto`,
//   `TypeNameHandling.All`, or `TypeNameHandling.Objects` — exactly the three
//   Newtonsoft.Json values that enable arbitrary type deserialization.
//   `TypeNameHandling.None` is the safe default and is explicitly excluded.
// - `object_creation_expression` where the type being constructed is `BinaryFormatter`.
//
// AST precision over AhoCorasick: avoids firing on commented-out code such as
// `// TypeNameHandling.Auto was the old setting` which the Tier 2 pattern catches
// as a false positive.
// ---------------------------------------------------------------------------

/// Dangerous TypeNameHandling values — all three enable `$type` deserialization RCE.
/// `TypeNameHandling.None` is the safe default and MUST NOT appear in this list.
const CSHARP_DANGEROUS_TNH: &[&str] = &[
    "TypeNameHandling.Auto",
    "TypeNameHandling.All",
    "TypeNameHandling.Objects",
];

/// Scan C# source for `TypeNameHandling` dangerous assignment expressions and
/// `BinaryFormatter` object creation via tree-sitter AST walk.
///
/// Phase 3 R&D upgrade per `docs/R_AND_D_ROADMAP.md` Section I (Shallow Language 3).
fn find_csharp_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files with neither TypeNameHandling nor BinaryFormatter.
    const CSHARP_MARKERS: &[&[u8]] = &[b"TypeNameHandling", b"BinaryFormatter"];
    if !CSHARP_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m))
    {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.csharp_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("cs")];
    };

    let mut findings = Vec::new();
    find_csharp_danger_nodes(tree.root_node(), source, &mut findings);
    findings
}

fn find_csharp_danger_nodes(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    match node.kind() {
        "assignment_expression" => {
            // Flag when the right-hand side is a dangerous TypeNameHandling value.
            if let Some(right) = node.child_by_field_name("right") {
                if let Ok(rhs) = right.utf8_text(source) {
                    for &dangerous in CSHARP_DANGEROUS_TNH {
                        if rhs == dangerous {
                            findings.push(SlopFinding {
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                                description: format!(
                                    "security:unsafe_deserialization — \
                                     `{rhs}` in Newtonsoft.Json enables arbitrary \
                                     type deserialization; attacker-controlled JSON \
                                     `$type` fields yield RCE on servers with \
                                     gadget-bearing assemblies; set \
                                     `TypeNameHandling.None` (the safe default)"
                                ),
                                domain: DOMAIN_FIRST_PARTY,
                                severity: Severity::Critical,
                            });
                            break;
                        }
                    }
                }
            }
        }
        "object_creation_expression" => {
            // Flag `new BinaryFormatter()` — any use of BinaryFormatter in .NET 5+
            // is deprecated (SYSLIB0011) and enables RCE via gadget chains.
            // Try the "type" field first; fall back to the first named child.
            let mut fallback_cursor = node.walk();
            let type_text = match node.child_by_field_name("type") {
                Some(t) => t.utf8_text(source).unwrap_or(""),
                None => node
                    .children(&mut fallback_cursor)
                    .find(|ch| ch.is_named())
                    .and_then(|ch| ch.utf8_text(source).ok())
                    .unwrap_or(""),
            };
            if type_text == "BinaryFormatter" {
                findings.push(SlopFinding {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    description: "security:unsafe_deserialization — `new BinaryFormatter()` \
                                  is banned in .NET 5+ (SYSLIB0011); attacker-controlled \
                                  bytes enable RCE via gadget chains; migrate to \
                                  System.Text.Json or XmlSerializer with explicit type \
                                  restrictions"
                        .to_string(),
                    domain: DOMAIN_FIRST_PARTY,
                    severity: Severity::Critical,
                });
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_csharp_danger_nodes(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// Phase 4 R&D: Go AST Walk — exec.Command shell injection (Go-1) +
//              TLS certificate verification bypass (Go-2)
// ---------------------------------------------------------------------------

/// Shell interpreter names that turn exec.Command into a shell injection sink.
const GO_SHELL_INTERPS: &[&str] = &["sh", "bash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe"];

fn find_go_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files containing neither dangerous pattern.
    const GO_MARKERS: &[&[u8]] = &[b"exec.Command", b"InsecureSkipVerify"];
    if !GO_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m))
    {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.go_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("go")];
    };

    let mut findings = Vec::new();
    find_go_danger_nodes(tree.root_node(), source, false, &mut findings);
    findings
}

fn find_go_danger_nodes(
    node: Node<'_>,
    source: &[u8],
    inside_test: bool,
    findings: &mut Vec<SlopFinding>,
) {
    // Propagate test-scope suppression for Go-1.  Go-2 (InsecureSkipVerify) is
    // never suppressed — there is no safe production use of this field.
    let in_test = if inside_test {
        true
    } else if node.kind() == "function_declaration" || node.kind() == "method_declaration" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        name.contains("test") || name.contains("Test")
    } else {
        false
    };

    match node.kind() {
        // Gate Go-1: exec.Command("sh"|"bash"|..., ...)
        "call_expression" if !in_test => {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "selector_expression" {
                    let operand_text = func
                        .child_by_field_name("operand")
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("");
                    let field_text = func
                        .child_by_field_name("field")
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("");
                    if operand_text == "exec" && field_text == "Command" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let first_arg = args.named_children(&mut args.walk()).next();
                            if let Some(arg) = first_arg {
                                let raw = arg.utf8_text(source).unwrap_or("");
                                // Strip surrounding double-quotes from string literal.
                                let stripped = raw.trim_matches('"');
                                if GO_SHELL_INTERPS.contains(&stripped) {
                                    findings.push(SlopFinding {
                                        start_byte: node.start_byte(),
                                        end_byte: node.end_byte(),
                                        description: format!(
                                            "security:command_injection_shell_exec — \
                                             `exec.Command({raw}, ...)` spawns a shell \
                                             interpreter; if subsequent arguments include \
                                             user-controlled data this is a command injection \
                                             primitive; use a specific binary path with \
                                             discrete arguments instead of a shell wrapper"
                                        ),
                                        domain: DOMAIN_FIRST_PARTY,
                                        severity: Severity::Critical,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        // Gate Go-2: InsecureSkipVerify: true — no suppression
        "keyed_element" => {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            if children.len() >= 2 {
                let key_text = children[0].utf8_text(source).unwrap_or("");
                let val_text = children[1].utf8_text(source).unwrap_or("");
                if key_text == "InsecureSkipVerify" && val_text == "true" {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: "security:tls_verification_bypass — \
                                      `InsecureSkipVerify: true` disables TLS certificate \
                                      verification entirely, enabling MitM attacks; \
                                      see CVE-2022-27664, CVE-2023-29409; remove this field \
                                      or set it to `false`"
                            .to_string(),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_go_danger_nodes(child, source, in_test, findings);
    }
}

// ---------------------------------------------------------------------------
// Phase 4 R&D: Ruby AST Walk — dynamic eval/system/exec/spawn (Ruby-1) +
//              Marshal.load deserialization (Ruby-2)
// ---------------------------------------------------------------------------

/// Ruby method names whose dynamic invocation constitutes a code execution sink.
const RUBY_DANGEROUS_EXEC_METHODS: &[&str] = &["eval", "system", "exec", "spawn"];

fn find_ruby_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files missing any dangerous keyword.
    const RUBY_MARKERS: &[&[u8]] = &[b"eval", b"system", b"Marshal.load", b"Marshal.restore"];
    if !RUBY_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m))
    {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.ruby_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("rb")];
    };

    let mut findings = Vec::new();
    find_ruby_danger_nodes(tree.root_node(), source, false, &mut findings);
    findings
}

fn find_ruby_danger_nodes(
    node: Node<'_>,
    source: &[u8],
    inside_test: bool,
    findings: &mut Vec<SlopFinding>,
) {
    // Track test/spec method scope for Ruby-1 suppression.
    let in_test = if inside_test {
        true
    } else if node.kind() == "method" || node.kind() == "singleton_method" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        name.contains("test") || name.contains("spec")
    } else {
        false
    };

    if node.kind() == "call" {
        let receiver_text = node
            .child_by_field_name("receiver")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        let method_text = node
            .child_by_field_name("method")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");

        // Gate Ruby-2: Marshal.load / Marshal.restore — no suppression.
        if receiver_text == "Marshal" && (method_text == "load" || method_text == "restore") {
            findings.push(SlopFinding {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                description: format!(
                    "security:unsafe_deserialization — `Marshal.{method_text}` executes \
                     arbitrary Ruby code embedded in the serialized stream; this is the \
                     mechanism behind dozens of Rails RCEs including CVE-2013-0156; \
                     use JSON.parse or a schema-validated deserializer instead"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            });
        }

        // Gate Ruby-1: eval/system/exec/spawn with dynamic (non-literal) argument.
        if !in_test
            && receiver_text.is_empty()
            && RUBY_DANGEROUS_EXEC_METHODS.contains(&method_text)
        {
            // Fire only when the first argument is not a plain string literal.
            let first_arg_is_literal = node
                .child_by_field_name("arguments")
                .and_then(|args| args.named_children(&mut args.walk()).next())
                .map(|arg| arg.kind() == "string")
                .unwrap_or(false);
            if !first_arg_is_literal {
                findings.push(SlopFinding {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    description: format!(
                        "security:dangerous_execution — `{method_text}(...)` with a \
                         dynamic argument is a code/command execution primitive; \
                         if the argument includes user-controlled data this enables \
                         arbitrary command injection or RCE; use a parameterised \
                         subprocess API or whitelist the allowed commands"
                    ),
                    domain: DOMAIN_FIRST_PARTY,
                    severity: Severity::Critical,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_ruby_danger_nodes(child, source, in_test, findings);
    }
}

// ---------------------------------------------------------------------------
// Phase 4 R&D: Bash AST Walk — curl|bash supply chain (Bash-1) +
//              eval with unquoted variable expansion (Bash-2)
// ---------------------------------------------------------------------------

fn find_bash_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files missing both dangerous keywords.
    const BASH_MARKERS: &[&[u8]] = &[b"eval", b"curl", b"wget"];
    if !BASH_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m))
    {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.bash_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("sh")];
    };

    let mut findings = Vec::new();
    find_bash_danger_nodes(tree.root_node(), source, &mut findings);
    findings
}

fn find_bash_danger_nodes(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    match node.kind() {
        // Gate Bash-1: pipeline where first command is curl/wget and last is bash/sh.
        "pipeline" => {
            let mut cursor = node.walk();
            let cmds: Vec<Node<'_>> = node
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "command")
                .collect();
            if cmds.len() >= 2 {
                let first_name = cmds[0]
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("");
                let last_name = cmds[cmds.len() - 1]
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("");
                if (first_name == "curl" || first_name == "wget")
                    && (last_name == "bash" || last_name == "sh")
                {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: format!(
                            "security:curl_pipe_execution — `{first_name} ... | {last_name}` \
                             executes a remote script without integrity verification; \
                             this is the canonical supply chain attack vector \
                             (malware deployment, bootstrap hijack); \
                             download the script, verify its checksum, then execute"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
        }
        // Gate Bash-2: eval command with an unquoted variable expansion argument.
        "command" => {
            let cmd_name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if cmd_name == "eval" {
                // Fire when any direct argument is a simple_expansion ($VAR) or
                // expansion (${VAR}).  Suppress when all arguments are quoted strings.
                let mut cursor = node.walk();
                let has_unquoted_expansion = node
                    .children(&mut cursor)
                    .any(|child| child.kind() == "simple_expansion" || child.kind() == "expansion");
                if has_unquoted_expansion {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: "security:eval_injection — `eval $VAR` or `eval ${VAR}` \
                                      expands an unquoted variable into executable code; \
                                      if the variable originates from user input, environment, \
                                      or an untrusted source this is a code injection primitive; \
                                      never eval unquoted variables"
                            .to_string(),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_bash_danger_nodes(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// Phase 1 R&D: Prototype Pollution detection — Layer A AhoCorasick (JS/TS)
//
// Covers direct `__proto__` key access patterns.  Layer B (unsafe merge
// utility AST walk) is Phase 3 per `docs/R_AND_D_ROADMAP.md`.
// ---------------------------------------------------------------------------

/// Prototype pollution patterns — direct `__proto__` and constructor chain access.
///
/// | Pattern                   | Rationale                                      |
/// |---------------------------|------------------------------------------------|
/// | `.__proto__`              | Direct prototype access in expression          |
/// | `["__proto__"]`           | Computed key bracket access                    |
/// | `['__proto__']`           | Single-quote computed key variant              |
/// | `[constructor][prototype]`| Indirect prototype chain traversal             |
const PROTOTYPE_PATTERNS: &[(&[u8], &str)] = &[
    (
        b".__proto__",
        "security:prototype_pollution — `.__proto__` directly accesses the object \
         prototype chain; if this property path is reachable from user-controlled \
         input it enables prototype pollution, overwriting shared object properties \
         across all instances and potentially achieving RCE in Node.js via gadget chains",
    ),
    (
        b"[\"__proto__\"]",
        "security:prototype_pollution — `[\"__proto__\"]` computed key accesses the \
         prototype chain; user-controlled keys fed into a merge/assign loop over \
         this bracket form enable prototype pollution",
    ),
    (
        b"['__proto__']",
        "security:prototype_pollution — `['__proto__']` computed key (single-quote \
         variant) accesses the prototype chain; same attack surface as the \
         double-quote form",
    ),
    (
        b"[constructor][prototype]",
        "security:prototype_pollution — `[constructor][prototype]` traverses the \
         prototype chain indirectly via the constructor property; this form is \
         used to bypass naive `__proto__` keyword filters in merge utilities",
    ),
];

static PROTOTYPE_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn prototype_automaton() -> &'static AhoCorasick {
    PROTOTYPE_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(PROTOTYPE_PATTERNS.iter().map(|(p, _)| p))
            .expect("slop_hunter: prototype AhoCorasick build cannot fail on static patterns")
    })
}

/// Scan JS/TS source bytes for prototype pollution patterns (Layer A).
///
/// Phase 1 AhoCorasick (Tier 2) gate per `docs/R_AND_D_ROADMAP.md` Section III.
/// Returns one [`SlopFinding`] per match at [`Severity::Critical`] (+50 pts).
pub fn find_prototype_pollution_slop(source: &[u8]) -> Vec<SlopFinding> {
    let ac = prototype_automaton();
    ac.find_iter(source)
        .map(|mat| SlopFinding {
            start_byte: mat.start(),
            end_byte: mat.end(),
            description: PROTOTYPE_PATTERNS[mat.pattern().as_usize()].1.to_owned(),
            domain: DOMAIN_FIRST_PARTY,
            severity: Severity::Critical,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Phase 3 R&D: Prototype Pollution — Layer B AST walk (JS/TS merge sinks)
//
// Detects `_.merge`, `lodash.merge`, `deepMerge`, `mergeDeep`, and
// `Object.assign` call sites where any argument:
//   (a) is the result of `JSON.parse(...)`, or
//   (b) is an identifier or member-expression property matching a common
//       HTTP request input name (`body`, `query`, `params`, `input`).
//
// Suppressed when the enclosing function name contains "sanitize" or "validate" —
// those functions exist precisely to clean input before merging.
// ---------------------------------------------------------------------------

/// Merge utility callee names that are prototype-pollution-capable.
const MERGE_CALL_TARGETS: &[&str] = &[
    "_.merge",
    "lodash.merge",
    "deepMerge",
    "mergeDeep",
    "Object.assign",
];

/// Common HTTP request property names that carry user-controlled data.
const USER_INPUT_NAMES: &[&str] = &["body", "query", "params", "input"];

/// Return `true` if `arg` is a known taint source:
/// - A `JSON.parse(...)` call expression, or
/// - An `identifier` whose name is in [`USER_INPUT_NAMES`], or
/// - A `member_expression` whose `property` is in [`USER_INPUT_NAMES`]
///   (e.g. `req.body`, `request.query`).
fn argument_is_tainted(arg: Node<'_>, source: &[u8]) -> bool {
    match arg.kind() {
        "call_expression" => arg
            .child_by_field_name("function")
            .and_then(|f| f.utf8_text(source).ok())
            .is_some_and(|t| t == "JSON.parse"),
        "identifier" => {
            let name = arg.utf8_text(source).unwrap_or("");
            USER_INPUT_NAMES.contains(&name)
        }
        "member_expression" => arg
            .child_by_field_name("property")
            .and_then(|p| p.utf8_text(source).ok())
            .is_some_and(|t| USER_INPUT_NAMES.contains(&t)),
        _ => false,
    }
}

fn find_merge_sink_calls(
    node: Node<'_>,
    source: &[u8],
    findings: &mut Vec<SlopFinding>,
    in_safe_scope: bool,
) {
    // When entering a named function, check if it is a sanitize/validate function.
    let next_in_safe_scope = if matches!(
        node.kind(),
        "function_declaration" | "method_definition" | "function_expression"
    ) {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        in_safe_scope || name.contains("sanitize") || name.contains("validate")
    } else {
        in_safe_scope
    };

    if !next_in_safe_scope && node.kind() == "call_expression" {
        if let (Some(func_node), Some(args_node)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_text = func_node.utf8_text(source).unwrap_or("");
            if MERGE_CALL_TARGETS.contains(&func_text) {
                let mut cursor = args_node.walk();
                let tainted = args_node
                    .children(&mut cursor)
                    .filter(|c| c.is_named())
                    .any(|arg| argument_is_tainted(arg, source));
                if tainted {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: format!(
                            "security:prototype_pollution_merge_sink — \
                             `{func_text}()` called with a potentially \
                             user-controlled argument (JSON.parse output or \
                             HTTP request property); if the source object \
                             contains `__proto__` or `constructor` keys this \
                             enables prototype pollution and may achieve RCE \
                             via Node.js gadget chains"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::Critical,
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_merge_sink_calls(child, source, findings, next_in_safe_scope);
    }
}

/// Scan JS/TS source for prototype pollution merge sink patterns (Layer B).
///
/// Targets known merge utilities (`_.merge`, `Object.assign`, etc.) whose
/// arguments include tainted inputs (`JSON.parse` output, `body`, `query`).
/// Suppressed inside functions named `sanitize*` or `validate*`.
///
/// Phase 3 R&D per `docs/R_AND_D_ROADMAP.md` Section III (Tier 1 AST walk).
fn find_prototype_merge_sink_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files without any known merge utility
    let has_merge = MERGE_CALL_TARGETS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == m.as_bytes()));
    if !has_merge {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding("js")];
    };

    let mut findings = Vec::new();
    find_merge_sink_calls(tree.root_node(), source, &mut findings, false);
    findings
}

// ---------------------------------------------------------------------------
// High-Entropy Token Gate (patch-level)
// ---------------------------------------------------------------------------

/// Compute Shannon entropy of `bytes` in bits per symbol.
///
/// Returns `0.0` for empty input.  Maximum theoretical value is `log2(|alphabet|)`.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Scan a unified-diff `patch` for high-entropy alphanumeric tokens.
///
/// Operates only on added lines (prefix `+`, excluding `+++` headers).
/// Emits one `security:credential_leak` finding per continuous alphanumeric
/// run that satisfies **both**:
/// - length > 32 characters, and
/// - Shannon entropy > 4.5 bits/symbol.
///
/// The 4.5-bit threshold separates random credential tokens (typical entropy
/// ≥5.0 bits) from dictionary words, base64-padded known strings, and UUIDs.
///
/// Each finding contributes +150 pts when wired into
/// [`crate::slop_filter::PatchBouncer::bounce`] — escalated above the
/// standard Critical tier (50 pts) because exposed live credentials are
/// immediately actionable by an adversary.
pub fn detect_secret_entropy(patch: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for line in patch.lines() {
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let src = &line[1..];
        let bytes = src.as_bytes();
        let mut run_start: Option<usize> = None;

        for (i, &b) in bytes.iter().enumerate() {
            if b.is_ascii_alphanumeric() {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(s) = run_start.take() {
                let token = &bytes[s..i];
                if token.len() > 32 {
                    let entropy = shannon_entropy(token);
                    if entropy > 4.5 {
                        findings.push(format!(
                            "security:credential_leak — high-entropy token \
                             ({:.2} bits/symbol, {} chars); possible API key or secret",
                            entropy,
                            token.len()
                        ));
                    }
                }
            }
        }
        // Check trailing run at end of line.
        if let Some(s) = run_start {
            let token = &bytes[s..];
            if token.len() > 32 {
                let entropy = shannon_entropy(token);
                if entropy > 4.5 {
                    findings.push(format!(
                        "security:credential_leak — high-entropy token \
                         ({:.2} bits/symbol, {} chars); possible API key or secret",
                        entropy,
                        token.len()
                    ));
                }
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_language_returns_empty() {
        let findings = find_slop("unknown_lang_xyz", b"some code");
        assert!(findings.is_empty());
    }

    // ── Linter annihilation regression guards (v7.6.0) ────────────────────
    // These tests verify that all deleted stylistic rules remain gone.

    #[test]
    fn test_python_not_flagged() {
        let src = b"def process():\n    import requests\n    return 42\n";
        let findings = find_slop("py", src);
        assert!(findings.is_empty(), "Python rules removed v7.6.0");
    }

    #[test]
    fn test_rust_unsafe_not_flagged() {
        let src = b"fn foo() {\n    unsafe {\n        let x = 1 + 1;\n    }\n}\n";
        let findings = find_slop("rs", src);
        assert!(
            findings.is_empty(),
            "Rust vacuous-unsafe rule removed v7.6.0"
        );
    }

    #[test]
    fn test_js_eval_not_flagged() {
        let src = b"const result = eval(userInput);\n";
        let findings = find_slop("js", src);
        assert!(findings.is_empty(), "JS eval() rule removed v7.6.0");
    }

    #[test]
    fn test_bash_unquoted_var_not_flagged() {
        let src = b"rm -rf $TARGET_DIR\n";
        let findings = find_slop("sh", src);
        assert!(findings.is_empty(), "Bash unquoted-var rule removed v7.6.0");
    }

    // ── C++ regression guard (rule removed v7.1.11) ───────────────────────

    #[test]
    fn test_cpp_raw_new_not_flagged() {
        let src = b"\
#include <string>
void foo() {
    std::string* s = new std::string(\"hello\");
    delete s;
}
";
        let findings = find_slop("cpp", src);
        assert!(
            findings.is_empty(),
            "C++ raw new must NOT be flagged (rule removed v7.1.11)"
        );
    }

    #[test]
    fn test_cpp_raw_delete_not_flagged() {
        let src = b"\
void foo(int* p) {
    delete p;
}
";
        let findings = find_slop("cpp", src);
        assert!(
            findings.is_empty(),
            "C++ raw delete must NOT be flagged (rule removed v7.1.11)"
        );
    }

    // ── YAML tests ────────────────────────────────────────────────────────

    #[test]
    fn test_yaml_virtualservice_wildcard_host_detected() {
        let src = b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - \"*\"
  gateways:
  - bookinfo-gateway
";
        let findings = find_slop("yaml", src);
        assert!(
            !findings.is_empty(),
            "VirtualService with wildcard host must be detected"
        );
        assert!(findings[0].description.contains("VirtualService"));
    }

    #[test]
    fn test_yaml_explicit_host_not_flagged() {
        let src = b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - bookinfo.example.com
";
        let findings = find_slop("yaml", src);
        assert!(
            findings.is_empty(),
            "VirtualService with explicit host must not be flagged"
        );
    }

    // ── C tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_c_gets_detected() {
        let src = b"#include <stdio.h>\nint main() { char buf[64]; gets(buf); return 0; }\n";
        let findings = find_slop("c", src);
        assert!(!findings.is_empty(), "gets() call in C must be detected");
        assert!(findings[0].description.contains("gets()"));
    }

    #[test]
    fn test_c_fgets_not_flagged() {
        let src =
            b"#include <stdio.h>\nint main() { char buf[64]; fgets(buf, sizeof(buf), stdin); return 0; }\n";
        let findings = find_slop("c", src);
        assert!(findings.is_empty(), "fgets() is safe — must not be flagged");
    }

    // ── HCL / Terraform tests ─────────────────────────────────────────────

    #[test]
    fn test_hcl_open_cidr_in_security_group_detected() {
        let src = b"\
resource \"aws_security_group_rule\" \"allow_all\" {
  type        = \"ingress\"
  cidr_blocks = [\"0.0.0.0/0\"]
  from_port   = 0
  to_port     = 65535
  protocol    = \"-1\"
}
";
        let findings = find_slop("tf", src);
        assert!(
            !findings.is_empty(),
            "wildcard CIDR in security group must be detected"
        );
        assert!(findings[0].description.contains("0.0.0.0/0"));
    }

    #[test]
    fn test_hcl_restricted_cidr_not_flagged() {
        let src = b"\
resource \"aws_security_group_rule\" \"office_only\" {
  type        = \"ingress\"
  cidr_blocks = [\"10.0.0.0/8\"]
  from_port   = 443
  to_port     = 443
  protocol    = \"tcp\"
}
";
        let findings = find_slop("tf", src);
        assert!(findings.is_empty(), "restricted CIDR must not be flagged");
    }

    #[test]
    fn test_hcl_wildcard_cidr_without_security_context_not_flagged() {
        let src = b"destination_cidr_block = \"0.0.0.0/0\"\n";
        let findings = find_slop("tf", src);
        assert!(
            findings.is_empty(),
            "wildcard CIDR without security context must not be flagged"
        );
    }

    // ── NCD Entropy Gate tests ────────────────────────────────────────────

    #[test]
    fn test_check_entropy_small_input_exempt() {
        let tiny = b"fn foo() {}";
        let ratio = check_entropy(tiny);
        assert!(
            (ratio - 1.0).abs() < f64::EPSILON,
            "tiny input must return 1.0, got {ratio}"
        );
    }

    #[test]
    fn test_check_entropy_natural_code_above_threshold() {
        let code = b"\
pub fn compute_statistical_summary(data: &[f64]) -> (f64, f64) {
    let n = data.len() as f64;
    let mean = data.iter().copied().sum::<f64>() / n;
    let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

pub fn find_outliers(data: &[f64], threshold: f64) -> Vec<f64> {
    let (mean, std_dev) = compute_statistical_summary(data);
    data.iter()
        .copied()
        .filter(|&x| (x - mean).abs() > threshold * std_dev)
        .collect()
}
";
        let repeated: Vec<u8> = code.iter().copied().cycle().take(512).collect();
        let ratio = check_entropy(&repeated);
        assert!(
            ratio > 0.0 && ratio <= 1.5,
            "natural code ratio out of sane range: {ratio}"
        );
    }

    #[test]
    fn test_check_entropy_repetitive_content_below_threshold() {
        let line = b"    pub fn get_value(&self) -> i32 { self.value }\n";
        let repetitive: Vec<u8> = line.iter().copied().cycle().take(15_000).collect();
        let ratio = check_entropy(&repetitive);
        assert!(
            ratio < MIN_ENTROPY_RATIO,
            "highly repetitive content must trigger gate (ratio={ratio:.4} >= {MIN_ENTROPY_RATIO})"
        );
    }

    // ── C/C++ unsafe string function tests ───────────────────────────────

    #[test]
    fn test_c_strcpy_detected() {
        let src =
            b"#include <string.h>\nvoid foo(char *dst, const char *src) { strcpy(dst, src); }\n";
        let findings = find_slop("c", src);
        assert!(!findings.is_empty(), "strcpy() call in C must be detected");
        assert!(findings[0].description.contains("strcpy()"));
    }

    #[test]
    fn test_c_sprintf_detected() {
        let src = b"#include <stdio.h>\nvoid foo(char *buf, int n) { sprintf(buf, \"%d\", n); }\n";
        let findings = find_slop("c", src);
        assert!(!findings.is_empty(), "sprintf() call in C must be detected");
        assert!(findings[0].description.contains("sprintf()"));
    }

    #[test]
    fn test_c_scanf_detected() {
        let src = b"#include <stdio.h>\nvoid foo() { int x; scanf(\"%d\", &x); }\n";
        let findings = find_slop("c", src);
        assert!(!findings.is_empty(), "scanf() call in C must be detected");
        assert!(findings[0].description.contains("scanf()"));
    }

    #[test]
    fn test_cpp_strcpy_detected() {
        let src =
            b"#include <cstring>\nvoid foo(char *dst, const char *src) { strcpy(dst, src); }\n";
        let findings = find_slop("cpp", src);
        assert!(
            !findings.is_empty(),
            "strcpy() call in C++ must be detected"
        );
    }

    // ── Python subprocess shell=True tests ───────────────────────────────

    #[test]
    fn test_python_subprocess_shell_true_detected() {
        let src = b"import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let findings = find_slop("py", src);
        assert!(
            !findings.is_empty(),
            "subprocess.run with shell=True must be detected"
        );
        assert!(findings[0].description.contains("shell_injection"));
    }

    #[test]
    fn test_python_subprocess_no_shell_not_flagged() {
        let src = b"import subprocess\nsubprocess.run(['ls', '-la'])\n";
        let findings = find_slop("py", src);
        assert!(
            findings.is_empty(),
            "subprocess.run without shell=True must not be flagged"
        );
    }

    #[test]
    fn test_python_shell_true_without_subprocess_not_flagged() {
        let src = b"# shell=True\nx = 1\n";
        let findings = find_slop("py", src);
        assert!(
            findings.is_empty(),
            "shell=True without subprocess must not be flagged"
        );
    }

    // ── JavaScript innerHTML tests ────────────────────────────────────────

    #[test]
    fn test_js_innerhtml_assignment_detected() {
        let src = b"element.innerHTML = userInput;\n";
        let findings = find_slop("js", src);
        assert!(
            !findings.is_empty(),
            "innerHTML assignment in JS must be detected"
        );
        assert!(findings[0].description.contains("innerHTML"));
    }

    #[test]
    fn test_js_textcontent_not_flagged() {
        let src = b"element.textContent = userInput;\n";
        let findings = find_slop("js", src);
        assert!(
            findings.is_empty(),
            "textContent assignment must not be flagged"
        );
    }

    #[test]
    fn test_ts_innerhtml_detected() {
        let src =
            b"const el: HTMLElement = document.getElementById('out')!;\nel.innerHTML = data;\n";
        let findings = find_slop("ts", src);
        assert!(
            !findings.is_empty(),
            "innerHTML assignment in TS must be detected"
        );
    }

    // ── HCL / S3 public ACL tests ─────────────────────────────────────────

    #[test]
    fn test_hcl_s3_public_read_detected() {
        let src = b"\
resource \"aws_s3_bucket_acl\" \"example\" {
  bucket = aws_s3_bucket.example.id
  acl    = \"public-read\"
}
";
        let findings = find_slop("tf", src);
        assert!(!findings.is_empty(), "S3 public-read ACL must be detected");
        assert!(findings[0].description.contains("s3_public_acl"));
    }

    // ── Recursive Boilerplate tests ───────────────────────────────────────

    /// Build a Rust source blob with N structurally identical functions.
    fn make_rust_boilerplate(n: usize) -> Vec<u8> {
        let mut src = String::new();
        for i in 0..n {
            src.push_str(&format!("fn func_{i}(x: i32) -> i32 {{ x + 1 }}\n"));
        }
        src.into_bytes()
    }

    #[test]
    fn test_recursive_boilerplate_below_threshold_not_flagged() {
        // 5 identical bodies — exactly at threshold, must NOT fire (needs >5).
        let src = make_rust_boilerplate(5);
        let result = detect_recursive_boilerplate("rs", &src);
        assert!(
            result.is_none(),
            "5 identical functions must not trigger (threshold is >5): {result:?}"
        );
    }

    #[test]
    fn test_recursive_boilerplate_above_threshold_detected() {
        // 6 identical bodies — one over threshold.
        let src = make_rust_boilerplate(6);
        let result = detect_recursive_boilerplate("rs", &src);
        assert!(
            result.is_some(),
            "6 identical functions must trigger recursive_boilerplate"
        );
        let f = result.unwrap();
        assert!(
            f.description.contains("recursive_boilerplate"),
            "description must contain antipattern label"
        );
        assert_eq!(
            f.severity,
            Severity::Critical,
            "recursive_boilerplate must be Critical severity"
        );
    }

    #[test]
    fn test_recursive_boilerplate_diverse_functions_not_flagged() {
        // 6 functions with distinct bodies — topology hashes diverge, must not fire.
        let src = b"
fn a(x: i32) -> i32 { x + 1 }
fn b(x: i32) -> i32 { x * 2 }
fn c(x: i32, y: i32) -> i32 { x + y }
fn d() -> String { String::new() }
fn e(v: Vec<i32>) -> usize { v.len() }
fn f(s: &str) -> bool { s.is_empty() }
";
        let result = detect_recursive_boilerplate("rs", src);
        assert!(
            result.is_none(),
            "structurally diverse functions must not trigger: {result:?}"
        );
    }

    #[test]
    fn test_recursive_boilerplate_python_detected() {
        // 6 structurally identical Python functions.
        let mut src = String::new();
        for i in 0..6 {
            src.push_str(&format!("def func_{i}(x):\n    return x + 1\n\n"));
        }
        let result = detect_recursive_boilerplate("py", src.as_bytes());
        assert!(
            result.is_some(),
            "6 identical Python functions must trigger recursive_boilerplate"
        );
    }

    #[test]
    fn test_recursive_boilerplate_unsupported_language_returns_none() {
        // YAML has no function nodes — must return None silently.
        let src = b"key: value\n";
        let result = detect_recursive_boilerplate("yaml", src);
        assert!(result.is_none(), "unsupported language must return None");
    }

    #[test]
    fn test_hcl_s3_private_not_flagged() {
        let src = b"\
resource \"aws_s3_bucket_acl\" \"example\" {
  bucket = aws_s3_bucket.example.id
  acl    = \"private\"
}
";
        let findings = find_slop("tf", src);
        assert!(findings.is_empty(), "S3 private ACL must not be flagged");
    }

    // ── YAML: remaining K8S_ROUTING_KINDS coverage ────────────────────────

    #[test]
    fn test_yaml_ingress_wildcard_host_detected() {
        let src = b"\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
spec:
  hosts:
  - \"*\"
";
        let findings = find_slop("yaml", src);
        assert!(
            !findings.is_empty(),
            "Ingress with wildcard host must be detected"
        );
        assert!(
            findings[0].description.contains("Ingress"),
            "description must name the resource kind"
        );
    }

    #[test]
    fn test_yaml_httproute_wildcard_host_detected() {
        let src = b"\
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
spec:
  hosts:
  - \"*\"
";
        let findings = find_slop("yaml", src);
        assert!(
            !findings.is_empty(),
            "HTTPRoute with wildcard host must be detected"
        );
        assert!(
            findings[0].description.contains("HTTPRoute"),
            "description must name the resource kind"
        );
    }

    #[test]
    fn test_yaml_gateway_wildcard_host_detected() {
        let src = b"\
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: test-gw
spec:
  hosts:
  - \"*\"
";
        let findings = find_slop("yaml", src);
        assert!(
            !findings.is_empty(),
            "Gateway with wildcard host must be detected"
        );
        assert!(
            findings[0].description.contains("Gateway"),
            "description must name the resource kind"
        );
    }

    // ── C++: gap-fill for gets/sprintf/scanf (only strcpy was tested) ─────

    #[test]
    fn test_cpp_gets_detected() {
        let src = b"#include <cstdio>\nvoid f() { char buf[64]; gets(buf); }\n";
        let findings = find_slop("cpp", src);
        assert!(!findings.is_empty(), "gets() in C++ must be detected");
        assert!(
            findings[0].description.contains("gets()"),
            "description must cite gets()"
        );
    }

    #[test]
    fn test_cpp_sprintf_detected() {
        let src =
            b"#include <cstdio>\nvoid f(char *buf, const char *in) { sprintf(buf, \"%s\", in); }\n";
        let findings = find_slop("cpp", src);
        assert!(!findings.is_empty(), "sprintf() in C++ must be detected");
        assert!(
            findings[0].description.contains("sprintf()"),
            "description must cite sprintf()"
        );
    }

    #[test]
    fn test_cpp_scanf_detected() {
        let src = b"#include <cstdio>\nvoid f() { char buf[64]; scanf(\"%s\", buf); }\n";
        let findings = find_slop("cpp", src);
        assert!(!findings.is_empty(), "scanf() in C++ must be detected");
        assert!(
            findings[0].description.contains("scanf()"),
            "description must cite scanf()"
        );
    }

    #[test]
    fn test_cpp_safe_strncpy_not_flagged() {
        let src =
            b"#include <cstring>\nvoid f(char *d, size_t n, const char *s) { strncpy(d, s, n - 1); d[n-1] = '\\0'; }\n";
        let findings = find_slop("cpp", src);
        assert!(findings.is_empty(), "strncpy() in C++ must not be flagged");
    }
}

#[cfg(test)]
mod logic_regression_tests {
    use super::check_logic_regression;

    /// Helper: build a minimal unified-diff patch from base and head line sets.
    fn make_patch(base_lines: &[&str], head_lines: &[&str]) -> String {
        let mut patch = String::from("--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n");
        for l in base_lines {
            patch.push('-');
            patch.push_str(l);
            patch.push('\n');
        }
        for l in head_lines {
            patch.push('+');
            patch.push_str(l);
            patch.push('\n');
        }
        patch
    }

    #[test]
    fn test_logic_erasure_fires_on_branch_reduction() {
        // Base: 5 branch lines, Head: 1 branch line — 80% reduction, same volume.
        let base = &[
            "if x > 0 {",
            "    if y > 0 {",
            "    match z { A => 1, B => 2 }",
            "    if w > 0 { return; }",
            "    if q { break; }",
            "    return base_value;",
        ];
        let head = &[
            "if x > 0 {",
            "    return simplified;",
            "    let a = 1;",
            "    let b = 2;",
            "    let c = 3;",
            "    return a + b + c;",
        ];
        let patch = make_patch(base, head);
        let result = check_logic_regression(&patch);
        assert!(result.is_some(), "logic_erasure should fire");
        let f = result.unwrap();
        assert!(
            f.description.contains("logic_erasure"),
            "description must contain 'logic_erasure'"
        );
    }

    #[test]
    fn test_logic_erasure_does_not_fire_when_branches_preserved() {
        // Base and head both have 4 branch lines — no regression.
        let base = &[
            "if a { do_x(); }",
            "if b { do_y(); }",
            "match c { X => 1, Y => 2 }",
            "if d { return; }",
        ];
        let head = &[
            "if a { do_x(); }",
            "if b { do_y_v2(); }",
            "match c { X => 1, Y => 2 }",
            "if d { return; }",
        ];
        let patch = make_patch(base, head);
        assert!(
            check_logic_regression(&patch).is_none(),
            "no regression when branch count is preserved"
        );
    }

    #[test]
    fn test_logic_erasure_does_not_fire_below_min_base_branches() {
        // Base has only 2 branch lines — below the minimum threshold of 3.
        let base = &["if a { do_x(); }", "if b { do_y(); }", "return z;"];
        let head = &["return simplified;", "return simplified;", "return z;"];
        let patch = make_patch(base, head);
        assert!(
            check_logic_regression(&patch).is_none(),
            "should not fire when base has fewer than 3 branches"
        );
    }

    #[test]
    fn test_logic_erasure_does_not_fire_on_volume_change() {
        // Base: 4 branches in 4 lines, Head: 0 branches in 40 lines — volume too different.
        let base_lines: Vec<&str> = vec!["if a { 1 }", "if b { 2 }", "if c { 3 }", "if d { 4 }"];
        let mut head_lines: Vec<&str> = Vec::new();
        for _ in 0..40 {
            head_lines.push("let x = 1;");
        }
        let patch = make_patch(&base_lines, &head_lines);
        assert!(
            check_logic_regression(&patch).is_none(),
            "should not fire when code volume changes significantly"
        );
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    // ── find_credential_slop ─────────────────────────────────────────────

    #[test]
    fn test_aws_key_prefix_detected_by_credential_slop() {
        let src = b"const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";";
        let findings = find_credential_slop(src);
        assert!(!findings.is_empty(), "AKIA prefix must be detected");
        assert!(
            findings[0].description.contains("credential_leak"),
            "description must cite credential_leak"
        );
        assert!(findings[0].description.contains("AWS"));
    }

    #[test]
    fn test_rsa_private_key_header_detected() {
        let src = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA";
        let findings = find_credential_slop(src);
        assert!(!findings.is_empty(), "RSA PEM header must be detected");
        assert!(findings[0].description.contains("RSA private key"));
    }

    #[test]
    fn test_stripe_live_key_detected() {
        // Assembled at runtime so the literal `sk_live_` prefix does not
        // appear in source and cannot be flagged by static push-protection
        // scanners.  Our AhoCorasick trigger fires on the prefix alone.
        let mut src = b"key = sk_".to_vec();
        src.extend_from_slice(b"live_FakeTestOnlyNotARealKey");
        let findings = find_credential_slop(&src);
        assert!(
            !findings.is_empty(),
            "Stripe live key prefix must be detected"
        );
        assert!(findings[0].description.contains("Stripe"));
    }

    #[test]
    fn test_clean_source_not_flagged() {
        let src = b"fn greet(name: &str) { println!(\"Hello, {name}!\"); }";
        let findings = find_credential_slop(src);
        assert!(
            findings.is_empty(),
            "clean source must not trigger credential scanner"
        );
    }

    #[test]
    fn test_find_slop_propagates_credential_findings_for_all_langs() {
        // Rust is not in the language match arms — verifies the credential
        // scan runs even for unsupported language extensions.
        let src = b"const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";";
        let findings = find_slop("rs", src);
        assert!(
            !findings.is_empty(),
            "find_slop must forward credential findings for unknown lang"
        );
    }

    // ── shannon_entropy ──────────────────────────────────────────────────

    #[test]
    fn test_shannon_entropy_uniform_bytes_is_zero() {
        // All identical bytes → entropy = 0.
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_two_equal_probability_bytes() {
        // Two equally probable symbols → entropy = 1.0 bit/symbol.
        let h = shannon_entropy(b"aabb");
        assert!(
            (h - 1.0).abs() < 1e-9,
            "two equal-prob bytes: entropy must be 1.0, got {h}"
        );
    }

    #[test]
    fn test_shannon_entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    // ── detect_secret_entropy ────────────────────────────────────────────

    #[test]
    fn test_high_entropy_token_in_added_line_detected() {
        // 33-char mixed-case alphanumeric token (all unique chars) — entropy
        // = log2(33) ≈ 5.04 bits/symbol, well above the 4.5-bit threshold.
        let patch = "+const SECRET: &str = \"xK9mP2nQ8wR5vL3jB7hF4dC6uT1iY0eAz\";\n";
        let findings = detect_secret_entropy(patch);
        assert!(
            !findings.is_empty(),
            "high-entropy 33-char token must be detected"
        );
        assert!(findings[0].contains("credential_leak"));
    }

    #[test]
    fn test_removed_line_not_flagged_by_entropy_gate() {
        // Lines starting with `-` are removals — must NOT be scanned.
        let patch = "-const SECRET: &str = \"xK9mP2nQ8wR5vL3jB7hF4dC6uT1iY0eAz\";\n";
        let findings = detect_secret_entropy(patch);
        assert!(
            findings.is_empty(),
            "removed lines must not be flagged by entropy detector"
        );
    }

    #[test]
    fn test_low_entropy_long_token_not_flagged() {
        // 40 repeated characters — entropy = 0, well below 4.5.
        let patch = "+const KEY: &str = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n";
        let findings = detect_secret_entropy(patch);
        assert!(
            findings.is_empty(),
            "low-entropy repeated characters must not trigger entropy gate"
        );
    }

    #[test]
    fn test_short_token_under_threshold_not_flagged() {
        // 16-char token — below the > 32-char length gate.
        let patch = "+const KEY: &str = \"xK9mP2nQ8wR5vL3j\";\n";
        let findings = detect_secret_entropy(patch);
        assert!(
            findings.is_empty(),
            "token ≤32 chars must not trigger entropy gate"
        );
    }

    // ── find_supply_chain_slop ────────────────────────────────────────────────

    #[test]
    fn test_external_script_tag_detected_by_supply_chain() {
        let src = b"<script src=\"https://cdn.example.com/analytics.js\"></script>";
        let findings = find_supply_chain_slop(src);
        assert!(
            !findings.is_empty(),
            "<script src=\"https://…\" must be flagged as unpinned_asset"
        );
        assert!(
            findings[0].description.contains("unpinned_asset"),
            "description must cite unpinned_asset"
        );
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_relative_script_not_flagged_by_supply_chain() {
        let src = b"<script src=\"/js/app.js\" type=\"module\"></script>";
        let findings = find_supply_chain_slop(src);
        assert!(
            findings.is_empty(),
            "relative script path must not trigger supply-chain detector"
        );
    }

    #[test]
    fn test_github_io_url_detected_by_supply_chain() {
        let src = b"const LIB = \"https://some-org.github.io/lib/v2/bundle.js\";";
        let findings = find_supply_chain_slop(src);
        assert!(
            !findings.is_empty(),
            ".github.io/ URL must be flagged as unpinned_asset"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_asset")),
            "must have unpinned_asset finding"
        );
    }

    #[test]
    fn test_github_com_not_flagged_by_supply_chain() {
        let src = b"const REPO = \"https://github.com/owner/repo/releases\";";
        let findings = find_supply_chain_slop(src);
        assert!(
            findings.is_empty(),
            "github.com URL must not be flagged by supply-chain detector"
        );
    }

    #[test]
    fn test_find_slop_propagates_supply_chain_findings() {
        // Verify find_slop() surfaces supply-chain findings for any language.
        let src = b"var cdn = \"https://evil.github.io/inject.js\";";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_asset")),
            "find_slop must forward supply-chain findings"
        );
    }
}

#[cfg(test)]
mod kev_tests {
    use super::*;

    // ── Severity tier ──────────────────────────────────────────────────────

    #[test]
    fn test_kev_critical_severity_points() {
        assert_eq!(
            Severity::KevCritical.points(),
            150,
            "KevCritical tier must contribute 150 points"
        );
    }

    #[test]
    fn test_kev_critical_does_not_shift_lower_tiers() {
        // Regression guard: inserting KevCritical must not renumber existing tiers.
        assert_eq!(Severity::Exhaustion.points(), 100);
        assert_eq!(Severity::Critical.points(), 50);
        assert_eq!(Severity::Warning.points(), 10);
        assert_eq!(Severity::Lint.points(), 0);
    }

    // ── Python SQLi ────────────────────────────────────────────────────────

    #[test]
    fn test_python_sqli_concatenation_detected() {
        let src = b"cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("sqli_concatenation")),
            "Python SQLi concat must fire"
        );
    }

    #[test]
    fn test_python_sqli_parameterized_not_flagged() {
        let src = b"cursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("sqli_concatenation")),
            "parameterized Python query must not be flagged"
        );
    }

    // ── Go SQLi ────────────────────────────────────────────────────────────

    #[test]
    fn test_go_sqli_concatenation_detected() {
        let src = b"rows, _ := db.Query(\"SELECT * FROM users WHERE id=\" + userId)";
        let findings = find_slop("go", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("sqli_concatenation")),
            "Go SQLi concat must fire"
        );
    }

    #[test]
    fn test_go_sqli_parameterized_not_flagged() {
        let src = b"rows, _ := db.Query(\"SELECT * FROM users WHERE id=$1\", userId)";
        let findings = find_slop("go", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("sqli_concatenation")),
            "parameterized Go query must not be flagged"
        );
    }

    // ── Python SSRF ────────────────────────────────────────────────────────

    #[test]
    fn test_python_ssrf_dynamic_url_detected() {
        let src = b"response = requests.get(\"https://internal.corp/\" + user_input)";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("ssrf_dynamic_url")),
            "Python SSRF dynamic URL must fire"
        );
    }

    #[test]
    fn test_python_ssrf_static_url_not_flagged() {
        let src = b"response = requests.get(\"https://api.example.com/users/123\")";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("ssrf_dynamic_url")),
            "Python SSRF static URL must not be flagged"
        );
    }

    // ── JS SSRF ────────────────────────────────────────────────────────────

    #[test]
    fn test_js_ssrf_dynamic_fetch_detected() {
        let src = b"const resp = await fetch(\"https://api.example.com/\" + userId);";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("ssrf_dynamic_url")),
            "JS SSRF dynamic fetch must fire"
        );
    }

    #[test]
    fn test_js_ssrf_static_fetch_not_flagged() {
        let src = b"const resp = await fetch(\"https://api.example.com/users/123\");";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("ssrf_dynamic_url")),
            "JS SSRF static fetch must not be flagged"
        );
    }

    // ── Python path traversal ──────────────────────────────────────────────

    #[test]
    fn test_python_path_traversal_concat_detected() {
        let src = b"with open(base_dir + user_file, 'r') as f:\n    content = f.read()\n";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("path_traversal_concatenation")),
            "Python path traversal concat must fire"
        );
    }

    #[test]
    fn test_python_path_traversal_os_path_join_not_flagged() {
        let src =
            b"import os\nwith open(os.path.join(base_dir, user_file), 'r') as f:\n    content = f.read()\n";
        let findings = find_slop("py", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("path_traversal_concatenation")),
            "os.path.join must not be flagged"
        );
    }

    // ── JS path traversal ─────────────────────────────────────────────────

    #[test]
    fn test_js_path_traversal_readfile_concat_detected() {
        let src = b"fs.readFile(uploadDir + filename, 'utf8', callback);";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("path_traversal_concatenation")),
            "JS path traversal readFile concat must fire"
        );
    }

    #[test]
    fn test_js_path_traversal_path_join_not_flagged() {
        let src = b"const p = path.join(uploadDir, filename);\nfs.readFile(p, 'utf8', callback);";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("path_traversal_concatenation")),
            "path.join must not be flagged"
        );
    }
}

#[cfg(test)]
mod exhaustion_tests {
    use super::*;

    #[test]
    fn test_exhaustion_severity_points() {
        assert_eq!(
            Severity::Exhaustion.points(),
            100,
            "Exhaustion tier must contribute 100 points"
        );
    }

    #[test]
    fn test_critical_severity_points_unchanged() {
        // Regression guard: adding Exhaustion must not shift Critical.
        assert_eq!(Severity::Critical.points(), 50);
        assert_eq!(Severity::Warning.points(), 10);
        assert_eq!(Severity::Lint.points(), 0);
    }

    #[test]
    fn test_parser_exhaustion_finding_content() {
        let f = parser_exhaustion_finding("yaml");
        assert!(
            f.description.contains("parser_exhaustion_anomaly"),
            "finding must cite parser_exhaustion_anomaly"
        );
        assert!(
            f.description.contains(".yaml"),
            "finding must embed the lang hint"
        );
        assert_eq!(
            f.severity,
            Severity::Exhaustion,
            "finding severity must be Exhaustion"
        );
        assert_eq!(f.domain, crate::metadata::DOMAIN_ALL);
    }

    #[test]
    fn test_parser_exhaustion_finding_clean_source_does_not_fire() {
        // A trivial source file must parse in well under 500 ms — no exhaustion finding.
        let src = b"fn main() {}";
        let findings = find_slop("rs", src);
        assert!(
            findings.iter().all(|f| f.severity != Severity::Exhaustion),
            "clean trivial source must not trigger exhaustion"
        );
    }
}

#[cfg(test)]
mod phase1_rd_tests {
    use super::*;

    // ── Java deserialization ─────────────────────────────────────────────────

    #[test]
    fn test_java_object_input_stream_fires() {
        let src = b"ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());\nObject obj = ois.readObject();\n";
        let findings = find_java_slop_fast(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "new ObjectInputStream( must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_java_runtime_exec_fires() {
        let src = b"Process p = Runtime.getRuntime().exec(userInput);\n";
        let findings = find_java_slop_fast(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("runtime_exec")),
            "Runtime.getRuntime().exec( must fire runtime_exec"
        );
    }

    #[test]
    fn test_java_jndi_lookup_fires() {
        let src = b"Context ctx = new InitialContext();\nObject obj = ctx.lookup(userInput);\nInitialContext().lookup(userInput);\n";
        let findings = find_java_slop_fast(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("jndi_injection")),
            "InitialContext().lookup( must fire jndi_injection"
        );
    }

    #[test]
    fn test_java_clean_serializable_override_safe() {
        // A class that only implements Serializable with no dangerous API calls
        let src = b"public class Foo implements Serializable {\n    private static final long serialVersionUID = 1L;\n}\n";
        let findings = find_java_slop_fast(src);
        assert!(
            findings.is_empty(),
            "clean Serializable class must not fire"
        );
    }

    // ── C# deserialization ───────────────────────────────────────────────────

    #[test]
    fn test_csharp_binary_formatter_fires() {
        let src = b"var bf = new BinaryFormatter();\nbf.Serialize(stream, obj);\n";
        let findings = find_csharp_slop_fast(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "new BinaryFormatter() must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_csharp_type_name_handling_auto_fires() {
        let src = b"var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };\n";
        let findings = find_csharp_slop_fast(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "TypeNameHandling.Auto must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_csharp_type_name_handling_none_is_safe() {
        // TypeNameHandling.None is the safe default — must NOT fire.
        let src = b"var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n";
        let findings = find_csharp_slop_fast(src);
        assert!(findings.is_empty(), "TypeNameHandling.None must not fire");
    }

    #[test]
    fn test_csharp_clean_json_settings_safe() {
        let src = b"var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };\n";
        let findings = find_csharp_slop_fast(src);
        assert!(
            findings.is_empty(),
            "clean JsonSerializerSettings must not fire"
        );
    }

    // ── Prototype Pollution ──────────────────────────────────────────────────

    #[test]
    fn test_prototype_pollution_dunder_proto_fires() {
        let src = b"obj.__proto__.isAdmin = true;\n";
        let findings = find_prototype_pollution_slop(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution")),
            ".__proto__ must fire prototype_pollution"
        );
    }

    #[test]
    fn test_prototype_pollution_bracket_fires() {
        let src = b"target[\"__proto__\"][\"admin\"] = true;\n";
        let findings = find_prototype_pollution_slop(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution")),
            "[\"__proto__\"] must fire prototype_pollution"
        );
    }

    #[test]
    fn test_prototype_pollution_constructor_chain_fires() {
        let src = b"obj[constructor][prototype].isAdmin = true;\n";
        let findings = find_prototype_pollution_slop(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution")),
            "[constructor][prototype] must fire prototype_pollution"
        );
    }

    #[test]
    fn test_prototype_pollution_clean_proto_string_safe() {
        // A string literal that mentions "__proto__" in a comment or doc — must not fire
        // because the pattern `.__proto__` requires the dot prefix.
        let src = b"// The __proto__ key is dangerous in merge utilities.\nconst safe = { key: 'value' };\n";
        let findings = find_prototype_pollution_slop(src);
        assert!(
            findings.is_empty(),
            "bare __proto__ in comment without dot prefix must not fire"
        );
    }

    // ── find_slop dispatch integration ──────────────────────────────────────

    #[test]
    fn test_find_slop_java_dispatches_danger_patterns() {
        let src = b"ObjectInputStream ois = new ObjectInputStream(in);\n";
        let findings = find_slop("java", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "find_slop(java) must route to java danger patterns"
        );
    }

    #[test]
    fn test_find_slop_cs_dispatches_danger_patterns() {
        let src = b"var bf = new BinaryFormatter();\n";
        let findings = find_slop("cs", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "find_slop(cs) must route to csharp danger patterns"
        );
    }

    #[test]
    fn test_find_slop_js_dispatches_prototype_pollution() {
        let src = b"merge(target, src);\ntarget.__proto__.admin = true;\n";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution")),
            "find_slop(js) must route to prototype pollution patterns"
        );
    }
}

#[cfg(test)]
mod phase2_rd_tests {
    use super::*;

    fn eng() -> &'static QueryEngine {
        engine().expect("QueryEngine must initialise in tests")
    }

    // ── Python dangerous-call AST walk ───────────────────────────────────────

    #[test]
    fn test_python_exec_fires() {
        let src = b"exec(user_input)\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("code_execution")),
            "exec() must fire code_execution"
        );
    }

    #[test]
    fn test_python_eval_fires_in_production_code() {
        let src = b"result = eval(expression)\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("dynamic_eval")),
            "eval() in production code must fire dynamic_eval"
        );
    }

    #[test]
    fn test_python_eval_suppressed_in_test_function() {
        let src =
            b"def test_eval_behavior():\n    result = eval('1 + 2')\n    assert result == 3\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("dynamic_eval")),
            "eval() inside test_ function must be suppressed"
        );
    }

    #[test]
    fn test_python_eval_suppressed_by_noqa() {
        let src = b"result = eval(expression)  # noqa\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("dynamic_eval")),
            "eval() with # noqa must be suppressed"
        );
    }

    #[test]
    fn test_python_pickle_loads_fires() {
        let src = b"import pickle\nobj = pickle.loads(data)\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "pickle.loads() must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_python_os_system_fires() {
        let src = b"import os\nos.system(cmd)\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("os_command_injection")),
            "os.system() must fire os_command_injection"
        );
    }

    #[test]
    fn test_python_dunder_import_fires() {
        let src = b"mod = __import__(module_name)\n";
        let findings = find_python_slop_ast(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("dynamic_import")),
            "__import__() must fire dynamic_import"
        );
    }

    #[test]
    fn test_python_ast_literal_eval_safe() {
        let src = b"import ast\nresult = ast.literal_eval(user_input)\n";
        let findings = find_python_slop_ast(eng(), src);
        // ast.literal_eval is not in PYTHON_DANGER_CALLS — must be silent.
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("dynamic_eval")),
            "ast.literal_eval() must not fire"
        );
    }

    // ── Java method-invocation AST walk ─────────────────────────────────────

    #[test]
    fn test_java_read_object_fires() {
        let src =
            b"ObjectInputStream ois = new ObjectInputStream(in);\nObject obj = ois.readObject();\n";
        let findings = find_java_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "ObjectInputStream.readObject() must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_java_runtime_exec_fires() {
        let src = b"Process p = Runtime.getRuntime().exec(userInput);\n";
        let findings = find_java_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("runtime_exec")),
            "Runtime.getRuntime().exec() must fire runtime_exec"
        );
    }

    #[test]
    fn test_java_jndi_dynamic_fires() {
        let src =
            b"InitialContext ctx = new InitialContext();\nObject obj = ctx.lookup(userInput);\n";
        let findings = find_java_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("jndi_injection")),
            "ctx.lookup(dynamic) must fire jndi_injection"
        );
    }

    #[test]
    fn test_java_jndi_static_string_safe() {
        let src = b"InitialContext ctx = new InitialContext();\nDataSource ds = (DataSource) ctx.lookup(\"java:comp/env/jdbc/mydb\");\n";
        let findings = find_java_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("jndi_injection")),
            "ctx.lookup(string_literal) must NOT fire"
        );
    }

    #[test]
    fn test_java_clean_mapper_read_value_safe() {
        let src = b"ObjectMapper mapper = new ObjectMapper();\nMyClass obj = mapper.readValue(json, MyClass.class);\n";
        let findings = find_java_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("unsafe_deserialization")),
            "ObjectMapper.readValue() must not fire"
        );
    }
}

#[cfg(test)]
mod phase3_rd_tests {
    use super::*;

    fn eng() -> &'static QueryEngine {
        engine().expect("QueryEngine must initialise in tests")
    }

    // ── C# AST walk (TypeNameHandling + BinaryFormatter) ─────────────────────

    #[test]
    fn test_csharp_type_name_handling_all_fires_via_ast() {
        let src =
            b"var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n";
        let findings = find_csharp_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "TypeNameHandling.All must fire unsafe_deserialization via AST"
        );
    }

    #[test]
    fn test_csharp_type_name_handling_objects_fires_via_ast() {
        let src = b"settings.TypeNameHandling = TypeNameHandling.Objects;\n";
        let findings = find_csharp_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "TypeNameHandling.Objects must fire unsafe_deserialization via AST"
        );
    }

    #[test]
    fn test_csharp_binary_formatter_fires_via_ast() {
        let src =
            b"BinaryFormatter formatter = new BinaryFormatter();\nformatter.Serialize(ms, obj);\n";
        let findings = find_csharp_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "new BinaryFormatter() must fire unsafe_deserialization via AST"
        );
    }

    #[test]
    fn test_csharp_type_name_handling_none_safe_via_ast() {
        let src =
            b"var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n";
        let findings = find_csharp_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("unsafe_deserialization")),
            "TypeNameHandling.None must NOT fire via AST"
        );
    }

    #[test]
    fn test_csharp_clean_stj_safe_via_ast() {
        let src = b"var obj = System.Text.Json.JsonSerializer.Deserialize<MyType>(json);\n";
        let findings = find_csharp_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("unsafe_deserialization")),
            "System.Text.Json deserialization must NOT fire via AST"
        );
    }

    // ── Prototype Pollution Layer B (merge sink AST walk) ─────────────────────

    #[test]
    fn test_pp_merge_sink_json_parse_arg_fires() {
        // Inline JSON.parse as a direct argument is the canonical tainted pattern.
        let src = b"_.merge(target, JSON.parse(userInput));\n";
        let findings = find_prototype_merge_sink_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution_merge_sink")),
            "_.merge with inline JSON.parse arg must fire prototype_pollution_merge_sink"
        );
    }

    #[test]
    fn test_pp_merge_sink_req_body_fires() {
        let src = b"Object.assign(config, req.body);\n";
        let findings = find_prototype_merge_sink_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution_merge_sink")),
            "Object.assign with req.body must fire prototype_pollution_merge_sink"
        );
    }

    #[test]
    fn test_pp_merge_sink_query_identifier_fires() {
        let src = b"_.merge(defaults, query);\n";
        let findings = find_prototype_merge_sink_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution_merge_sink")),
            "_.merge with query identifier must fire"
        );
    }

    #[test]
    fn test_pp_merge_sink_suppressed_in_sanitize_function() {
        let src = b"function sanitizeAndMerge(target, source) {\n    _.merge(target, source);\n    return target;\n}\n";
        // 'source' is not in USER_INPUT_NAMES so this wouldn't fire anyway,
        // but we verify suppression logic by using a tainted name in a sanitize function.
        let src2 = b"function sanitizeInput(target) {\n    _.merge(target, req.body);\n    return target;\n}\n";
        let findings = find_prototype_merge_sink_slop(eng(), src2);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("prototype_pollution_merge_sink")),
            "_.merge inside sanitize function must be suppressed"
        );
    }

    #[test]
    fn test_pp_merge_sink_clean_literal_arg_safe() {
        // Merging a literal object — no user input, must not fire.
        let src = b"_.merge(defaults, { theme: 'dark', locale: 'en' });\n";
        let findings = find_prototype_merge_sink_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("prototype_pollution_merge_sink")),
            "_.merge with literal object must NOT fire"
        );
    }

    // ── find_slop dispatch integration ───────────────────────────────────────

    #[test]
    fn test_find_slop_cs_csharp_slop_dispatched() {
        let src = b"settings.TypeNameHandling = TypeNameHandling.Auto;\n";
        let findings = find_slop("cs", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "find_slop(cs) must dispatch to csharp_slop AST walk"
        );
    }

    #[test]
    fn test_find_slop_js_merge_sink_dispatched() {
        let src = b"_.merge(config, JSON.parse(data));\n";
        let findings = find_slop("js", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("prototype_pollution_merge_sink")),
            "find_slop(js) must dispatch to merge sink AST walk"
        );
    }
}

#[cfg(test)]
mod phase4_rd_tests {
    use super::*;

    fn eng() -> &'static QueryEngine {
        engine().expect("QueryEngine must initialise in tests")
    }

    // ── Go-1: exec.Command shell injection ───────────────────────────────────

    #[test]
    fn test_go_exec_command_bash_fires() {
        let src = b"cmd := exec.Command(\"bash\", \"-c\", userInput)\ncmd.Run()\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("command_injection_shell_exec")),
            "exec.Command(\"bash\", ...) must fire command_injection_shell_exec"
        );
    }

    #[test]
    fn test_go_exec_command_sh_fires() {
        let src = b"cmd := exec.Command(\"sh\", \"-c\", input)\ncmd.Run()\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("command_injection_shell_exec")),
            "exec.Command(\"sh\", ...) must fire command_injection_shell_exec"
        );
    }

    #[test]
    fn test_go_exec_command_non_shell_safe() {
        let src = b"cmd := exec.Command(\"git\", \"status\")\ncmd.Run()\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("command_injection_shell_exec")),
            "exec.Command(\"git\", ...) must not fire command_injection_shell_exec"
        );
    }

    #[test]
    fn test_go_exec_command_in_test_func_suppressed() {
        // Call site inside a function named TestSomething — must be suppressed.
        let src = b"func TestRunShell(t *testing.T) {\n    cmd := exec.Command(\"bash\", \"-c\", \"echo hi\")\n    cmd.Run()\n}\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("command_injection_shell_exec")),
            "exec.Command in test function must be suppressed"
        );
    }

    // ── Go-2: InsecureSkipVerify: true ───────────────────────────────────────

    #[test]
    fn test_go_insecure_skip_verify_true_fires() {
        let src = b"tr := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n}\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("tls_verification_bypass")),
            "InsecureSkipVerify: true must fire tls_verification_bypass"
        );
    }

    #[test]
    fn test_go_insecure_skip_verify_false_safe() {
        let src = b"tr := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},\n}\n";
        let findings = find_go_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("tls_verification_bypass")),
            "InsecureSkipVerify: false must not fire tls_verification_bypass"
        );
    }

    #[test]
    fn test_find_slop_go_dispatches_phase4() {
        let src = b"tr := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n}\n";
        let findings = find_slop("go", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("tls_verification_bypass")),
            "find_slop(go) must dispatch to Phase 4 Go AST walk"
        );
    }

    // ── Ruby-1: dynamic eval/system/exec/spawn ───────────────────────────────

    #[test]
    fn test_ruby_eval_dynamic_fires() {
        let src = b"eval(params[:code])\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("dangerous_execution")),
            "eval(dynamic_arg) must fire dangerous_execution"
        );
    }

    #[test]
    fn test_ruby_eval_string_literal_safe() {
        let src = b"eval(\"1 + 1\")\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("dangerous_execution")),
            "eval(string_literal) must not fire dangerous_execution"
        );
    }

    #[test]
    fn test_ruby_system_dynamic_fires() {
        let src = b"system(user_command)\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("dangerous_execution")),
            "system(dynamic_arg) must fire dangerous_execution"
        );
    }

    // ── Ruby-2: Marshal.load deserialization ─────────────────────────────────

    #[test]
    fn test_ruby_marshal_load_fires() {
        let src = b"obj = Marshal.load(user_data)\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "Marshal.load must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_ruby_marshal_restore_fires() {
        let src = b"obj = Marshal.restore(payload)\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unsafe_deserialization")),
            "Marshal.restore must fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_ruby_marshal_dump_safe() {
        // Marshal.dump serializes — does not execute code.
        let src = b"data = Marshal.dump(object)\n";
        let findings = find_ruby_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("unsafe_deserialization")),
            "Marshal.dump must not fire unsafe_deserialization"
        );
    }

    #[test]
    fn test_find_slop_rb_dispatches_phase4() {
        let src = b"eval(params[:cmd])\n";
        let findings = find_slop("rb", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("dangerous_execution")),
            "find_slop(rb) must dispatch to Phase 4 Ruby AST walk"
        );
    }

    // ── Bash-1: curl|bash pipeline ───────────────────────────────────────────

    #[test]
    fn test_bash_curl_pipe_bash_fires() {
        let src = b"curl https://install.example.com/setup.sh | bash\n";
        let findings = find_bash_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("curl_pipe_execution")),
            "curl ... | bash must fire curl_pipe_execution"
        );
    }

    #[test]
    fn test_bash_wget_pipe_sh_fires() {
        let src = b"wget -qO- https://example.com/install.sh | sh\n";
        let findings = find_bash_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("curl_pipe_execution")),
            "wget ... | sh must fire curl_pipe_execution"
        );
    }

    #[test]
    fn test_bash_curl_download_then_exec_safe() {
        // Download-then-verify pattern — not a pipeline to bash.
        let src = b"curl -o setup.sh https://install.example.com/setup.sh && bash setup.sh\n";
        let findings = find_bash_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("curl_pipe_execution")),
            "curl -o ... && bash must not fire curl_pipe_execution"
        );
    }

    // ── Bash-2: eval with unquoted variable expansion ────────────────────────

    #[test]
    fn test_bash_eval_unquoted_var_fires() {
        let src = b"eval $USER_COMMAND\n";
        let findings = find_bash_slop(eng(), src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("eval_injection")),
            "eval $VAR must fire eval_injection"
        );
    }

    #[test]
    fn test_bash_eval_string_literal_safe() {
        let src = b"eval \"echo hello\"\n";
        let findings = find_bash_slop(eng(), src);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("eval_injection")),
            "eval \"string literal\" must not fire eval_injection"
        );
    }

    #[test]
    fn test_find_slop_sh_dispatches_phase4() {
        let src = b"curl https://install.example.com/setup.sh | bash\n";
        let findings = find_slop("sh", src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("curl_pipe_execution")),
            "find_slop(sh) must dispatch to Phase 4 Bash AST walk"
        );
    }
}
