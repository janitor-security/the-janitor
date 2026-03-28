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
use std::sync::OnceLock;

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
/// | Tier       | Points |
/// |------------|--------|
/// | `Critical` |  50    |
/// | `Warning`  |  10    |
/// | `Lint`     |   0    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Security-critical finding — contributes 50 points.
    ///
    /// Examples: Kubernetes wildcard hosts, open-world CIDR rules, `gets()` calls,
    /// Unicode injection, LotL execution, AST-Bomb DoS.
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
            Self::Critical => 50,
            Self::Warning => 10,
            Self::Lint => 0,
        }
    }
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
    /// JavaScript grammar — used for `innerHTML` assignment detection.
    js_lang: Language,
}

impl QueryEngine {
    fn new() -> anyhow::Result<Self> {
        let yaml_lang: Language = tree_sitter_yaml::LANGUAGE.into();
        let c_lang: Language = tree_sitter_c::LANGUAGE.into();
        let js_lang: Language = tree_sitter_javascript::LANGUAGE.into();
        Ok(Self {
            yaml_lang,
            c_lang,
            js_lang,
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

    match language {
        "yaml" | "yml" => find_yaml_slop(eng, source),
        "c" | "h" => find_c_slop(eng, source),
        "cpp" | "cxx" | "cc" | "hpp" => find_cpp_slop(eng, source),
        "hcl" | "tf" => find_hcl_slop(source),
        "py" => find_python_slop(source),
        "js" | "jsx" | "ts" | "tsx" => find_js_slop(eng, source),
        _ => Vec::new(),
    }
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
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
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
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
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
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
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
probable AI erasure of edge-case safety checks"
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
    let tree = parser.parse(source, None)?;
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
        assert!(
            findings.is_empty(),
            "Python rules removed v7.6.0: {findings:?}"
        );
    }

    #[test]
    fn test_rust_unsafe_not_flagged() {
        let src = b"fn foo() {\n    unsafe {\n        let x = 1 + 1;\n    }\n}\n";
        let findings = find_slop("rs", src);
        assert!(
            findings.is_empty(),
            "Rust vacuous-unsafe rule removed v7.6.0: {findings:?}"
        );
    }

    #[test]
    fn test_js_eval_not_flagged() {
        let src = b"const result = eval(userInput);\n";
        let findings = find_slop("js", src);
        assert!(
            findings.is_empty(),
            "JS eval() rule removed v7.6.0: {findings:?}"
        );
    }

    #[test]
    fn test_bash_unquoted_var_not_flagged() {
        let src = b"rm -rf $TARGET_DIR\n";
        let findings = find_slop("sh", src);
        assert!(
            findings.is_empty(),
            "Bash unquoted-var rule removed v7.6.0: {findings:?}"
        );
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
            "C++ raw new must NOT be flagged (rule removed v7.1.11): {findings:?}"
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
            "C++ raw delete must NOT be flagged (rule removed v7.1.11): {findings:?}"
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
        assert!(
            !findings.is_empty(),
            "gets() call in C must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("gets()"));
    }

    #[test]
    fn test_c_fgets_not_flagged() {
        let src =
            b"#include <stdio.h>\nint main() { char buf[64]; fgets(buf, sizeof(buf), stdin); return 0; }\n";
        let findings = find_slop("c", src);
        assert!(
            findings.is_empty(),
            "fgets() is safe — must not be flagged: {findings:?}"
        );
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
            "wildcard CIDR in security group must be detected: {findings:?}"
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
        assert!(
            findings.is_empty(),
            "restricted CIDR must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_hcl_wildcard_cidr_without_security_context_not_flagged() {
        let src = b"destination_cidr_block = \"0.0.0.0/0\"\n";
        let findings = find_slop("tf", src);
        assert!(
            findings.is_empty(),
            "wildcard CIDR without security context must not be flagged: {findings:?}"
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
        assert!(
            !findings.is_empty(),
            "strcpy() call in C must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("strcpy()"));
    }

    #[test]
    fn test_c_sprintf_detected() {
        let src = b"#include <stdio.h>\nvoid foo(char *buf, int n) { sprintf(buf, \"%d\", n); }\n";
        let findings = find_slop("c", src);
        assert!(
            !findings.is_empty(),
            "sprintf() call in C must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("sprintf()"));
    }

    #[test]
    fn test_c_scanf_detected() {
        let src = b"#include <stdio.h>\nvoid foo() { int x; scanf(\"%d\", &x); }\n";
        let findings = find_slop("c", src);
        assert!(
            !findings.is_empty(),
            "scanf() call in C must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("scanf()"));
    }

    #[test]
    fn test_cpp_strcpy_detected() {
        let src =
            b"#include <cstring>\nvoid foo(char *dst, const char *src) { strcpy(dst, src); }\n";
        let findings = find_slop("cpp", src);
        assert!(
            !findings.is_empty(),
            "strcpy() call in C++ must be detected: {findings:?}"
        );
    }

    // ── Python subprocess shell=True tests ───────────────────────────────

    #[test]
    fn test_python_subprocess_shell_true_detected() {
        let src = b"import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let findings = find_slop("py", src);
        assert!(
            !findings.is_empty(),
            "subprocess.run with shell=True must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("shell_injection"));
    }

    #[test]
    fn test_python_subprocess_no_shell_not_flagged() {
        let src = b"import subprocess\nsubprocess.run(['ls', '-la'])\n";
        let findings = find_slop("py", src);
        assert!(
            findings.is_empty(),
            "subprocess.run without shell=True must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_python_shell_true_without_subprocess_not_flagged() {
        let src = b"# shell=True\nx = 1\n";
        let findings = find_slop("py", src);
        assert!(
            findings.is_empty(),
            "shell=True without subprocess must not be flagged: {findings:?}"
        );
    }

    // ── JavaScript innerHTML tests ────────────────────────────────────────

    #[test]
    fn test_js_innerhtml_assignment_detected() {
        let src = b"element.innerHTML = userInput;\n";
        let findings = find_slop("js", src);
        assert!(
            !findings.is_empty(),
            "innerHTML assignment in JS must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("innerHTML"));
    }

    #[test]
    fn test_js_textcontent_not_flagged() {
        let src = b"element.textContent = userInput;\n";
        let findings = find_slop("js", src);
        assert!(
            findings.is_empty(),
            "textContent assignment must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_ts_innerhtml_detected() {
        let src =
            b"const el: HTMLElement = document.getElementById('out')!;\nel.innerHTML = data;\n";
        let findings = find_slop("ts", src);
        assert!(
            !findings.is_empty(),
            "innerHTML assignment in TS must be detected: {findings:?}"
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
        assert!(
            !findings.is_empty(),
            "S3 public-read ACL must be detected: {findings:?}"
        );
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
            "description must contain antipattern label: {}",
            f.description
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
        assert!(
            findings.is_empty(),
            "S3 private ACL must not be flagged: {findings:?}"
        );
    }
}
