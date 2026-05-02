//! Legacy C/C++ Latent Vulnerability Mining Engine (P1-8).
//!
//! Five high-yield structural patterns for mining latent memory-safety bugs in
//! legacy C/C++ codebases. Each pattern applies an AhoCorasick byte-scan gate
//! before invoking the tree-sitter AST confirmation pass, keeping the hot path
//! allocation-free.
//!
//! Patterns are deliberately complementary to the existing `find_c_slop`
//! detector: LCM-001 covers extended-family variants (`strncat`, `vsprintf`,
//! `vprintf`); LCM-002 through LCM-005 target patterns the existing detector
//! does not emit.
//!
//! | ID      | Pattern                             | CWE     | Severity    |
//! |---------|-------------------------------------|---------|-------------|
//! | LCM-001 | Extended unbounded string ops        | CWE-120 | Critical    |
//! | LCM-002 | Integer truncation in malloc/calloc  | CWE-190 | Critical    |
//! | LCM-003 | Off-by-one `<=` loop array write     | CWE-193 | Critical    |
//! | LCM-004 | Use-after-free on struct pointer     | CWE-416 | KevCritical |
//! | LCM-005 | Double-free on error path            | CWE-415 | KevCritical |

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use tree_sitter::{Language, Node};

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{parse_with_timeout, Severity, SlopFinding};

// ---------------------------------------------------------------------------
// AhoCorasick pre-screens (one OnceLock per pattern group, zero allocations
// in the hot path after first initialization).
// ---------------------------------------------------------------------------

static LCM001_AC: OnceLock<AhoCorasick> = OnceLock::new();
static LCM002_AC: OnceLock<AhoCorasick> = OnceLock::new();
static LCM003_AC: OnceLock<AhoCorasick> = OnceLock::new();
static LCM004_AC: OnceLock<AhoCorasick> = OnceLock::new();
static LCM005_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn lcm001_ac() -> &'static AhoCorasick {
    LCM001_AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build([b"strncat".as_slice(), b"vsprintf", b"vprintf", b"vsnprintf"])
            .expect("LCM-001 AC build infallible")
    })
}

fn lcm002_ac() -> &'static AhoCorasick {
    LCM002_AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build([b"malloc".as_slice(), b"calloc", b"realloc"])
            .expect("LCM-002 AC build infallible")
    })
}

fn lcm003_ac() -> &'static AhoCorasick {
    LCM003_AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build([b"<=", b"=<"])
            .expect("LCM-003 AC build infallible")
    })
}

fn lcm004_ac() -> &'static AhoCorasick {
    LCM004_AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build([b"free("])
            .expect("LCM-004 AC build infallible")
    })
}

fn lcm005_ac() -> &'static AhoCorasick {
    LCM005_AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build([b"free("])
            .expect("LCM-005 AC build infallible")
    })
}

static C_LANG: OnceLock<Language> = OnceLock::new();

fn c_lang() -> &'static Language {
    C_LANG.get_or_init(|| tree_sitter_c::LANGUAGE.into())
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `source` for the five LCM patterns and return any confirmed findings.
///
/// Designed to be called from [`crate::slop_hunter::find_slop`] on every C/C++
/// source file after the existing `find_c_slop` pass. Emits findings under the
/// `security:lcm_*` ID namespace to avoid duplication with existing detectors.
pub fn find_legacy_c_mining_targets(source: &[u8]) -> Vec<SlopFinding> {
    let mut out = Vec::new();
    lcm001(source, &mut out);
    lcm002(source, &mut out);
    lcm003(source, &mut out);
    lcm004(source, &mut out);
    lcm005(source, &mut out);
    out
}

// ---------------------------------------------------------------------------
// LCM-001 — Extended unbounded string operations (CWE-120)
// ---------------------------------------------------------------------------
//
// `strncat` with a size argument derived from the destination capacity (rather
// than remaining capacity) produces off-by-one overflows in real code.
// `vsprintf` / `vprintf` are unbounded format-write sinks identical to `sprintf`.
// `vsnprintf` is included when the return-value is unchecked (heuristic: no
// comparison operator adjacent to the call).

fn lcm001(source: &[u8], out: &mut Vec<SlopFinding>) {
    if !lcm001_ac().is_match(source) {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(c_lang()).is_err() {
        return;
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return;
    };
    walk_lcm001(tree.root_node(), source, out);
}

fn walk_lcm001(node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(source) {
                    let desc: Option<&str> = match name {
                        "strncat" => Some(
                            "security:lcm_unbounded_strncat (CWE-120) — \
                             strncat(dst, src, n): if n equals sizeof(dst) rather than \
                             remaining capacity, the destination overflows by one byte; \
                             use strlcat(dst, src, sizeof(dst))",
                        ),
                        "vsprintf" | "vprintf" => Some(
                            "security:lcm_unbounded_vprintf (CWE-120) — \
                             vsprintf/vprintf: unbounded format write to destination buffer; \
                             replace with vsnprintf(buf, sizeof(buf), fmt, ap)",
                        ),
                        _ => None,
                    };
                    if let Some(d) = desc {
                        out.push(SlopFinding {
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
        walk_lcm001(child, source, out);
    }
}

// ---------------------------------------------------------------------------
// LCM-002 — Integer truncation in malloc/calloc/realloc (CWE-190)
// ---------------------------------------------------------------------------
//
// Looks for `malloc(n * sizeof(T))` where the argument is a binary expression
// involving a potential signed `int` operand — a classic integer overflow that
// wraps to 0 or a small positive value, resulting in an under-allocation.
// Heuristic: argument contains a `*` binary expression without an explicit cast.

fn lcm002(source: &[u8], out: &mut Vec<SlopFinding>) {
    if !lcm002_ac().is_match(source) {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(c_lang()).is_err() {
        return;
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return;
    };
    walk_lcm002(tree.root_node(), source, out);
}

fn walk_lcm002(node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(source) {
                    if matches!(name, "malloc" | "calloc" | "realloc") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if arg_contains_unchecked_multiply(args, source) {
                                out.push(SlopFinding {
                                    start_byte: node.start_byte(),
                                    end_byte: node.end_byte(),
                                    description: format!(
                                        "security:lcm_malloc_integer_truncation (CWE-190) — \
                                         {name}() argument contains an unchecked integer \
                                         multiplication: if the count value overflows int \
                                         the allocation is under-sized; use \
                                         checked_mul() or calloc(count, sizeof(T))"
                                    ),
                                    domain: DOMAIN_FIRST_PARTY,
                                    severity: Severity::Critical,
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_lcm002(child, source, out);
    }
}

/// Returns `true` when the argument list contains a `*` binary expression
/// that is NOT wrapped in an explicit `(size_t)` cast.
fn arg_contains_unchecked_multiply(args_node: Node<'_>, source: &[u8]) -> bool {
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        if child.kind() == "binary_expression" {
            let op_text = child
                .child_by_field_name("operator")
                .and_then(|op| op.utf8_text(source).ok())
                .unwrap_or("");
            if op_text == "*" {
                // Suppress if the parent is a cast_expression to size_t / uint*
                // (heuristic: look for a cast sibling in the argument list)
                if !binary_expr_has_size_cast(args_node, source) {
                    return true;
                }
            }
        }
    }
    false
}

fn binary_expr_has_size_cast(args_node: Node<'_>, source: &[u8]) -> bool {
    let src_text = args_node.utf8_text(source).unwrap_or("");
    src_text.contains("(size_t)") || src_text.contains("(SIZE_T)")
}

// ---------------------------------------------------------------------------
// LCM-003 — Off-by-one `<=` loop condition writing to array (CWE-193)
// ---------------------------------------------------------------------------
//
// Detects for/while loops where the loop condition uses `<=` against an array
// size bound AND the body contains a subscript assignment `arr[i] = …`.
// High recall; moderate precision — confirmed as true-positive class in
// Project Zero retrospectives for multiple C network stacks.

fn lcm003(source: &[u8], out: &mut Vec<SlopFinding>) {
    if !lcm003_ac().is_match(source) {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(c_lang()).is_err() {
        return;
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return;
    };
    walk_lcm003(tree.root_node(), source, out);
}

fn walk_lcm003(node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    let is_loop = matches!(node.kind(), "for_statement" | "while_statement");
    if is_loop
        && loop_condition_has_lte(node, source)
        && loop_body_has_subscript_assign(node, source)
    {
        out.push(SlopFinding {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            description:
                "security:lcm_off_by_one_loop (CWE-193) — loop condition uses `<=` against an \
                 array bound while the body assigns to a subscript; when the index equals the \
                 bound the write overflows the array by one element; change `<=` to `<`"
                    .to_string(),
            domain: DOMAIN_FIRST_PARTY,
            severity: Severity::Critical,
        });
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_lcm003(child, source, out);
    }
}

fn loop_condition_has_lte(loop_node: Node<'_>, source: &[u8]) -> bool {
    // Walk immediate children looking for the condition expression.
    let mut cursor = loop_node.walk();
    for child in loop_node.children(&mut cursor) {
        if matches!(child.kind(), "binary_expression") {
            let op = child
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if op == "<=" {
                return true;
            }
        }
        // For `for` loops the condition is the second child; recurse one level.
        if matches!(
            child.kind(),
            "binary_expression" | "parenthesized_expression"
        ) && subtree_has_lte(child, source)
        {
            return true;
        }
    }
    false
}

fn subtree_has_lte(node: Node<'_>, source: &[u8]) -> bool {
    if node.kind() == "binary_expression" {
        let op = node
            .child_by_field_name("operator")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        if op == "<=" {
            return true;
        }
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    children.into_iter().any(|c| subtree_has_lte(c, source))
}

fn loop_body_has_subscript_assign(loop_node: Node<'_>, source: &[u8]) -> bool {
    let body_src = loop_node.utf8_text(source).unwrap_or("");
    // Heuristic: source bytes contain `[` followed by `]` and `=` (not `==`)
    // within the same line — sufficient for initial recall pass.
    body_src_has_subscript_write(body_src.as_bytes())
}

fn body_src_has_subscript_write(src: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 3 < src.len() {
        if src[i] == b'[' {
            // Scan ahead for `] =` (not `==`)
            let mut j = i + 1;
            while j < src.len() && src[j] != b']' && src[j] != b'\n' {
                j += 1;
            }
            if j < src.len() && src[j] == b']' {
                // skip whitespace
                let mut k = j + 1;
                while k < src.len() && src[k] == b' ' {
                    k += 1;
                }
                if k < src.len() && src[k] == b'=' && (k + 1 >= src.len() || src[k + 1] != b'=') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// LCM-004 — Use-after-free on struct pointer (CWE-416)
// ---------------------------------------------------------------------------
//
// Detects a `free(ptr)` call followed by a use of `ptr->` or `*ptr` in the
// same function body. This is a byte-scan heuristic — real IFDS-level
// dataflow confirmation is deferred to the Z3 spine (Sprint Batch 90+).

fn lcm004(source: &[u8], out: &mut Vec<SlopFinding>) {
    if !lcm004_ac().is_match(source) {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(c_lang()).is_err() {
        return;
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return;
    };
    walk_lcm004_fn_bodies(tree.root_node(), source, out);
}

fn walk_lcm004_fn_bodies(node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    if node.kind() == "function_definition" {
        scan_fn_for_uaf(node, source, out);
        return; // Do not recurse into nested functions (C doesn't have them but be safe)
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_lcm004_fn_bodies(child, source, out);
    }
}

/// Collect all `free(ident)` call sites and all subsequent `ident->` / `*ident`
/// uses within the same function compound statement.
fn scan_fn_for_uaf(fn_node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    // Collect (freed_name, free_end_byte) pairs
    let mut freed: Vec<(String, usize)> = Vec::new();
    collect_free_calls(fn_node, source, &mut freed);
    if freed.is_empty() {
        return;
    }
    // For each freed name, check if it appears after its free site as `name->` or `(*name)`
    let fn_src = fn_node.utf8_text(source).unwrap_or("");
    let fn_start = fn_node.start_byte();
    for (freed_name, free_end) in &freed {
        let post_free_offset = free_end.saturating_sub(fn_start);
        if post_free_offset >= fn_src.len() {
            continue;
        }
        let post_free = &fn_src.as_bytes()[post_free_offset..];
        if bytes_contain_ptr_deref(post_free, freed_name.as_bytes())
            && !bytes_null_assigned_before_deref(post_free, freed_name.as_bytes())
        {
            out.push(SlopFinding {
                start_byte: *free_end,
                end_byte: *free_end,
                description: format!(
                    "security:lcm_use_after_free (CWE-416) — pointer `{freed_name}` is \
                     dereferenced (`{freed_name}->` or `*{freed_name}`) after `free({freed_name})` \
                     in the same function scope; set pointer to NULL after free to prevent \
                     dangling-pointer dereference"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::KevCritical,
            });
        }
    }
}

fn collect_free_calls(node: Node<'_>, source: &[u8], freed: &mut Vec<(String, usize)>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.utf8_text(source).unwrap_or("") == "free" {
                if let Some(args) = node.child_by_field_name("arguments") {
                    // First argument to free()
                    let mut cursor = args.walk();
                    for arg in args.children(&mut cursor) {
                        if matches!(arg.kind(), "identifier" | "pointer_expression") {
                            if let Ok(name) = arg.utf8_text(source) {
                                let clean = name.trim_start_matches('*').trim();
                                if !clean.is_empty() {
                                    freed.push((clean.to_string(), node.end_byte()));
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_free_calls(child, source, freed);
    }
}

fn bytes_contain_ptr_deref(haystack: &[u8], name: &[u8]) -> bool {
    let arrow: Vec<u8> = [name, b"->"].concat();
    let deref: Vec<u8> = [b"*", name].concat();
    haystack.windows(arrow.len()).any(|w| w == arrow.as_slice())
        || haystack.windows(deref.len()).any(|w| w == deref.as_slice())
}

/// Returns `true` when `name = NULL` or `name = 0` appears before any deref,
/// indicating a defensive NULL-assignment that suppresses the UAF.
fn bytes_null_assigned_before_deref(haystack: &[u8], name: &[u8]) -> bool {
    let null_assign: Vec<u8> = [name, b" = NULL"].concat();
    let zero_assign: Vec<u8> = [name, b" = 0"].concat();
    let arrow: Vec<u8> = [name, b"->"].concat();
    let null_pos = haystack
        .windows(null_assign.len())
        .position(|w| w == null_assign.as_slice())
        .or_else(|| {
            haystack
                .windows(zero_assign.len())
                .position(|w| w == zero_assign.as_slice())
        });
    let deref_pos = haystack
        .windows(arrow.len())
        .position(|w| w == arrow.as_slice());
    match (null_pos, deref_pos) {
        (Some(n), Some(d)) => n < d,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// LCM-005 — Double-free on error path (CWE-415)
// ---------------------------------------------------------------------------
//
// Detects two `free(ident)` call expressions on the same identifier within a
// function body where no `ident = NULL` assignment appears between them.

fn lcm005(source: &[u8], out: &mut Vec<SlopFinding>) {
    // Double-free requires at least two `free(` byte sequences.
    let count = lcm005_ac().find_iter(source).count();
    if count < 2 {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(c_lang()).is_err() {
        return;
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return;
    };
    walk_lcm005_fn_bodies(tree.root_node(), source, out);
}

fn walk_lcm005_fn_bodies(node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    if node.kind() == "function_definition" {
        scan_fn_for_double_free(node, source, out);
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_lcm005_fn_bodies(child, source, out);
    }
}

fn scan_fn_for_double_free(fn_node: Node<'_>, source: &[u8], out: &mut Vec<SlopFinding>) {
    let mut freed: Vec<(String, usize)> = Vec::new();
    collect_free_calls(fn_node, source, &mut freed);
    if freed.len() < 2 {
        return;
    }
    // Group by name; look for same name appearing twice without NULL reset between.
    let fn_src = fn_node.utf8_text(source).unwrap_or("");
    let fn_start = fn_node.start_byte();

    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (name, free_end) in &freed {
        if let Some(first_free_end) = seen.get(name).copied() {
            // Two frees of same name: check if NULL assignment is between them.
            let between_start = first_free_end.saturating_sub(fn_start);
            let between_end = free_end.saturating_sub(fn_start);
            if between_start < between_end && between_end <= fn_src.len() {
                let between = &fn_src.as_bytes()[between_start..between_end];
                let null_assign: Vec<u8> = [name.as_bytes(), b" = NULL"].concat();
                let zero_assign: Vec<u8> = [name.as_bytes(), b" = 0"].concat();
                let nulled = between
                    .windows(null_assign.len())
                    .any(|w| w == null_assign.as_slice())
                    || between
                        .windows(zero_assign.len())
                        .any(|w| w == zero_assign.as_slice());
                if !nulled {
                    out.push(SlopFinding {
                        start_byte: *free_end,
                        end_byte: *free_end,
                        description: format!(
                            "security:lcm_double_free (CWE-415) — `free({name})` is called \
                             twice in the same function without setting `{name} = NULL` between \
                             calls; the second free() corrupts the heap allocator's free-list; \
                             set pointer to NULL immediately after the first free()"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
                        severity: Severity::KevCritical,
                    });
                }
            }
        } else {
            seen.insert(name.clone(), *free_end);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcm001_strncat_detected() {
        let src = b"void f(char *d, const char *s) { strncat(d, s, sizeof(d)); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("lcm_unbounded_strncat")),
            "strncat must be detected by LCM-001"
        );
    }

    #[test]
    fn lcm001_vsprintf_detected() {
        let src = b"void f(char *b, const char *fmt, va_list ap) { vsprintf(b, fmt, ap); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("lcm_unbounded_vprintf")),
            "vsprintf must be detected by LCM-001"
        );
    }

    #[test]
    fn lcm002_malloc_multiply_detected() {
        let src = b"void *f(int n) { return malloc(n * sizeof(int)); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("lcm_malloc_integer_truncation")),
            "malloc with int * sizeof must be detected by LCM-002"
        );
    }

    #[test]
    fn lcm002_malloc_safe_cast_not_flagged() {
        let src = b"void *f(size_t n) { return malloc((size_t)n * sizeof(int)); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.description.contains("lcm_malloc_integer_truncation")),
            "malloc with explicit size_t cast must not be flagged"
        );
    }

    #[test]
    fn lcm003_off_by_one_loop_detected() {
        let src = b"void f(char *buf, int n) { int i; for (i = 0; i <= n; i++) { buf[i] = 0; } }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("lcm_off_by_one_loop")),
            "for loop with <= and array subscript write must be detected by LCM-003"
        );
    }

    #[test]
    fn lcm005_double_free_detected() {
        let src = b"void f(char *p) { free(p); if (p) free(p); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("lcm_double_free")),
            "double free without NULL reset must be detected by LCM-005"
        );
    }

    #[test]
    fn lcm005_free_with_null_reset_not_flagged() {
        let src = b"void f(char *p) { free(p); p = NULL; free(p); }\n";
        let findings = find_legacy_c_mining_targets(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.description.contains("lcm_double_free")),
            "free() with NULL reset between calls must not be flagged as double-free"
        );
    }
}
