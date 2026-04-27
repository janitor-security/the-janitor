//! CI workflow governance checks.
//!
//! Enforces immutable remote action references in GitHub Actions workflows.

use common::slop::StructuredFinding;
use std::path::Path;
use tree_sitter::Parser;

const WORKFLOW_FINDING_ID: &str = "security:mutable_workflow_tag";

/// Scan `.github/workflows/` under the current directory for mutable action pins.
pub fn check_workflow_pinning() -> Vec<StructuredFinding> {
    std::env::current_dir()
        .ok()
        .map(|root| check_workflow_pinning_in_root(&root))
        .unwrap_or_default()
}

/// Scan `.github/workflows/` under `root` for mutable action pins.
pub fn check_workflow_pinning_in_root(root: &Path) -> Vec<StructuredFinding> {
    let workflow_dir = root.join(".github").join("workflows");
    let Ok(entries) = std::fs::read_dir(&workflow_dir) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_workflow_yaml_path(&path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .into_owned();
        findings.extend(check_workflow_pinning_source(&rel, &bytes));
    }
    findings
}

/// Scan one workflow YAML document for mutable remote action references.
pub fn check_workflow_pinning_source(file_name: &str, source: &[u8]) -> Vec<StructuredFinding> {
    if !is_workflow_yaml_path(Path::new(file_name)) {
        return Vec::new();
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    if parser.parse(source, None).is_none() {
        return Vec::new();
    };

    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    text.lines()
        .enumerate()
        .filter_map(|(idx, line)| mutable_uses_value(line).map(|value| (idx + 1, value)))
        .map(|(line, value)| workflow_finding(file_name, line as u32, &value))
        .collect()
}

fn is_workflow_yaml_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    if !matches!(ext, "yml" | "yaml") {
        return false;
    }
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized.contains(".github/workflows/")
}

fn mutable_uses_value(line: &str) -> Option<String> {
    let trimmed = line
        .trim_start()
        .strip_prefix("- ")
        .unwrap_or(line.trim_start());
    let rest = trimmed.strip_prefix("uses:")?.trim();
    let value = rest
        .split('#')
        .next()
        .unwrap_or(rest)
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    if is_mutable_remote_action(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn is_mutable_remote_action(value: &str) -> bool {
    let Some((_, reference)) = value.rsplit_once('@') else {
        return false;
    };
    !(reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn workflow_finding(file_name: &str, line: u32, value: &str) -> StructuredFinding {
    StructuredFinding {
        id: WORKFLOW_FINDING_ID.to_string(),
        file: Some(file_name.to_string()),
        line: Some(line),
        fingerprint: blake3::hash(
            format!("{WORKFLOW_FINDING_ID}:{file_name}:{line}:{value}").as_bytes(),
        )
        .to_hex()
        .to_string(),
        severity: Some("Critical".to_string()),
        remediation: Some(format!(
            "Pin GitHub Action `{value}` to a full 40-character commit SHA."
        )),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: false,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_workflow_tag_is_critical() {
        let source = br#"
name: ci
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
"#;

        let findings = check_workflow_pinning_source(".github/workflows/ci.yml", source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, WORKFLOW_FINDING_ID);
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
        assert_eq!(findings[0].line, Some(6));
    }

    #[test]
    fn full_sha_pin_is_accepted() {
        let source = br#"
name: ci
jobs:
  test:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
"#;

        let findings = check_workflow_pinning_source(".github/workflows/ci.yml", source);

        assert!(findings.is_empty());
    }
}
