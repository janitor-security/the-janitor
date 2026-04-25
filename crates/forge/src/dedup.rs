//! Structural deduplication of [`StructuredFinding`] instances (P3-3).
//!
//! When a developer copy-pastes vulnerable code across files, the engine emits
//! one finding per file.  Without deduplication, a Bugcrowd triager receives N
//! reports for the same root-cause pattern and closes them all as duplicates.
//!
//! [`deduplicate_findings`] groups findings by a deterministic structural
//! signature — `BLAKE3(rule_id || "\0" || file_ext || "\0" || taint_source_label)` —
//! then collapses each group into a single [`DeduplicatedFinding`] whose
//! `occurrences` list captures every affected file.  Single-file findings are
//! returned with an `occurrences` vec containing exactly one entry.
//!
//! ## Signature dimensions
//! | Dimension | Source field | Rationale |
//! |-----------|-------------|-----------|
//! | Rule ID | `finding.id` | Same vulnerability class |
//! | Language  | file extension of `finding.file` | Same sink AST node kind family |
//! | Taint source | `exploit_witness.source_label` (or `""`) | Same taint origin kind |
//!
//! The function is deterministic: identical inputs always produce identical
//! outputs.  Output order is sorted by `(rule_id, primary_file, primary_line)`
//! for stable report generation.

use std::collections::HashMap;
use std::path::Path;

use common::slop::StructuredFinding;

/// A single file location where a deduplicated finding was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingOccurrence {
    /// Relative path of the file where this occurrence was found.
    pub file: String,
    /// 1-indexed line number within that file, if line-addressable.
    pub line: Option<u32>,
}

/// A canonical finding with all cross-file occurrences attached.
///
/// [`deduplicate_findings`] collapses N same-signature findings into one
/// `DeduplicatedFinding`.  `occurrences` always contains at least one entry
/// (the primary finding's own location).
#[derive(Debug, Clone)]
pub struct DeduplicatedFinding {
    /// The canonical (first-observed) finding for this structural signature.
    pub finding: StructuredFinding,
    /// All file locations (including the primary) where this pattern was found.
    pub occurrences: Vec<FindingOccurrence>,
}

impl DeduplicatedFinding {
    /// Returns `true` when the same pattern was found in more than one file.
    pub fn is_cross_file(&self) -> bool {
        self.occurrences.len() > 1
    }
}

/// Compute the u64 structural signature for a single finding.
///
/// Encodes the vulnerability class, target language, and taint source kind —
/// the three dimensions that make two findings "structurally identical"
/// regardless of which file they appear in.
pub fn structural_signature(finding: &StructuredFinding) -> u64 {
    let rule_id = finding.id.as_str();
    let lang = finding
        .file
        .as_deref()
        .and_then(|f| Path::new(f).extension())
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    let source_label = finding
        .exploit_witness
        .as_ref()
        .map(|w| w.source_label.as_str())
        .unwrap_or("");
    let mut hasher = blake3::Hasher::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(lang.as_bytes());
    hasher.update(b"\0");
    hasher.update(source_label.as_bytes());
    let digest = hasher.finalize();
    let d = digest.as_bytes();
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Collapse semantically identical findings across files into single reports.
///
/// Findings sharing the same `(rule_id, language, taint_source_kind)` structural
/// signature are merged into one [`DeduplicatedFinding`].  The first occurrence
/// by input order within its signature group becomes the primary finding in
/// `DeduplicatedFinding::finding`; all locations (including the primary) are
/// appended to `occurrences`.
///
/// Output is sorted by `(rule_id, primary_file, primary_line)` for deterministic
/// report ordering.
pub fn deduplicate_findings(findings: Vec<StructuredFinding>) -> Vec<DeduplicatedFinding> {
    // group_order preserves first-insertion sequence so we can iterate groups
    // in a stable order before the final sort.
    let mut group_order: Vec<u64> = Vec::new();
    let mut groups: HashMap<u64, Vec<StructuredFinding>> = HashMap::new();

    for f in findings {
        let sig = structural_signature(&f);
        if !groups.contains_key(&sig) {
            group_order.push(sig);
        }
        groups.entry(sig).or_default().push(f);
    }

    let mut output: Vec<DeduplicatedFinding> = group_order
        .into_iter()
        .map(|sig| {
            let group = groups.remove(&sig).unwrap_or_default();
            let occurrences: Vec<FindingOccurrence> = group
                .iter()
                .filter_map(|f| {
                    f.file.as_deref().map(|file| FindingOccurrence {
                        file: file.to_string(),
                        line: f.line,
                    })
                })
                .collect();
            let primary = group.into_iter().next().unwrap_or_default();
            DeduplicatedFinding {
                finding: primary,
                occurrences,
            }
        })
        .collect();

    // Deterministic sort: rule_id → primary file → primary line.
    output.sort_by(|a, b| {
        a.finding
            .id
            .cmp(&b.finding.id)
            .then_with(|| a.finding.file.as_deref().cmp(&b.finding.file.as_deref()))
            .then_with(|| a.finding.line.cmp(&b.finding.line))
    });

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, file: &str, line: u32) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            file: Some(file.to_string()),
            line: Some(line),
            ..StructuredFinding::default()
        }
    }

    #[test]
    fn identical_findings_in_two_files_are_collapsed_into_one() {
        let findings = vec![
            make_finding("security:sqli_concatenation", "src/db/users.py", 42),
            make_finding("security:sqli_concatenation", "src/db/orders.py", 17),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(
            deduped.len(),
            1,
            "two same-signature findings must collapse to one"
        );
        let entry = &deduped[0];
        assert_eq!(entry.finding.id, "security:sqli_concatenation");
        assert_eq!(
            entry.occurrences.len(),
            2,
            "both files must appear in occurrences"
        );
        let files: Vec<&str> = entry.occurrences.iter().map(|o| o.file.as_str()).collect();
        assert!(files.contains(&"src/db/users.py"));
        assert!(files.contains(&"src/db/orders.py"));
        assert!(entry.is_cross_file());
    }

    #[test]
    fn distinct_rule_ids_are_not_collapsed() {
        let findings = vec![
            make_finding("security:sqli_concatenation", "src/db/users.py", 10),
            make_finding("security:command_injection", "src/db/users.py", 20),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 2, "different rule IDs must remain separate");
        for entry in &deduped {
            assert!(
                !entry.is_cross_file(),
                "single-file findings must not be cross-file"
            );
        }
    }

    #[test]
    fn same_rule_different_extension_not_collapsed() {
        let findings = vec![
            make_finding("security:sqli_concatenation", "src/db.py", 1),
            make_finding("security:sqli_concatenation", "src/db.js", 1),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(
            deduped.len(),
            2,
            "same rule in different languages must not collapse"
        );
    }

    #[test]
    fn single_finding_returned_with_one_occurrence() {
        let findings = vec![make_finding("security:credential_leak", "config.py", 5)];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].occurrences.len(), 1);
        assert!(!deduped[0].is_cross_file());
    }

    #[test]
    fn deduplication_is_deterministic() {
        let findings_a = vec![
            make_finding("security:path_traversal", "a/utils.py", 10),
            make_finding("security:path_traversal", "b/helpers.py", 20),
            make_finding("security:path_traversal", "c/views.py", 30),
        ];
        let findings_b = findings_a.clone();
        let result_a = deduplicate_findings(findings_a);
        let result_b = deduplicate_findings(findings_b);
        assert_eq!(result_a.len(), result_b.len());
        assert_eq!(result_a[0].occurrences.len(), result_b[0].occurrences.len());
        let files_a: Vec<&str> = result_a[0]
            .occurrences
            .iter()
            .map(|o| o.file.as_str())
            .collect();
        let files_b: Vec<&str> = result_b[0]
            .occurrences
            .iter()
            .map(|o| o.file.as_str())
            .collect();
        assert_eq!(
            files_a, files_b,
            "deduplication output must be deterministic"
        );
    }
}
