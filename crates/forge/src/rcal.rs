//! Root Cause Abstraction Lattice (RCAL) causality scoring.
//!
//! The first lattice layer groups findings by sanitizer path and vulnerability
//! class.  A sanitizer becomes a proven invariant for a class only when the
//! matched repository cohort clears the configured clean-rate threshold.

use common::slop::StructuredFinding;
use std::collections::BTreeMap;

/// Propensity-score style evidence for one sanitizer and vulnerability class.
#[derive(Debug, Clone, PartialEq)]
pub struct CausalityVector {
    /// Sanitizer or validator path being evaluated.
    pub sanitizer_path: String,
    /// Vulnerability family or concrete finding class.
    pub finding_class: String,
    /// Number of comparable repositories using this sanitizer path.
    pub repos_observed: u32,
    /// Number of comparable repositories with zero findings in `finding_class`.
    pub clean_repos: u32,
}

impl CausalityVector {
    /// Return the clean percentage for this vector.
    pub fn clean_rate_pct(&self) -> f64 {
        if self.repos_observed == 0 {
            return 0.0;
        }
        self.clean_repos as f64 / self.repos_observed as f64 * 100.0
    }
}

/// Sanitizer/class pair that cleared the PSM clean-rate threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenInvariant {
    /// Sanitizer path that behaved as an invariant.
    pub sanitizer_path: String,
    /// Finding class suppressed by the invariant.
    pub finding_class: String,
    /// Repositories in the matched cohort.
    pub repos_observed: u32,
    /// Clean repositories in the matched cohort.
    pub clean_repos: u32,
    /// Clean percentage over the cohort.
    pub clean_rate_pct: f64,
}

/// Evaluate sanitizer causality vectors and return proven invariants.
pub fn evaluate_proven_invariants(
    vectors: &[CausalityVector],
    threshold_pct: f64,
) -> Vec<ProvenInvariant> {
    let mut grouped: BTreeMap<(&str, &str), (u32, u32)> = BTreeMap::new();
    for vector in vectors {
        if vector.repos_observed == 0 {
            continue;
        }
        let entry = grouped
            .entry((&vector.sanitizer_path, &vector.finding_class))
            .or_default();
        entry.0 = entry.0.saturating_add(vector.repos_observed);
        entry.1 = entry.1.saturating_add(vector.clean_repos);
    }

    grouped
        .into_iter()
        .filter_map(
            |((sanitizer_path, finding_class), (repos_observed, clean_repos))| {
                if repos_observed == 0 {
                    return None;
                }
                let clean_rate_pct = clean_repos as f64 / repos_observed as f64 * 100.0;
                (clean_rate_pct >= threshold_pct).then(|| ProvenInvariant {
                    sanitizer_path: sanitizer_path.to_string(),
                    finding_class: finding_class.to_string(),
                    repos_observed,
                    clean_repos,
                    clean_rate_pct,
                })
            },
        )
        .collect()
}

/// Build defensive evidence text for Bugcrowd-style reports.
pub fn defensive_evidence_for_findings(findings: &[&StructuredFinding]) -> Option<String> {
    let mut vectors = Vec::new();
    for finding in findings {
        let Some(witness) = finding.exploit_witness.as_ref() else {
            continue;
        };
        let Some(audit) = witness.sanitizer_audit.as_deref() else {
            continue;
        };
        vectors.extend(parse_causality_vectors(&finding.id, audit));
    }

    let invariants = evaluate_proven_invariants(&vectors, 90.0);
    if invariants.is_empty() {
        return None;
    }

    let lines = invariants
        .iter()
        .map(|invariant| {
            format!(
                "- Proven Invariant: `{}` kept `{}` clean in {}/{} matched repos ({:.1}%).",
                invariant.sanitizer_path,
                invariant.finding_class,
                invariant.clean_repos,
                invariant.repos_observed,
                invariant.clean_rate_pct
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(lines)
}

fn parse_causality_vectors(finding_class: &str, audit: &str) -> Vec<CausalityVector> {
    let mut vectors = Vec::new();
    for sanitizer in bracketed_sanitizers(audit) {
        if let Some((clean_repos, repos_observed)) = parse_repo_ratio_after(audit, &sanitizer) {
            vectors.push(CausalityVector {
                sanitizer_path: sanitizer,
                finding_class: finding_class.to_string(),
                repos_observed,
                clean_repos,
            });
        }
    }
    vectors
}

fn bracketed_sanitizers(audit: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = audit;
    while let Some(start) = rest.find('[') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(']') else {
            break;
        };
        for part in after[..end].split(',') {
            let sanitizer = part.trim();
            if !sanitizer.is_empty() {
                out.push(sanitizer.to_string());
            }
        }
        rest = &after[end + 1..];
    }
    out.sort();
    out.dedup();
    out
}

fn parse_repo_ratio_after(audit: &str, sanitizer: &str) -> Option<(u32, u32)> {
    let index = audit.find(sanitizer)?;
    let tail = &audit[index..];
    parse_ratio(tail).or_else(|| parse_percent(tail).map(|pct| (pct as u32, 100)))
}

fn parse_ratio(text: &str) -> Option<(u32, u32)> {
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '/');
        let Some((left, right)) = trimmed.split_once('/') else {
            continue;
        };
        let clean = left.parse::<u32>().ok()?;
        let total = right.parse::<u32>().ok()?;
        if total > 0 && clean <= total {
            return Some((clean, total));
        }
    }
    None
}

fn parse_percent(text: &str) -> Option<f64> {
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
        if token.contains('%') {
            let pct = trimmed.parse::<f64>().ok()?;
            if (0.0..=100.0).contains(&pct) {
                return Some(pct);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causality_vector_promotes_sanitizer_to_proven_invariant() {
        let vectors = vec![
            CausalityVector {
                sanitizer_path: "escapeHtml".to_string(),
                finding_class: "security:dom_xss_innerHTML".to_string(),
                repos_observed: 10,
                clean_repos: 9,
            },
            CausalityVector {
                sanitizer_path: "escapeHtml".to_string(),
                finding_class: "security:dom_xss_innerHTML".to_string(),
                repos_observed: 10,
                clean_repos: 10,
            },
        ];

        let invariants = evaluate_proven_invariants(&vectors, 90.0);

        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].sanitizer_path, "escapeHtml");
        assert_eq!(invariants[0].repos_observed, 20);
        assert_eq!(invariants[0].clean_repos, 19);
        assert!(invariants[0].clean_rate_pct >= 95.0);
    }

    #[test]
    fn causality_vector_rejects_low_clean_rate() {
        let vectors = vec![CausalityVector {
            sanitizer_path: "escapeHtml".to_string(),
            finding_class: "security:ssrf".to_string(),
            repos_observed: 10,
            clean_repos: 6,
        }];

        assert!(evaluate_proven_invariants(&vectors, 90.0).is_empty());
    }

    #[test]
    fn defensive_evidence_extracts_repo_ratio_from_sanitizer_audit() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            exploit_witness: Some(common::slop::ExploitWitness {
                sanitizer_audit: Some(
                    "Path sanitizers [escapeHtml] matched PSM cohort 19/20 clean repos."
                        .to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        let evidence = defensive_evidence_for_findings(&[&finding])
            .expect("PSM ratio must produce defensive evidence");

        assert!(evidence.contains("Proven Invariant"));
        assert!(evidence.contains("escapeHtml"));
        assert!(evidence.contains("19/20"));
    }
}
