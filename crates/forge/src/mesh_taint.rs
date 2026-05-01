//! Cross-repository taint mesh composition — P4-8 Phase B.
//!
//! Composes per-service IFDS summaries into a global solution and emits
//! `security:cross_service_taint_propagation` when a producer removes a
//! sanitizer that a downstream consumer was relying on.

use serde::{Deserialize, Serialize};

/// Per-service taint summary exported by the single-repo IFDS solver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshSummary {
    /// Canonical service identifier (e.g., `"api-gateway"`, `"order-service"`).
    pub service: String,
    /// Taint source labels reachable from network ingress for this service.
    pub sources: Vec<String>,
    /// Sink labels reachable from at least one taint source in this service.
    pub sinks: Vec<String>,
    /// Sanitizer labels applied on the taint path before every sink.
    pub sanitizers: Vec<String>,
}

/// A compositional violation: a producer removed a sanitizer that a consumer trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossServiceFinding {
    /// Service that removed the sanitizer.
    pub producer_service: String,
    /// Sanitizer label that was removed.
    pub removed_sanitizer: String,
    /// Downstream consumer services that were relying on this sanitizer.
    pub consumer_services: Vec<String>,
    /// Machine-readable finding ID.
    pub rule_id: String,
    /// Human-readable description for the operator.
    pub description: String,
}

/// Compose two mesh snapshots and return cross-service taint violations.
///
/// Compares `before` (mesh state prior to a PR landing) against `after` (post-merge).
/// For each service that loses a sanitizer between snapshots, a [`CrossServiceFinding`]
/// is emitted.  Consumer services are every service in `after` whose `sources` overlap
/// with the producer's `sinks` — those services depended on the sanitizer to guard
/// taint flowing from the producer.
pub fn compose_mesh_summaries(
    before: &[MeshSummary],
    after: &[MeshSummary],
) -> Vec<CrossServiceFinding> {
    let mut findings: Vec<CrossServiceFinding> = Vec::new();

    for after_svc in after {
        let Some(before_svc) = before.iter().find(|b| b.service == after_svc.service) else {
            // New service has no prior snapshot — nothing was removed.
            continue;
        };

        let removed: Vec<&str> = before_svc
            .sanitizers
            .iter()
            .filter(|s| !after_svc.sanitizers.contains(*s))
            .map(String::as_str)
            .collect();

        if removed.is_empty() {
            continue;
        }

        // Consumer services: any peer whose sources overlap with this producer's sinks.
        let consumers: Vec<String> = after
            .iter()
            .filter(|s| s.service != after_svc.service)
            .filter(|s| s.sources.iter().any(|src| after_svc.sinks.contains(src)))
            .map(|s| s.service.clone())
            .collect();

        for san in &removed {
            findings.push(CrossServiceFinding {
                producer_service: after_svc.service.clone(),
                removed_sanitizer: san.to_string(),
                consumer_services: consumers.clone(),
                rule_id: "security:cross_service_taint_propagation".to_string(),
                description: format!(
                    "security:cross_service_taint_propagation — \
                     service `{}` removed sanitizer `{}`: \
                     downstream consumers no longer receive sanitized output",
                    after_svc.service, san,
                ),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(service: &str, sources: &[&str], sinks: &[&str], sanitizers: &[&str]) -> MeshSummary {
        MeshSummary {
            service: service.to_string(),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            sinks: sinks.iter().map(|s| s.to_string()).collect(),
            sanitizers: sanitizers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn removed_sanitizer_emits_cross_service_finding() {
        let before = vec![
            svc(
                "api-gateway",
                &["http_request"],
                &["db_query"],
                &["input_validation"],
            ),
            svc("order-service", &["db_query"], &["payment_sink"], &[]),
        ];
        let after = vec![
            svc("api-gateway", &["http_request"], &["db_query"], &[]),
            svc("order-service", &["db_query"], &["payment_sink"], &[]),
        ];
        let findings = compose_mesh_summaries(&before, &after);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            "security:cross_service_taint_propagation"
        );
        assert_eq!(findings[0].producer_service, "api-gateway");
        assert_eq!(findings[0].removed_sanitizer, "input_validation");
        assert!(findings[0]
            .consumer_services
            .contains(&"order-service".to_string()));
    }

    #[test]
    fn unchanged_sanitizers_produce_no_finding() {
        let snap = vec![svc(
            "api-gateway",
            &["http_request"],
            &["db_query"],
            &["input_validation"],
        )];
        let findings = compose_mesh_summaries(&snap, &snap);
        assert!(findings.is_empty());
    }

    #[test]
    fn added_sanitizer_produces_no_finding() {
        let before = vec![svc("svc-a", &["http"], &["sql"], &[])];
        let after = vec![svc("svc-a", &["http"], &["sql"], &["new_guard"])];
        let findings = compose_mesh_summaries(&before, &after);
        assert!(findings.is_empty());
    }

    #[test]
    fn new_service_with_no_prior_snapshot_skipped() {
        let before: Vec<MeshSummary> = vec![];
        let after = vec![svc("brand-new", &["http"], &["sql"], &["validator"])];
        let findings = compose_mesh_summaries(&before, &after);
        assert!(findings.is_empty());
    }

    #[test]
    fn isolated_service_no_consumers_still_emits_finding() {
        let before = vec![svc("standalone", &["http"], &["sink"], &["validator"])];
        let after = vec![svc("standalone", &["http"], &["sink"], &[])];
        let findings = compose_mesh_summaries(&before, &after);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].producer_service, "standalone");
        assert!(findings[0].consumer_services.is_empty());
    }
}
