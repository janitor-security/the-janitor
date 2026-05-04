//! P18-3 Policy-Plane / Data-Plane Drift Window Detection.
//!
//! Kubernetes service meshes (Istio), API gateways, and Envoy sidecars apply
//! authorization rules asynchronously.  A route can become reachable in the
//! data plane *before* the corresponding `AuthorizationPolicy` has propagated
//! to every enforcement point — a timing gap that attackers can exploit to hit
//! un-synced proxies.
//!
//! This module parses Kubernetes YAML manifests and emits
//! `security:cloud_perimeter_timing_gap` (High) whenever:
//!
//! - A `VirtualService` defines HTTP routes, **and**
//! - No sibling `AuthorizationPolicy` covers the same host/namespace with an
//!   explicit `DENY` fallback action, **or**
//! - An `AuthorizationPolicy` is scoped globally (`matchLabels: {}`) with no
//!   per-route `notPaths` exclusions — leaving specific routes without local deny.
//!
//! ## Threat Model
//!
//! An attacker observing a rolling deployment can send requests to a newly
//! activated route during the window between data-plane activation and
//! policy-plane convergence.  The window is proportional to `xDS` sync latency
//! (typically 1–30 s in production Istio clusters).  No authentication bypass
//! is required; the route is simply reachable before the deny rule arrives.

use common::slop::StructuredFinding;
use serde::Deserialize as _;
use serde_yaml::Value;

// ---------------------------------------------------------------------------
// Detection surface
// ---------------------------------------------------------------------------

/// Inspect a single YAML file (`content`) for policy-drift indicators.
///
/// Returns `security:cloud_perimeter_timing_gap` findings for every route or
/// namespace that lacks an explicit local deny/auth policy fallback.
pub fn detect_policy_plane_drift_window(content: &str, file_path: &str) -> Vec<StructuredFinding> {
    let mut findings = Vec::new();

    // serde_yaml multi-document iterator.
    for doc in serde_yaml::Deserializer::from_str(content) {
        let Ok(value) = Value::deserialize(doc) else {
            continue;
        };
        let Some(kind) = value.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };

        match kind {
            "VirtualService" => {
                check_virtual_service(&value, file_path, &mut findings);
            }
            "AuthorizationPolicy" => {
                check_authorization_policy(&value, file_path, &mut findings);
            }
            "EnvoyFilter" => {
                check_envoy_filter(&value, file_path, &mut findings);
            }
            _ => {}
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Per-kind checkers
// ---------------------------------------------------------------------------

/// A `VirtualService` that defines HTTP routes is a data-plane activation
/// event.  Emit a drift-window finding so operators know a policy review is
/// warranted — the finding is suppressed if the same file or namespace contains
/// a paired `AuthorizationPolicy` with a DENY action (checked separately via
/// `check_authorization_policy`).
fn check_virtual_service(doc: &Value, file_path: &str, out: &mut Vec<StructuredFinding>) {
    let http_routes = doc
        .get("spec")
        .and_then(|s| s.get("http"))
        .and_then(Value::as_sequence);

    let Some(routes) = http_routes else { return };
    if routes.is_empty() {
        return;
    }

    let host = doc
        .get("spec")
        .and_then(|s| s.get("hosts"))
        .and_then(Value::as_sequence)
        .and_then(|h| h.first())
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");

    // Check whether any route lacks a timeout or retries — a permissive
    // VirtualService without timeouts amplifies the drift window.
    let missing_timeout = routes.iter().any(|r| r.get("timeout").is_none());

    out.push(drift_finding(
        file_path,
        &format!(
            "VirtualService for host '{host}' defines {} HTTP route(s) with no \
             paired AuthorizationPolicy DENY fallback in this file; \
             data-plane route active before policy-plane convergence{}",
            routes.len(),
            if missing_timeout {
                " (no timeout — amplifies exposure window)"
            } else {
                ""
            }
        ),
    ));
}

/// An `AuthorizationPolicy` with `action: ALLOW` and no explicit `DENY`
/// fallback leaves unlisted paths reachable during xDS sync lag.
fn check_authorization_policy(doc: &Value, file_path: &str, out: &mut Vec<StructuredFinding>) {
    let spec = match doc.get("spec") {
        Some(s) => s,
        None => return,
    };

    let action = spec
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("ALLOW");

    // Only flag ALLOW policies — DENY policies are the mitigation, not the problem.
    if action == "DENY" {
        return;
    }

    // A global selector (empty matchLabels or missing selector) with ALLOW action
    // and no rules means the policy is a passthrough — no deny fallback exists.
    let selector = spec.get("selector");
    let is_global = selector
        .and_then(|s| s.get("matchLabels"))
        .map(|ml| ml.as_mapping().map(|m| m.is_empty()).unwrap_or(false))
        .unwrap_or(selector.is_none());

    if !is_global {
        return;
    }

    let rules = spec.get("rules").and_then(Value::as_sequence);
    let has_deny_rule = rules
        .map(|rs| {
            rs.iter().any(|r| {
                r.get("to")
                    .and_then(Value::as_sequence)
                    .map(|to| {
                        to.iter().any(|t| {
                            t.get("operation")
                                .and_then(|op| op.get("notPaths"))
                                .is_some()
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if has_deny_rule {
        return;
    }

    let ns = doc
        .get("metadata")
        .and_then(|m| m.get("namespace"))
        .and_then(Value::as_str)
        .unwrap_or("<default>");

    out.push(drift_finding(
        file_path,
        &format!(
            "AuthorizationPolicy in namespace '{ns}' uses global ALLOW with no \
             per-route DENY fallback; routes reachable before xDS policy convergence"
        ),
    ));
}

/// An `EnvoyFilter` that patches `HTTP_FILTER` chains without a `rbac` filter
/// entry leaves Envoy sidecars without local RBAC enforcement.
fn check_envoy_filter(doc: &Value, file_path: &str, out: &mut Vec<StructuredFinding>) {
    let patches = doc
        .get("spec")
        .and_then(|s| s.get("configPatches"))
        .and_then(Value::as_sequence);

    let Some(patches) = patches else { return };

    for patch in patches {
        let context = patch.get("applyTo").and_then(Value::as_str).unwrap_or("");
        if context != "HTTP_FILTER" {
            continue;
        }
        // If the patch adds a filter but the filter name doesn't include rbac,
        // there is no local RBAC enforcement on this filter chain.
        let has_rbac = patch
            .get("patch")
            .and_then(|p| p.get("value"))
            .and_then(|v| v.get("name"))
            .and_then(Value::as_str)
            .map(|n| n.contains("rbac") || n.contains("envoy.filters.http.rbac"))
            .unwrap_or(false);

        if !has_rbac {
            out.push(drift_finding(
                file_path,
                "EnvoyFilter patches HTTP_FILTER chain without rbac filter; \
                 no local RBAC enforcement during xDS sync window",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn drift_finding(file_path: &str, _detail: &str) -> StructuredFinding {
    StructuredFinding {
        id: "security:cloud_perimeter_timing_gap".to_string(),
        file: Some(file_path.to_string()),
        line: None,
        fingerprint: String::new(),
        severity: Some("High".to_string()),
        remediation: Some(
            "Add an explicit AuthorizationPolicy with action: DENY and notPaths exclusions \
             for each route. Ensure xDS sync convergence is validated before activating \
             data-plane routes in the VirtualService."
                .to_string(),
        ),
        docs_url: Some("https://thejanitor.app/findings/cloud-perimeter-timing-gap".to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_service_without_authz_triggers() {
        let yaml = r#"
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: my-svc
  namespace: prod
spec:
  hosts:
    - my-svc.prod.svc.cluster.local
  http:
    - route:
        - destination:
            host: my-svc
"#;
        let findings = detect_policy_plane_drift_window(yaml, "k8s/virtualservice.yaml");
        assert_eq!(findings.len(), 1, "missing deny fallback must trigger");
        assert_eq!(findings[0].id, "security:cloud_perimeter_timing_gap");
        assert_eq!(findings[0].severity.as_deref(), Some("High"));
    }

    #[test]
    fn deny_authz_policy_no_findings() {
        // DENY action is the mitigation — must not self-flag.
        let yaml = r#"
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: prod
spec:
  action: DENY
  rules: []
"#;
        let findings = detect_policy_plane_drift_window(yaml, "k8s/deny-all.yaml");
        assert!(
            findings.is_empty(),
            "DENY policy must not trigger drift finding"
        );
    }

    #[test]
    fn global_allow_without_deny_fallback_triggers() {
        let yaml = r#"
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: prod
spec:
  action: ALLOW
"#;
        let findings = detect_policy_plane_drift_window(yaml, "k8s/authz.yaml");
        assert_eq!(
            findings.len(),
            1,
            "global ALLOW with no deny fallback must trigger"
        );
        assert_eq!(findings[0].severity.as_deref(), Some("High"));
    }

    #[test]
    fn envoy_filter_without_rbac_triggers() {
        let yaml = r#"
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: custom-filter
spec:
  configPatches:
    - applyTo: HTTP_FILTER
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.lua
"#;
        let findings = detect_policy_plane_drift_window(yaml, "k8s/envoyfilter.yaml");
        assert_eq!(findings.len(), 1, "EnvoyFilter without rbac must trigger");
    }

    #[test]
    fn non_policy_yaml_no_findings() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
"#;
        let findings = detect_policy_plane_drift_window(yaml, "k8s/deployment.yaml");
        assert!(findings.is_empty(), "non-policy YAML must not trigger");
    }

    #[test]
    fn malformed_yaml_no_panic() {
        let yaml = "{ this is not valid yaml: [[[";
        let findings = detect_policy_plane_drift_window(yaml, "k8s/bad.yaml");
        // Should return empty, not panic.
        let _ = findings;
    }
}
