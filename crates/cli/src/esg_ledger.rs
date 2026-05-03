//! P4-6 Lightweight ESG Actuarial Ledger.
//!
//! Emits OTLP-Logs-compliant JSON energy records without the bloated
//! `opentelemetry` crate suite (8GB Law compliance). Payloads are HMAC-SHA256
//! signed to produce verifiable actuarial receipts that procurement, ESG, and
//! GRC teams can verify offline without source upload.
//!
//! ## Protocol
//!
//! 1. Build a raw OTLP Logs JSON payload carrying `ci_energy_saved_kwh` and
//!    `engine_exec_ms` attributes.
//! 2. Sign the payload with HMAC-SHA256 keyed by `JANITOR_ESG_HMAC_SECRET`
//!    (or a static dev fallback when unset).
//! 3. If `JANITOR_ESG_WEBHOOK_URL` is set, POST the payload via `ureq` with
//!    `X-Janitor-ESG-Signature: sha256=<hex>` for downstream verification.
//! 4. Return an `EsgReceipt` containing the payload hash and signature so
//!    callers can persist the receipt in the bounce log.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Verifiable actuarial receipt returned by [`emit_otlp_energy_record`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EsgReceipt {
    /// Unix epoch milliseconds when the record was emitted.
    pub ts_ms: u64,
    /// CI energy saved in kilowatt-hours.
    pub ci_energy_saved_kwh: f64,
    /// Engine execution time in milliseconds.
    pub engine_exec_ms: u64,
    /// HMAC-SHA256 signature over the serialized OTLP payload.
    pub signature: String,
    /// Whether the payload was successfully delivered to the webhook endpoint.
    pub webhook_delivered: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Emit an OTLP-Logs-compliant ESG energy record and return a signed receipt.
///
/// Reads two environment variables:
/// - `JANITOR_ESG_WEBHOOK_URL` — if set, POST the payload to this endpoint.
/// - `JANITOR_ESG_HMAC_SECRET` — signing key; falls back to a static dev
///   sentinel when unset (unsigned receipts are valid for local testing).
pub fn emit_otlp_energy_record(ci_energy_saved_kwh: f64, engine_exec_ms: u64) -> EsgReceipt {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let payload = build_otlp_payload(ts_ms, ci_energy_saved_kwh, engine_exec_ms);
    let secret = std::env::var("JANITOR_ESG_HMAC_SECRET")
        .unwrap_or_else(|_| "janitor-esg-dev-sentinel".to_string());
    let signature = sign_payload(&secret, &payload);

    let webhook_delivered = if let Ok(url) = std::env::var("JANITOR_ESG_WEBHOOK_URL") {
        if !url.is_empty() {
            match ureq::post(&url)
                .header("Content-Type", "application/json")
                .header("X-Janitor-ESG-Signature", &signature)
                .send(payload.as_str())
            {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("janitor-esg: webhook delivery failed: {e}");
                    false
                }
            }
        } else {
            false
        }
    } else {
        false
    };

    EsgReceipt {
        ts_ms,
        ci_energy_saved_kwh,
        engine_exec_ms,
        signature,
        webhook_delivered,
    }
}

// ---------------------------------------------------------------------------
// OTLP payload builder
// ---------------------------------------------------------------------------

/// Build a minimal OTLP Logs JSON payload carrying the energy attributes.
///
/// Schema follows the OTLP Logs protobuf-JSON mapping:
/// `resourceLogs → scopeLogs → logRecords[]`.  No opentelemetry crate dependency.
pub fn build_otlp_payload(ts_ms: u64, ci_energy_saved_kwh: f64, engine_exec_ms: u64) -> String {
    serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    { "key": "service.name", "value": { "stringValue": "janitor" } },
                    { "key": "telemetry.sdk.name", "value": { "stringValue": "janitor-esg-ledger" } }
                ]
            },
            "scopeLogs": [{
                "scope": { "name": "janitor.esg", "version": env!("CARGO_PKG_VERSION") },
                "logRecords": [{
                    "timeUnixNano": ts_ms as u128 * 1_000_000u128,
                    "severityNumber": 9,
                    "severityText": "INFO",
                    "body": { "stringValue": "janitor:esg_energy_record" },
                    "attributes": [
                        {
                            "key": "ci_energy_saved_kwh",
                            "value": { "doubleValue": ci_energy_saved_kwh }
                        },
                        {
                            "key": "engine_exec_ms",
                            "value": { "intValue": engine_exec_ms.to_string() }
                        },
                        {
                            "key": "schema_version",
                            "value": { "stringValue": "janitor.esg.v1" }
                        }
                    ]
                }]
            }]
        }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

fn sign_payload(secret: &str, payload: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let result = mac.finalize().into_bytes();
    let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_otlp_payload_produces_valid_json() {
        let payload = build_otlp_payload(1_700_000_000_000, 0.042, 1500);
        let v: serde_json::Value = serde_json::from_str(&payload).expect("must be valid JSON");
        assert!(
            v.get("resourceLogs").is_some(),
            "must have resourceLogs key"
        );
    }

    #[test]
    fn otlp_payload_contains_energy_attributes() {
        let payload = build_otlp_payload(1_700_000_000_000, 0.042, 1500);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let attrs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"];
        let energy = attrs
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == "ci_energy_saved_kwh")
            .expect("ci_energy_saved_kwh must be present");
        let val = energy["value"]["doubleValue"]
            .as_f64()
            .expect("doubleValue must be f64");
        assert!((val - 0.042).abs() < f64::EPSILON * 100.0);
    }

    #[test]
    fn otlp_payload_contains_exec_ms() {
        let payload = build_otlp_payload(1_700_000_000_000, 0.0, 9999);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let attrs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"];
        let exec = attrs
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == "engine_exec_ms")
            .expect("engine_exec_ms must be present");
        assert_eq!(exec["value"]["intValue"], "9999");
    }

    #[test]
    fn sign_payload_produces_sha256_prefix() {
        let sig = sign_payload("test-secret", r#"{"test":true}"#);
        assert!(
            sig.starts_with("sha256="),
            "signature must start with sha256="
        );
        assert_eq!(sig.len(), "sha256=".len() + 64, "hex must be 64 chars");
    }

    #[test]
    fn emit_otlp_energy_record_returns_receipt_without_webhook() {
        // No JANITOR_ESG_WEBHOOK_URL set → webhook_delivered must be false
        std::env::remove_var("JANITOR_ESG_WEBHOOK_URL");
        let receipt = emit_otlp_energy_record(0.001, 250);
        assert!(!receipt.webhook_delivered);
        assert!(receipt.ts_ms > 0);
        assert!((receipt.ci_energy_saved_kwh - 0.001).abs() < f64::EPSILON * 100.0);
        assert_eq!(receipt.engine_exec_ms, 250);
        assert!(receipt.signature.starts_with("sha256="));
    }

    #[test]
    fn esg_receipt_serde_roundtrip() {
        let receipt = EsgReceipt {
            ts_ms: 1_700_000_000_000,
            ci_energy_saved_kwh: 0.042,
            engine_exec_ms: 1500,
            signature: "sha256=abc123".to_string(),
            webhook_delivered: false,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: EsgReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
    }
}
