//! P3-4 Phase C: Lightweight Warg-compatible registry client.
//!
//! Downloads BYOP Wasm rule modules from a customer-hosted registry over HTTPS.
//! Uses `ureq` (workspace dependency) as the HTTP transport — avoids the
//! multi-GB `warg-protocol` dependency stack per the 8GB Law.
//!
//! ## Protocol
//!
//! 1. `GET {registry_url}/manifest.json` — `{"rules": ["rule_a", ...]}`
//! 2. For each rule ID: `GET {url}/{id}.wasm` → Wasm bytes
//! 3. For each rule ID: `GET {url}/{id}.wasm.sig` → base64 ML-DSA-65 signature
//! 4. Write both to a temp directory; return paths for `WasmHost::new`.
//!
//! Signature verification is delegated to the existing `WasmHost` ML-DSA-65
//! gate via `wasm_pqc_pub_key` in `JanitorPolicy`.

use anyhow::{Context as _, Result};

/// Maximum bytes accepted per Wasm rule module (4 MiB).
const MAX_WASM_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes accepted for the registry manifest (64 KiB).
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum bytes accepted per signature file (8 KiB).
const MAX_SIG_BYTES: usize = 8 * 1024;
/// Maximum rules fetched from a single registry to prevent resource exhaustion.
const MAX_RULES_PER_REGISTRY: usize = 32;

/// RAII container for registry-fetched Wasm rule modules.
///
/// Holds the `TempDir` guard that deletes all `.wasm` and `.wasm.sig` files
/// when this struct is dropped, preventing temp-file accumulation across bounces.
pub struct FetchedWasmRules {
    _temp_dir: tempfile::TempDir,
    /// Absolute paths to the downloaded `.wasm` files.
    /// Each path has a sibling `<path>.sig` file in the same temp directory.
    pub rule_paths: Vec<String>,
}

/// Download and stage Wasm rule modules from `registry_url`.
///
/// Fetches `manifest.json`, then each listed rule's `.wasm` + `.wasm.sig`.
/// Writes all files into a single temp directory.  Signature verification
/// occurs later in `WasmHost::new` when `wasm_pqc_pub_key` is configured.
///
/// Returns `Err` if any rule ID contains unsafe characters, the manifest is
/// malformed, or any HTTP fetch fails.
pub fn fetch_wasm_from_registry(registry_url: &str) -> Result<FetchedWasmRules> {
    let manifest_bytes =
        http_get_bounded(&format!("{registry_url}/manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .context("registry manifest.json is not valid JSON")?;
    let rule_ids: Vec<String> = manifest["rules"]
        .as_array()
        .context("registry manifest.json missing 'rules' array")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .take(MAX_RULES_PER_REGISTRY)
        .collect();

    let temp_dir = tempfile::tempdir().context("creating temp dir for registry rules")?;
    let mut rule_paths = Vec::with_capacity(rule_ids.len());

    for rule_id in &rule_ids {
        validate_rule_id(rule_id)?;

        let wasm_bytes =
            http_get_bounded(&format!("{registry_url}/{rule_id}.wasm"), MAX_WASM_BYTES)?;
        let sig_bytes =
            http_get_bounded(&format!("{registry_url}/{rule_id}.wasm.sig"), MAX_SIG_BYTES)?;

        let wasm_path = temp_dir.path().join(format!("{rule_id}.wasm"));
        let sig_path = temp_dir.path().join(format!("{rule_id}.wasm.sig"));

        std::fs::write(&wasm_path, &wasm_bytes).context("writing wasm rule to temp dir")?;
        std::fs::write(&sig_path, &sig_bytes).context("writing wasm rule signature to temp dir")?;

        rule_paths.push(wasm_path.to_string_lossy().into_owned());
    }

    Ok(FetchedWasmRules {
        _temp_dir: temp_dir,
        rule_paths,
    })
}

/// Reject rule IDs that contain path-traversal or shell-injection characters.
fn validate_rule_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
    {
        anyhow::bail!("unsafe characters in registry rule id: {id:?}");
    }
    Ok(())
}

/// Bounded HTTP GET — refuses responses larger than `max_bytes`.
fn http_get_bounded(url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let mut resp = ureq::get(url)
        .call()
        .with_context(|| format!("HTTP GET failed: {url}"))?;
    resp.body_mut()
        .with_config()
        .limit(max_bytes as u64)
        .read_to_vec()
        .with_context(|| format!("reading HTTP response body from {url}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_rule_ids_pass_validation() {
        let valid = ["my-rule", "rule_a", "Rule123", "a", "my-rule-v2"];
        for id in &valid {
            assert!(validate_rule_id(id).is_ok(), "'{id}' should be valid");
        }
    }

    #[test]
    fn unsafe_rule_ids_rejected() {
        let bad = [
            "../evil",
            "evil/rule",
            "evil;cmd",
            "evil rule",
            "",
            "a\0b",
            "rule.wasm",
        ];
        for id in &bad {
            assert!(
                validate_rule_id(id).is_err(),
                "unsafe rule id {id:?} must be rejected"
            );
        }
    }

    /// Prove the end-to-end contract: a .wasm rule arriving from a registry
    /// with a corrupt PQC signature is rejected by `WasmHost::new` before
    /// any execution occurs.  This is the security invariant that makes
    /// the Warg registry safe to expose to untrusted distribution networks.
    #[test]
    fn registry_wasm_rule_with_corrupt_sig_rejected() {
        use base64::Engine as _;
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen as MlKeyGen, SerDes as MlSerDes};
        use forge::wasm_host::WasmHost;
        use std::collections::HashMap;

        // Minimal WAT that satisfies the ABI (same as in wasm_host tests).
        const MOCK_WAT: &str = r#"(module
          (memory (export "memory") 2)
          (data (i32.const 0) "{\"id\":\"security:test_rule\",\"file\":null,\"line\":null}\n")
          (func (export "output_ptr") (result i32) i32.const 0)
          (func (export "analyze") (param i32 i32) (result i32) i32.const 52)
        )"#;

        // Simulate what `fetch_wasm_from_registry` writes to disk.
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("registry_rule.wasm");
        let sig_path = dir.path().join("registry_rule.wasm.sig");
        std::fs::write(&wasm_path, MOCK_WAT.as_bytes()).unwrap();
        // Corrupt sig — wrong length, will fail ML-DSA-65 length check.
        let corrupt_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        std::fs::write(&sig_path, corrupt_sig.as_bytes()).unwrap();

        // Generate a real ML-DSA-65 key so failure is at sig verification, not key parse.
        let (pk, _sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA-65 keygen failed");
        let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(pk.into_bytes());

        let path_str = wasm_path.to_string_lossy().into_owned();
        match WasmHost::new(&[path_str.as_str()], &HashMap::new(), Some(&pub_key_b64)) {
            Err(err) => assert!(
                err.to_string().contains("exactly"),
                "rejection message must cite expected ML-DSA-65 signature length; got: {err}"
            ),
            Ok(_) => panic!("corrupt PQC signature must reject rule before execution"),
        }
    }
}
