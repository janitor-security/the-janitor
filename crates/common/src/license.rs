use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const LICENSE_KEY_DERIVATION_CONTEXT: &str = "the-janitor/license-ed25519/v1";

/// Repository-embedded Ed25519 verifying key for janitor.lic validation.
///
/// Dummy bootstrap key for Sprint Batch 4. Replace with the production
/// commercial licensing key before enterprise issuance.
pub const JANITOR_LICENSE_PUB_KEY: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct License {
    pub issued_to: String,
    pub expires_at: u64,
    pub features: Vec<String>,
}

fn license_candidate_paths(path: &Path) -> Vec<PathBuf> {
    if let Some(explicit) = std::env::var_os("JANITOR_LICENSE").map(PathBuf::from) {
        return vec![explicit];
    }

    let mut candidates = vec![path.join(".janitor").join("janitor.lic")];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        candidates.push(home.join(".config").join("janitor").join("janitor.lic"));
    }
    candidates
}

fn current_unix_timestamp() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn decode_license_file(contents: &str) -> Option<(Vec<u8>, Signature)> {
    let (payload_b64, signature_b64) = contents.trim().rsplit_once('.')?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.trim())
        .ok()?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(signature_b64.trim()))
        .ok()?;
    let sig_bytes: [u8; 64] = signature_bytes.as_slice().try_into().ok()?;
    Some((payload, Signature::from_bytes(&sig_bytes)))
}

fn derive_license_signing_key(seed_material: &[u8]) -> SigningKey {
    let seed = blake3::derive_key(LICENSE_KEY_DERIVATION_CONTEXT, seed_material);
    SigningKey::from_bytes(&seed)
}

fn local_license_seed_path(project_root: &Path) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("JANITOR_PQC_KEY").map(PathBuf::from) {
        return Some(path);
    }
    let bundled = project_root.join(".janitor_release.key");
    bundled.exists().then_some(bundled)
}

fn local_license_verifying_key(project_root: &Path) -> Option<VerifyingKey> {
    let key_path = local_license_seed_path(project_root)?;
    let seed_material = std::fs::read(key_path).ok()?;
    Some(derive_license_signing_key(&seed_material).verifying_key())
}

pub fn resolve_license_signing_key(project_root: &Path) -> anyhow::Result<SigningKey> {
    let Some(key_path) = local_license_seed_path(project_root) else {
        anyhow::bail!(
            "license signing key unavailable; set JANITOR_PQC_KEY or provision {}",
            project_root.join(".janitor_release.key").display()
        );
    };
    let seed_material = std::fs::read(&key_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read license seed material {}: {e}",
            key_path.display()
        )
    })?;
    Ok(derive_license_signing_key(&seed_material))
}

pub fn encode_license_file(license: &License, signing_key: &SigningKey) -> anyhow::Result<String> {
    let payload = serde_json::to_vec(license)
        .map_err(|e| anyhow::anyhow!("failed to serialize license payload: {e}"))?;
    let signature = signing_key.sign(&payload);
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    Ok(format!("{payload_b64}.{signature_b64}"))
}

pub fn verify_license(path: &Path) -> bool {
    verify_license_candidates(path, license_candidate_paths(path))
}

fn verify_license_candidates(path: &Path, candidates: Vec<PathBuf>) -> bool {
    let Some((payload, signature)) = candidates
        .into_iter()
        .filter_map(|candidate| std::fs::read_to_string(candidate).ok())
        .find_map(|contents| decode_license_file(&contents))
    else {
        return false;
    };
    let mut verifying_keys = Vec::with_capacity(2);
    if let Some(local_key) = local_license_verifying_key(path) {
        verifying_keys.push(local_key);
    }
    let embedded_key = match VerifyingKey::from_bytes(&JANITOR_LICENSE_PUB_KEY) {
        Ok(key) => key,
        Err(_) => return false,
    };
    verifying_keys.push(embedded_key);

    if verifying_keys
        .iter()
        .all(|verifying_key| verifying_key.verify(&payload, &signature).is_err())
    {
        return false;
    }
    let license: License = match serde_json::from_slice(&payload) {
        Ok(license) => license,
        Err(_) => return false,
    };
    matches!(
        current_unix_timestamp(),
        Some(now) if now <= license.expires_at
    )
}

#[cfg(test)]
mod tests {
    use super::{
        encode_license_file, license_candidate_paths, resolve_license_signing_key, verify_license,
        verify_license_candidates, License, JANITOR_LICENSE_PUB_KEY,
    };
    use ed25519_dalek::VerifyingKey;
    use tempfile::tempdir;

    #[test]
    fn embedded_dummy_license_key_is_valid() {
        let verifying_key = VerifyingKey::from_bytes(&JANITOR_LICENSE_PUB_KEY)
            .expect("embedded dummy key must remain a valid Ed25519 point");
        assert_eq!(verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn missing_license_returns_false() {
        let dir = tempdir().expect("tempdir");
        assert!(!verify_license(dir.path()));
    }

    #[test]
    fn default_candidates_include_project_then_global_license() {
        let dir = tempdir().expect("tempdir");
        let candidates = license_candidate_paths(dir.path());
        assert_eq!(
            candidates[0],
            dir.path().join(".janitor").join("janitor.lic")
        );
        assert!(
            candidates
                .iter()
                .any(|path| path.ends_with(".config/janitor/janitor.lic")),
            "global user config fallback must be present when HOME is set"
        );
    }

    #[test]
    fn locally_derived_license_round_trips() {
        let dir = tempdir().expect("tempdir");
        let key_path = dir.path().join(".janitor_release.key");
        std::fs::write(&key_path, vec![0x5a; 4128]).expect("write local seed material");
        let signing_key = resolve_license_signing_key(dir.path()).expect("resolve signing key");
        let license = License {
            issued_to: "unit-test".to_string(),
            expires_at: u64::MAX,
            features: vec!["IFDS".to_string(), "AEG".to_string(), "Wasm".to_string()],
        };
        let encoded = encode_license_file(&license, &signing_key).expect("encode license");
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect("create janitor dir");
        std::fs::write(janitor_dir.join("janitor.lic"), encoded).expect("write license file");

        assert!(verify_license(dir.path()));
    }

    #[test]
    fn global_config_license_fallback_round_trips() {
        let dir = tempdir().expect("tempdir");
        let key_path = dir.path().join(".janitor_release.key");
        std::fs::write(&key_path, vec![0x5a; 4128]).expect("write local seed material");
        let signing_key = resolve_license_signing_key(dir.path()).expect("resolve signing key");
        let license = License {
            issued_to: "unit-test-global".to_string(),
            expires_at: u64::MAX,
            features: vec!["IFDS".to_string()],
        };
        let encoded = encode_license_file(&license, &signing_key).expect("encode license");
        let global_dir = dir.path().join("home").join(".config").join("janitor");
        std::fs::create_dir_all(&global_dir).expect("create global config dir");
        let global_license = global_dir.join("janitor.lic");
        std::fs::write(&global_license, encoded).expect("write global license file");

        assert!(verify_license_candidates(
            dir.path(),
            vec![
                dir.path().join(".janitor").join("janitor.lic"),
                global_license
            ],
        ));
    }
}
