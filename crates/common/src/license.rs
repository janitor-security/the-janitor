use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn resolve_license_path(path: &Path) -> PathBuf {
    std::env::var_os("JANITOR_LICENSE")
        .map(PathBuf::from)
        .unwrap_or_else(|| path.join(".janitor").join("janitor.lic"))
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

pub fn verify_license(path: &Path) -> bool {
    let resolved = resolve_license_path(path);
    let contents = match std::fs::read_to_string(&resolved) {
        Ok(contents) => contents,
        Err(_) => return false,
    };
    let (payload, signature) = match decode_license_file(&contents) {
        Some(decoded) => decoded,
        None => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&JANITOR_LICENSE_PUB_KEY) {
        Ok(key) => key,
        Err(_) => return false,
    };
    if verifying_key.verify(&payload, &signature).is_err() {
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
    use super::{verify_license, JANITOR_LICENSE_PUB_KEY};
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
}
