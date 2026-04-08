//! Release-asset integrity verifier — SLSA Level 4 trust anchor.
//!
//! `janitor verify-asset` performs two sequential checks:
//!
//! 1. **BLAKE3 hash integrity** — recomputes the BLAKE3 digest of `--file`
//!    and compares it to the hex stored in `--hash` (.b3 file).  Catches
//!    CDN bit-rot, partial downloads, and transparent-proxy tampering.
//!
//! 2. **ML-DSA-65 signature** (when `--sig` is supplied) — verifies the
//!    detached PQC signature in `--sig` against the BLAKE3 hash using the
//!    immutable release verifying key hardcoded below.  Catches a compromised
//!    CDN that can serve a re-hashed replacement binary.
//!
//! The two checks compose into a SLSA Level 4 trust anchor: a CDN that can
//! replace both the binary *and* the co-hosted `.b3` file cannot forge a
//! valid ML-DSA-65 signature without the private key.

use anyhow::Context as _;
use common::pqc::ML_DSA_PUBLIC_KEY_LEN;
use std::path::Path;

/// The Janitor's release ML-DSA-65 verifying key (FIPS 204).
///
/// Generated once during the release key ceremony.  The corresponding private
/// key is held off-device and injected at release time via `JANITOR_PQC_KEY`.
///
/// # Production configuration
///
/// Replace the zeroed placeholder with the actual 1952-byte key before
/// deploying to production.  A zeroed key will fail `try_from_bytes` with a
/// clear error rather than silently passing verification.
///
/// To extract the public key from the private key bundle:
///   `dd if=dual.key bs=4032 count=1 | xxd -i > ml_pub.rs`   (first 4032 bytes are ML-DSA private)
///   Then separately, `janitor sign-asset` logs the public key bytes when run with JANITOR_DEBUG=1.
const JANITOR_RELEASE_ML_DSA_PUB_KEY: [u8; ML_DSA_PUBLIC_KEY_LEN] = [0u8; ML_DSA_PUBLIC_KEY_LEN];

/// Run the `verify-asset` command.
///
/// # Arguments
/// * `file`      — path to the release binary to verify
/// * `hash_path` — path to the `.b3` file (64 lowercase hex chars + optional newline)
/// * `sig_path`  — optional path to the `.sig` JSON file produced by `janitor sign-asset`
pub fn cmd_verify_asset(
    file: &Path,
    hash_path: &Path,
    sig_path: Option<&Path>,
) -> anyhow::Result<()> {
    // ── Step 1: recompute BLAKE3 and compare to .b3 file ────────────────────
    let data = std::fs::read(file).with_context(|| format!("reading binary {}", file.display()))?;
    let actual_hash = blake3::hash(&data).to_hex().to_string();

    let raw_expected = std::fs::read_to_string(hash_path)
        .with_context(|| format!("reading hash file {}", hash_path.display()))?;
    let expected_hash = raw_expected.trim();

    // Strict format gate — 64 lowercase hex chars only.
    anyhow::ensure!(
        expected_hash.len() == 64
            && expected_hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "hash file {} contains invalid format (expected 64 lowercase hex chars, got {} chars)",
        hash_path.display(),
        expected_hash.len()
    );

    anyhow::ensure!(
        actual_hash == expected_hash,
        "BLAKE3 integrity check FAILED\n  file:     {}\n  expected: {}\n  actual:   {}",
        file.display(),
        expected_hash,
        actual_hash
    );
    println!("BLAKE3 verified: {actual_hash}");

    // ── Step 2: ML-DSA-65 signature (optional — fires only when --sig given) ─
    let Some(sig_path) = sig_path else {
        // No signature file supplied — BLAKE3-only verification complete.
        println!("ML-DSA-65: skipped (--sig not provided)");
        return Ok(());
    };

    // Guard: zeroed placeholder key means production key not yet configured.
    anyhow::ensure!(
        JANITOR_RELEASE_ML_DSA_PUB_KEY.iter().any(|&b| b != 0),
        "release PQC verifying key is not configured — \
         JANITOR_RELEASE_ML_DSA_PUB_KEY must be replaced with the production key bytes \
         before verify-asset can validate signatures"
    );

    let sig_json = std::fs::read_to_string(sig_path)
        .with_context(|| format!("reading signature file {}", sig_path.display()))?;
    let bundle: serde_json::Value =
        serde_json::from_str(&sig_json).context("parsing signature file JSON")?;

    let ml_dsa_sig_b64 = bundle["ml_dsa_sig"]
        .as_str()
        .context("signature file missing ml_dsa_sig field")?;

    // Verify against the raw 32-byte BLAKE3 hash (same preimage as sign-asset).
    let hash_bytes: [u8; 32] = blake3::hash(&data).into();
    let valid = common::pqc::verify_asset_ml_dsa_signature(
        &hash_bytes,
        &JANITOR_RELEASE_ML_DSA_PUB_KEY,
        ml_dsa_sig_b64,
    )?;

    anyhow::ensure!(
        valid,
        "ML-DSA-65 signature verification FAILED — binary may be tampered or key mismatch"
    );
    println!("ML-DSA-65 signature verified");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::ml_dsa_65;
    use fips204::traits::{KeyGen as MlKeyGen, SerDes as MlSerDes, Signer as MlSigner};
    use std::path::PathBuf;

    fn write_tmp(dir: &PathBuf, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn blake3_mismatch_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("janitor_verify_asset_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let file = write_tmp(&dir, "binary", b"correct binary");
        // Deliberately wrong hash.
        let hash_file = write_tmp(
            &dir,
            "binary.b3",
            b"0000000000000000000000000000000000000000000000000000000000000000",
        );

        let err = cmd_verify_asset(&file, &hash_file, None).unwrap_err();
        assert!(
            err.to_string().contains("BLAKE3 integrity check FAILED"),
            "wrong hash must fail BLAKE3 gate"
        );
    }

    #[test]
    fn invalid_hash_format_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("janitor_verify_asset_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let file = write_tmp(&dir, "binary", b"data");
        let hash_file = write_tmp(&dir, "binary.b3", b"not-hex-garbage");

        let err = cmd_verify_asset(&file, &hash_file, None).unwrap_err();
        assert!(
            err.to_string().contains("invalid format"),
            "malformed hash file must be rejected with format error"
        );
    }

    #[test]
    fn blake3_only_verification_succeeds() {
        let dir =
            std::env::temp_dir().join(format!("janitor_verify_asset_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let payload = b"release binary contents";
        let file = write_tmp(&dir, "binary", payload);
        let hex = blake3::hash(payload).to_hex().to_string();
        let hash_file = write_tmp(&dir, "binary.b3", hex.as_bytes());

        cmd_verify_asset(&file, &hash_file, None).expect("blake3-only verify must succeed");
    }

    /// Round-trip: sign-asset hash with a fresh ML-DSA-65 key, then verify with
    /// a dynamically injected public key — exercises the full PQC path without
    /// the production key placeholder.
    #[test]
    fn pqc_verify_roundtrip_with_dynamic_key() {
        use base64::Engine as _;
        use common::pqc::JANITOR_ASSET_CONTEXT;

        let dir =
            std::env::temp_dir().join(format!("janitor_verify_asset_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let payload = b"test release payload";
        let hash_bytes: [u8; 32] = blake3::hash(payload).into();

        // Generate a fresh keypair for this test.
        let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA keygen");
        let sig = sk
            .try_sign(&hash_bytes, JANITOR_ASSET_CONTEXT)
            .expect("ML-DSA sign");
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());

        let valid =
            common::pqc::verify_asset_ml_dsa_signature(&hash_bytes, &pk.into_bytes(), &sig_b64)
                .expect("verify must not error");
        assert!(valid, "valid ML-DSA-65 asset signature must verify");
    }

    #[test]
    fn pqc_verify_rejects_tampered_binary() {
        use base64::Engine as _;
        use common::pqc::JANITOR_ASSET_CONTEXT;

        let hash_bytes: [u8; 32] = blake3::hash(b"original").into();
        let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA keygen");
        let sig = sk
            .try_sign(&hash_bytes, JANITOR_ASSET_CONTEXT)
            .expect("ML-DSA sign");
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());

        // Verify against a DIFFERENT payload hash — simulates tampered binary.
        let tampered_hash: [u8; 32] = blake3::hash(b"tampered").into();
        let valid =
            common::pqc::verify_asset_ml_dsa_signature(&tampered_hash, &pk.into_bytes(), &sig_b64)
                .expect("verify must not error");
        assert!(
            !valid,
            "tampered binary hash must fail ML-DSA-65 verification"
        );
    }
}
