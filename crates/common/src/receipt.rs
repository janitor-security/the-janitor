//! Governor-sealed decision receipts and replay capsules for offline audit verification.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write as _;
use std::path::Path;

/// Embedded Ed25519 verifying key for Governor-sealed decision receipts.
///
/// The corresponding private key must be supplied to `janitor-gov` via runtime
/// environment and is never committed.
pub const GOVERNOR_VERIFYING_KEY_BYTES: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

const CHECKSUM_LEN: usize = 32;

/// Deterministic semantic mutation root captured at bounce time.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct CapsuleMutationRoot {
    pub language: String,
    pub hash: String,
    pub bytes: Vec<u8>,
}

/// Replayable raw score vector sealed into a [`DecisionCapsule`].
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct DecisionScoreVector {
    pub dead_symbols_added: u32,
    pub logic_clones_found: u32,
    pub zombie_symbols_added: u32,
    pub antipattern_score: u32,
    pub comment_violations: u32,
    pub unlinked_pr: u32,
    pub hallucinated_security_fix: u32,
    pub agentic_origin_penalty: u32,
    pub version_silo_count: u32,
}

impl DecisionScoreVector {
    /// Replay the canonical slop-score reduction over the sealed vector.
    pub fn score(&self) -> u32 {
        let clamped_clones = self.logic_clones_found.min(50);
        let capped_antipattern_score = self.antipattern_score.min(500);
        clamped_clones * 5
            + self.zombie_symbols_added * 10
            + capped_antipattern_score
            + self.comment_violations * 5
            + self.unlinked_pr * 20
            + self.hallucinated_security_fix * 100
            + self.agentic_origin_penalty
            + self.version_silo_count * 20
    }
}

/// Compact, replayable evidence bundle for offline audit reenactment.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct DecisionCapsule {
    pub execution_tier: String,
    pub mutation_roots: Vec<CapsuleMutationRoot>,
    pub policy_hash: String,
    pub wisdom_hash: String,
    pub cbom_digest: String,
    pub score_vector: DecisionScoreVector,
    pub wasm_policy_receipts: Vec<crate::wasm_receipt::WasmPolicyReceipt>,
    /// BLAKE3 hex digest of `.janitor/taint_catalog.rkyv` at the moment the
    /// bounce decision was sealed.
    ///
    /// `None` when no taint catalog was loaded (first run, catalog missing, or
    /// cross-file analysis not triggered for the patched language).
    ///
    /// When present, downstream replay tooling can verify that the catalog state
    /// used during detection matches the current on-disk archive — a
    /// cryptographic proof that the taint catalog was not tampered between the
    /// original bounce and the replay (CT-013).
    #[serde(default)]
    pub taint_catalog_hash: Option<String>,
}

impl DecisionCapsule {
    /// Deterministically serialize the capsule payload.
    pub fn to_canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| anyhow::anyhow!("serializing decision capsule failed: {e}"))
    }

    /// BLAKE3 hex digest of the canonical capsule payload.
    pub fn hash(&self) -> anyhow::Result<String> {
        Ok(blake3::hash(&self.to_canonical_bytes()?)
            .to_hex()
            .to_string())
    }

    /// Verify every stored mutation root against its sealed hash.
    pub fn verify_roots(&self) -> anyhow::Result<()> {
        for root in &self.mutation_roots {
            let actual = blake3::hash(&root.bytes).to_hex().to_string();
            if actual != root.hash {
                anyhow::bail!(
                    "decision capsule mutation root hash mismatch for language {}",
                    root.language
                );
            }
        }
        Ok(())
    }
}

/// Canonical payload sealed by `janitor-gov` after a bounce decision.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct DecisionReceipt {
    pub execution_tier: String,
    pub policy_hash: String,
    pub wisdom_hash: String,
    pub commit_sha: String,
    pub repo_slug: String,
    pub slop_score: u32,
    pub transparency_anchor: String,
    pub cbom_signature: String,
    pub capsule_hash: String,
    pub wasm_policy_receipts: Vec<crate::wasm_receipt::WasmPolicyReceipt>,
}

/// Detached Governor signature envelope for a [`DecisionReceipt`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SignedDecisionReceipt {
    pub receipt: DecisionReceipt,
    pub signature: String,
}

/// On-disk replay envelope pairing the sealed capsule and Governor receipt.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SealedDecisionCapsule {
    pub capsule: DecisionCapsule,
    pub receipt: SignedDecisionReceipt,
}

impl SignedDecisionReceipt {
    /// Deterministically serialize the signed payload bytes.
    pub fn signing_payload(receipt: &DecisionReceipt) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(receipt)
            .map_err(|e| anyhow::anyhow!("serializing decision receipt payload failed: {e}"))
    }

    /// Sign a receipt with the supplied Governor Ed25519 signing key.
    pub fn sign(receipt: DecisionReceipt, signing_key: &SigningKey) -> anyhow::Result<Self> {
        let payload = Self::signing_payload(&receipt)?;
        let signature = signing_key.sign(&payload);
        Ok(Self {
            receipt,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Verify the receipt against the embedded Governor public key.
    pub fn verify(&self) -> anyhow::Result<()> {
        let payload = Self::signing_payload(&self.receipt)?;
        let verifying_key = VerifyingKey::from_bytes(&GOVERNOR_VERIFYING_KEY_BYTES)
            .map_err(|e| anyhow::anyhow!("invalid embedded Governor verifying key: {e}"))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(self.signature.trim())
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(self.signature.trim())
            })
            .map_err(|e| anyhow::anyhow!("failed to decode Governor receipt signature: {e}"))?;
        let sig_bytes: [u8; 64] = decoded.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("Governor receipt signature must decode to exactly 64 bytes")
        })?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| anyhow::anyhow!("Governor decision receipt signature mismatch"))
    }
}

impl SealedDecisionCapsule {
    /// Persist the sealed replay capsule as `[checksum][rkyv payload]`.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| anyhow::anyhow!("serializing sealed capsule failed: {e}"))?;
        let checksum = blake3::hash(&payload);
        let tmp = path.with_extension("capsule.tmp");
        {
            let mut file = File::create(&tmp)?;
            file.write_all(checksum.as_bytes())?;
            file.write_all(&payload)?;
            file.flush()?;
        }
        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        Ok(())
    }

    /// Load and validate a sealed replay capsule from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < CHECKSUM_LEN {
            anyhow::bail!("sealed capsule is truncated");
        }
        let mut stored = [0_u8; CHECKSUM_LEN];
        stored.copy_from_slice(&bytes[..CHECKSUM_LEN]);
        let payload = &bytes[CHECKSUM_LEN..];
        if blake3::hash(payload).as_bytes() != &stored {
            anyhow::bail!("sealed capsule checksum mismatch");
        }
        let archived = rkyv::access::<ArchivedSealedDecisionCapsule, rkyv::rancor::Error>(payload)
            .map_err(|e| anyhow::anyhow!("sealed capsule access failed: {e}"))?;
        rkyv::deserialize::<SealedDecisionCapsule, rkyv::rancor::Error>(archived)
            .map_err(|e| anyhow::anyhow!("sealed capsule deserialize failed: {e}"))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Test-only Ed25519 seed matching `GOVERNOR_VERIFYING_KEY_BYTES`.
    pub const TEST_GOVERNOR_SIGNING_KEY_SEED: [u8; 32] = [
        0x23, 0x70, 0xde, 0x11, 0x87, 0xe8, 0xd5, 0x7e, 0x42, 0x3d, 0x3e, 0xe0, 0x38, 0x64, 0x2c,
        0x41, 0x3e, 0x27, 0x23, 0x36, 0xd4, 0x26, 0x5c, 0x1b, 0xc4, 0x1c, 0x6c, 0x22, 0x9a, 0xc4,
        0xeb, 0xe5,
    ];

    fn sample_receipt() -> DecisionReceipt {
        DecisionReceipt {
            execution_tier: "Community".to_string(),
            policy_hash: "policy".to_string(),
            wisdom_hash: "wisdom".to_string(),
            commit_sha: "deadbeef".to_string(),
            repo_slug: "owner/repo".to_string(),
            slop_score: 150,
            transparency_anchor: "42:abc123".to_string(),
            cbom_signature: "mlsig".to_string(),
            capsule_hash: "capsule".to_string(),
            wasm_policy_receipts: Vec::new(),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = SigningKey::from_bytes(&TEST_GOVERNOR_SIGNING_KEY_SEED);
        let signed =
            SignedDecisionReceipt::sign(sample_receipt(), &signing_key).expect("receipt must sign");
        signed.verify().expect("receipt must verify");
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let signing_key = SigningKey::from_bytes(&TEST_GOVERNOR_SIGNING_KEY_SEED);
        let mut signed =
            SignedDecisionReceipt::sign(sample_receipt(), &signing_key).expect("receipt must sign");
        signed.receipt.slop_score = 999;
        assert!(signed.verify().is_err(), "tampered receipt must fail");
    }

    #[test]
    fn capsule_hash_and_root_verification_roundtrip() {
        let capsule = DecisionCapsule {
            execution_tier: "Community".to_string(),
            mutation_roots: vec![CapsuleMutationRoot {
                language: "js".to_string(),
                hash: blake3::hash(b"eval(atob(\"boom\"))").to_hex().to_string(),
                bytes: b"eval(atob(\"boom\"))".to_vec(),
            }],
            policy_hash: "policy".to_string(),
            wisdom_hash: "wisdom".to_string(),
            cbom_digest: "cbom".to_string(),
            wasm_policy_receipts: Vec::new(),
            taint_catalog_hash: None,
            score_vector: DecisionScoreVector {
                antipattern_score: 150,
                ..DecisionScoreVector::default()
            },
        };
        capsule.verify_roots().unwrap();
        assert!(!capsule.hash().unwrap().is_empty());
    }
}
