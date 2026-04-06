//! Governor-sealed decision receipts for offline audit verification.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Embedded Ed25519 verifying key for Governor-sealed decision receipts.
///
/// The corresponding private key must be supplied to `janitor-gov` via runtime
/// environment and is never committed.
pub const GOVERNOR_VERIFYING_KEY_BYTES: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

/// Canonical payload sealed by `janitor-gov` after a bounce decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionReceipt {
    pub policy_hash: String,
    pub wisdom_hash: String,
    pub commit_sha: String,
    pub repo_slug: String,
    pub slop_score: u32,
    pub transparency_anchor: String,
    pub cbom_signature: String,
}

/// Detached Governor signature envelope for a [`DecisionReceipt`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDecisionReceipt {
    pub receipt: DecisionReceipt,
    pub signature: String,
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
            policy_hash: "policy".to_string(),
            wisdom_hash: "wisdom".to_string(),
            commit_sha: "deadbeef".to_string(),
            repo_slug: "owner/repo".to_string(),
            slop_score: 150,
            transparency_anchor: "42:abc123".to_string(),
            cbom_signature: "mlsig".to_string(),
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
}
