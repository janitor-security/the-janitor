use anyhow::{bail, Context};
use base64::Engine as _;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as MlSerDes, Signer as MlSigner, Verifier as MlVerifier};
use fips205::slh_dsa_shake_192s;
use fips205::traits::{SerDes as SlhSerDes, Signer as SlhSigner, Verifier as SlhVerifier};
use std::path::{Path, PathBuf};

pub const JANITOR_CBOM_CONTEXT: &[u8] = b"janitor-cbom";
pub const ML_DSA_PRIVATE_KEY_LEN: usize = 4032;
pub const ML_DSA_PUBLIC_KEY_LEN: usize = 1952;
pub const SLH_DSA_PRIVATE_KEY_LEN: usize = slh_dsa_shake_192s::SK_LEN;
pub const SLH_DSA_PUBLIC_KEY_LEN: usize = slh_dsa_shake_192s::PK_LEN;
pub const SLH_DSA_VARIANT: &str = "SLH-DSA-SHAKE-192s";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcSignatureBundle {
    pub ml_dsa_sig: Option<String>,
    pub slh_dsa_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcPrivateKeyBundle {
    pub ml_dsa: Option<[u8; ML_DSA_PRIVATE_KEY_LEN]>,
    pub slh_dsa: Option<[u8; SLH_DSA_PRIVATE_KEY_LEN]>,
}

/// Parsed source of a `--pqc-key` attestation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcKeySource {
    /// Local filesystem path containing a raw ML-DSA-65 private key.
    File(PathBuf),
    /// AWS KMS key ARN (commercial Governor integration only).
    AwsKmsArn(String),
    /// Azure Key Vault key URI (commercial Governor integration only).
    AzureKeyVaultUrl(String),
    /// PKCS#11 URI (commercial Governor integration only).
    Pkcs11Uri(String),
}

impl PqcKeySource {
    /// Parse the operator-supplied `--pqc-key` value into a typed source.
    pub fn parse(raw: &str) -> Self {
        if raw.starts_with("arn:aws:kms:") {
            Self::AwsKmsArn(raw.to_owned())
        } else if raw.starts_with("pkcs11:") {
            Self::Pkcs11Uri(raw.to_owned())
        } else if raw.starts_with("https://") && raw.contains("vault.azure.net") {
            Self::AzureKeyVaultUrl(raw.to_owned())
        } else {
            Self::File(PathBuf::from(raw))
        }
    }

    /// Returns `true` when this source requires the commercial Governor binary.
    pub fn requires_commercial_governor(&self) -> bool {
        !matches!(self, Self::File(_))
    }

    /// Stable custody label written to bounce logs and CBOM properties.
    pub fn custody_label(&self) -> &'static str {
        match self {
            Self::File(_) => "filesystem",
            Self::AwsKmsArn(_) => "aws-kms",
            Self::AzureKeyVaultUrl(_) => "azure-kv",
            Self::Pkcs11Uri(_) => "pkcs11",
        }
    }
}

pub fn sign_cbom_dual_from_file(
    cbom_bytes: &[u8],
    path: &Path,
) -> anyhow::Result<PqcSignatureBundle> {
    let key_bytes = std::fs::read(path)
        .with_context(|| format!("reading PQC private key bundle: {}", path.display()))?;
    let keys = private_key_bundle_from_bytes(&key_bytes)?;
    sign_cbom_dual_from_keys(cbom_bytes, &keys)
}

pub fn sign_cbom_dual_from_keys(
    cbom_bytes: &[u8],
    keys: &PqcPrivateKeyBundle,
) -> anyhow::Result<PqcSignatureBundle> {
    let ml_dsa_sig = if let Some(sk_bytes) = keys.ml_dsa {
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 private key: {e}"))?;
        let sig = sk
            .try_sign(cbom_bytes, JANITOR_CBOM_CONTEXT)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;
        Some(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
    } else {
        None
    };

    let slh_dsa_sig = if let Some(sk_bytes) = keys.slh_dsa {
        let sk = slh_dsa_shake_192s::PrivateKey::try_from_bytes(&sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid {SLH_DSA_VARIANT} private key: {e}"))?;
        let sig = sk
            .try_sign(cbom_bytes, JANITOR_CBOM_CONTEXT, true)
            .map_err(|e| anyhow::anyhow!("{SLH_DSA_VARIANT} signing failed: {e}"))?;
        Some(base64::engine::general_purpose::STANDARD.encode(sig))
    } else {
        None
    };

    if ml_dsa_sig.is_none() && slh_dsa_sig.is_none() {
        bail!("PQC private key bundle contained neither ML-DSA-65 nor {SLH_DSA_VARIANT} material");
    }

    Ok(PqcSignatureBundle {
        ml_dsa_sig,
        slh_dsa_sig,
    })
}

pub fn verify_ml_dsa_signature(
    cbom_bytes: &[u8],
    public_key_bytes: &[u8],
    sig_b64: &str,
) -> anyhow::Result<bool> {
    let pk_array: [u8; ML_DSA_PUBLIC_KEY_LEN] = public_key_bytes.try_into().map_err(|_| {
        anyhow::anyhow!("ML-DSA-65 public key must be exactly {ML_DSA_PUBLIC_KEY_LEN} bytes")
    })?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_array)
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 public key: {e}"))?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .context("base64 decode of ML-DSA-65 signature failed")?;
    let sig_array: [u8; ml_dsa_65::SIG_LEN] = sig_bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "ML-DSA-65 signature must decode to exactly {} bytes",
            ml_dsa_65::SIG_LEN
        )
    })?;
    Ok(pk.verify(cbom_bytes, &sig_array, JANITOR_CBOM_CONTEXT))
}

pub fn verify_slh_dsa_signature(
    cbom_bytes: &[u8],
    public_key_bytes: &[u8],
    sig_b64: &str,
) -> anyhow::Result<bool> {
    let pk_array: [u8; SLH_DSA_PUBLIC_KEY_LEN] = public_key_bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "{SLH_DSA_VARIANT} public key must be exactly {SLH_DSA_PUBLIC_KEY_LEN} bytes"
        )
    })?;
    let pk = slh_dsa_shake_192s::PublicKey::try_from_bytes(&pk_array)
        .map_err(|e| anyhow::anyhow!("invalid {SLH_DSA_VARIANT} public key: {e}"))?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .context("base64 decode of SLH-DSA signature failed")?;
    let sig_array: [u8; slh_dsa_shake_192s::SIG_LEN] = sig_bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "{SLH_DSA_VARIANT} signature must decode to exactly {} bytes",
            slh_dsa_shake_192s::SIG_LEN
        )
    })?;
    Ok(pk.verify(cbom_bytes, &sig_array, JANITOR_CBOM_CONTEXT))
}

fn private_key_bundle_from_bytes(bytes: &[u8]) -> anyhow::Result<PqcPrivateKeyBundle> {
    match bytes.len() {
        ML_DSA_PRIVATE_KEY_LEN => {
            let ml_dsa = bytes.try_into().map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 key length"))?;
            Ok(PqcPrivateKeyBundle {
                ml_dsa: Some(ml_dsa),
                slh_dsa: None,
            })
        }
        SLH_DSA_PRIVATE_KEY_LEN => {
            let slh_dsa = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid {SLH_DSA_VARIANT} key length"))?;
            Ok(PqcPrivateKeyBundle {
                ml_dsa: None,
                slh_dsa: Some(slh_dsa),
            })
        }
        len if len == ML_DSA_PRIVATE_KEY_LEN + SLH_DSA_PRIVATE_KEY_LEN => {
            let (ml_bytes, slh_bytes) = bytes.split_at(ML_DSA_PRIVATE_KEY_LEN);
            let ml_dsa = ml_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 key bundle prefix"))?;
            let slh_dsa = slh_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid {SLH_DSA_VARIANT} key bundle suffix"))?;
            Ok(PqcPrivateKeyBundle {
                ml_dsa: Some(ml_dsa),
                slh_dsa: Some(slh_dsa),
            })
        }
        other => bail!(
            "unsupported PQC private key bundle length {other}; expected {ML_DSA_PRIVATE_KEY_LEN}, {SLH_DSA_PRIVATE_KEY_LEN}, or {} bytes",
            ML_DSA_PRIVATE_KEY_LEN + SLH_DSA_PRIVATE_KEY_LEN
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::PqcKeySource;
    use super::{sign_cbom_dual_from_keys, verify_ml_dsa_signature, PqcPrivateKeyBundle};
    use fips204::ml_dsa_65;
    use fips204::traits::{KeyGen as MlKeyGen, SerDes as MlSerDes};
    use std::path::PathBuf;

    #[test]
    fn parses_aws_kms_arn() {
        let src = PqcKeySource::parse("arn:aws:kms:us-east-1:123456789012:key/abc");
        assert!(matches!(src, PqcKeySource::AwsKmsArn(_)));
        assert!(src.requires_commercial_governor());
    }

    #[test]
    fn parses_azure_key_vault_uri() {
        let src = PqcKeySource::parse("https://corp.vault.azure.net/keys/janitor/main");
        assert!(matches!(src, PqcKeySource::AzureKeyVaultUrl(_)));
        assert!(src.requires_commercial_governor());
    }

    #[test]
    fn parses_pkcs11_uri() {
        let src = PqcKeySource::parse("pkcs11:token=janitor;object=ml-dsa");
        assert!(matches!(src, PqcKeySource::Pkcs11Uri(_)));
        assert!(src.requires_commercial_governor());
    }

    #[test]
    fn parses_local_file_path() {
        let src = PqcKeySource::parse("./mlksa.key");
        assert_eq!(src, PqcKeySource::File(PathBuf::from("./mlksa.key")));
        assert!(!src.requires_commercial_governor());
    }

    #[test]
    fn custody_labels_are_stable() {
        assert_eq!(
            PqcKeySource::parse("./mlksa.key").custody_label(),
            "filesystem"
        );
        assert_eq!(
            PqcKeySource::parse("arn:aws:kms:us-east-1:123456789012:key/abc").custody_label(),
            "aws-kms"
        );
        assert_eq!(
            PqcKeySource::parse("https://corp.vault.azure.net/keys/janitor/main").custody_label(),
            "azure-kv"
        );
        assert_eq!(
            PqcKeySource::parse("pkcs11:token=janitor;object=ml-dsa").custody_label(),
            "pkcs11"
        );
    }

    #[test]
    fn ml_only_bundle_roundtrip_verifies_ml_signature() {
        let (ml_pk, ml_sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA keygen must succeed");
        let keys = PqcPrivateKeyBundle {
            ml_dsa: Some(ml_sk.into_bytes()),
            slh_dsa: None,
        };

        let cbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#;
        let signatures = sign_cbom_dual_from_keys(cbom, &keys).expect("dual signing must succeed");

        assert!(signatures.ml_dsa_sig.is_some());
        assert!(signatures.slh_dsa_sig.is_none());
        assert!(verify_ml_dsa_signature(
            cbom,
            &ml_pk.into_bytes(),
            signatures.ml_dsa_sig.as_deref().unwrap()
        )
        .expect("ML-DSA verify must succeed"));
    }

    #[test]
    fn unsupported_bundle_length_fails_closed() {
        let err = super::private_key_bundle_from_bytes(&[0u8; 12]).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported PQC private key bundle length"),
            "bundle parser must explain supported dual-signature key formats"
        );
    }
}
