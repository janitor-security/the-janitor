use std::path::PathBuf;

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
}

#[cfg(test)]
mod tests {
    use super::PqcKeySource;
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
}
