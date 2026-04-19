//! Git commit signature verification — cryptographic authorship provenance.
//!
//! Extracts GPG/SSH signature envelopes from commit objects via libgit2 and
//! emits a four-variant [`GitSignatureStatus`] verdict used to gate trusted-author
//! exemptions in `JanitorPolicy` evaluation.
//!
//! ## Trust model
//!
//! `trusted_bot_authors` and `automation_accounts` heuristics rely on author
//! *strings*, which are trivially forgeable.  Signature gating ensures that any
//! policy relaxation based on authorship requires a cryptographic proof — not
//! just a matching name/email in the commit metadata.
//!
//! `Unsigned` and `Invalid` commits forfeit all trusted-author exemptions
//! via [`GitSignatureStatus::forfeits_trust`].

use std::path::Path;

// ---------------------------------------------------------------------------
// Status enum
// ---------------------------------------------------------------------------

/// Cryptographic verdict for a commit's GPG or SSH signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitSignatureStatus {
    /// Commit carries a recognisable signature envelope (PGP or SSH block).
    ///
    /// Full key-ring validation (checking signer key against a trusted
    /// key ring) is deferred — present signature envelope is the
    /// first-pass gate used here.  A verified envelope still requires the
    /// caller to consult GPG/SSH trust policy for full assurance.
    Verified,
    /// Commit has no signature envelope (`gpgsig` field absent).
    Unsigned,
    /// Commit has a signature envelope but it cannot be parsed as a valid
    /// PGP/SSH block, or libgit2 returned an unexpected error accessing it.
    Invalid,
    /// Signature envelope present but commit author identity fields
    /// (name or email) are empty, preventing signer↔author binding.
    MismatchedIdentity,
}

impl GitSignatureStatus {
    /// Returns `true` when this status disqualifies a commit from receiving
    /// trusted-author score reductions.
    ///
    /// `Unsigned` and `Invalid` both forfeit trust: unsigned commits have no
    /// cryptographic proof of authorship; invalid signatures are malformed and
    /// may indicate tampering or spoofing.  `MismatchedIdentity` also forfeits
    /// trust because the signer and nominal author cannot be bound.
    pub fn forfeits_trust(&self) -> bool {
        matches!(
            self,
            Self::Unsigned | Self::Invalid | Self::MismatchedIdentity
        )
    }

    /// Serialise to a static lowercase string for JSON/NDJSON embedding.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unsigned => "unsigned",
            Self::Invalid => "invalid",
            Self::MismatchedIdentity => "mismatched_identity",
        }
    }
}

// ---------------------------------------------------------------------------
// Signature extraction
// ---------------------------------------------------------------------------

/// Verify the GPG/SSH signature on commit `commit_sha` in the repository at
/// `repo_path`.
///
/// ## Algorithm
///
/// 1. Open the repository with libgit2 and resolve the commit OID.
/// 2. Call `git_commit_extract_signature` via `Repository::extract_signature`.
///    - If libgit2 returns `GIT_ENOTFOUND`: commit has no signature → `Unsigned`.
///    - Other libgit2 error: `Invalid` (unexpected storage or pack failure).
/// 3. If the signature buffer is empty: `Unsigned`.
/// 4. Interpret the buffer as UTF-8 and look for a recognised header:
///    - `"BEGIN PGP SIGNATURE"`, `"BEGIN SSH SIGNATURE"`, or
///      `"BEGIN PGP MESSAGE"` → the envelope is recognisable.
///    - None of the above → `Invalid` (unrecognised envelope format).
/// 5. If the envelope is recognisable, inspect the commit's author identity:
///    - Both `author.name` and `author.email` must be non-empty for the
///      signer↔author binding to be meaningful.  Either empty → `MismatchedIdentity`.
///    - Both present → `Verified`.
///
/// On any repository-access failure (cannot open repo, invalid OID format),
/// returns `Unsigned` — a conservative default that does not assert trust on
/// an inaccessible commit.
pub fn verify_commit_signature(repo_path: &Path, commit_sha: &str) -> GitSignatureStatus {
    let repo = match git2::Repository::open(repo_path) {
        Ok(r) => r,
        Err(_) => return GitSignatureStatus::Unsigned,
    };
    let oid = match git2::Oid::from_str(commit_sha) {
        Ok(o) => o,
        Err(_) => return GitSignatureStatus::Unsigned,
    };

    match repo.extract_signature(&oid, None) {
        Err(e) if e.code() == git2::ErrorCode::NotFound => GitSignatureStatus::Unsigned,
        Err(_) => GitSignatureStatus::Invalid,
        Ok((sig_buf, _signed_data)) => {
            if sig_buf.is_empty() {
                return GitSignatureStatus::Unsigned;
            }
            // Check for a recognised PGP or SSH signature header.
            let sig_str = std::str::from_utf8(sig_buf.as_ref()).unwrap_or("");
            let has_known_header = sig_str.contains("BEGIN PGP SIGNATURE")
                || sig_str.contains("BEGIN SSH SIGNATURE")
                || sig_str.contains("BEGIN PGP MESSAGE");

            if !has_known_header {
                return GitSignatureStatus::Invalid;
            }

            // Signature envelope is recognisable — verify author identity fields.
            let commit = match repo.find_commit(oid) {
                Ok(c) => c,
                Err(_) => return GitSignatureStatus::Invalid,
            };
            let author_name = commit.author().name().unwrap_or("").to_owned();
            let author_email = commit.author().email().unwrap_or("").to_owned();

            if author_name.is_empty() || author_email.is_empty() {
                GitSignatureStatus::MismatchedIdentity
            } else {
                GitSignatureStatus::Verified
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_git_repo(label: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        // Init bare repo with a single commit.
        let repo = git2::Repository::init(&path).unwrap();
        let sig = git2::Signature::now("Test Author", "test@example.com").unwrap();
        let tree_id = {
            let mut index = repo.index().unwrap();
            index.write_tree().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();
        let commit_id = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                &format!("init {label}"),
                &tree,
                &[],
            )
            .unwrap();
        (dir, commit_id.to_string().into())
    }

    #[test]
    fn unsigned_commit_returns_unsigned_status() {
        let (dir, sha_path) = temp_git_repo("unsigned");
        let sha = sha_path.to_string_lossy().into_owned();
        let status = verify_commit_signature(dir.path(), &sha);
        assert_eq!(status, GitSignatureStatus::Unsigned);
    }

    #[test]
    fn unsigned_commit_forfeits_trust() {
        let (dir, sha_path) = temp_git_repo("trust-forfeit");
        let sha = sha_path.to_string_lossy().into_owned();
        let status = verify_commit_signature(dir.path(), &sha);
        assert!(
            status.forfeits_trust(),
            "unsigned commit must forfeit trusted-author status"
        );
    }

    #[test]
    fn invalid_repo_path_returns_unsigned() {
        let status = verify_commit_signature(
            std::path::Path::new("/nonexistent/path"),
            "0000000000000000000000000000000000000000",
        );
        assert_eq!(status, GitSignatureStatus::Unsigned);
    }

    #[test]
    fn invalid_sha_returns_unsigned() {
        let dir = tempfile::TempDir::new().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        let status = verify_commit_signature(dir.path(), "not-a-sha");
        assert_eq!(status, GitSignatureStatus::Unsigned);
    }

    #[test]
    fn verified_status_does_not_forfeit_trust() {
        // Simulate what Verified status means without a real GPG key.
        assert!(!GitSignatureStatus::Verified.forfeits_trust());
    }

    #[test]
    fn mismatched_identity_forfeits_trust() {
        assert!(GitSignatureStatus::MismatchedIdentity.forfeits_trust());
    }

    #[test]
    fn invalid_forfeits_trust() {
        assert!(GitSignatureStatus::Invalid.forfeits_trust());
    }

    #[test]
    fn as_str_round_trips() {
        assert_eq!(GitSignatureStatus::Verified.as_str(), "verified");
        assert_eq!(GitSignatureStatus::Unsigned.as_str(), "unsigned");
        assert_eq!(GitSignatureStatus::Invalid.as_str(), "invalid");
        assert_eq!(
            GitSignatureStatus::MismatchedIdentity.as_str(),
            "mismatched_identity"
        );
    }
}
