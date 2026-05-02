//! OAuth Pre-Account Fusion Detector (P1-13).
//!
//! Detects identity pre-account takeover — the pattern where a local account is
//! created or looked up by email and then merged with an OAuth/SSO identity
//! without requiring that the local email address is verified first.
//!
//! ## Detection Strategy
//!
//! Uses AhoCorasick pre-screen for account-merge sink keywords, then emits
//! `security:oauth_account_fusion_pretakeover` at `KevCritical` when the merge
//! sink is NOT preceded by an email-verification dominance check within the same
//! source block (± 30 lines heuristic window).
//!
//! Plain email equality (`user.email == provider.email`) is explicitly NOT a
//! sufficient sanitizer — only a boolean verified flag, a signed token check, or
//! a provider-attested claim counts.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// Merge-sink patterns (account linking / identity fusion)
// ---------------------------------------------------------------------------

/// AhoCorasick automaton for account-merge sink keywords.
fn merge_sink_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "linkAccount".as_bytes(),
            b"link_account",
            b"mergeAccount",
            b"merge_account",
            b"connectProvider",
            b"connect_provider",
            b"associateIdentity",
            b"associate_identity",
            b"find_or_create_by",
            b"findOrCreateBy",
            b"OAuth.link",
            b"passport.authenticate",
            b"OmniAuth",
            b"omniauth",
            b"provider_link",
            b"account_link",
            b"NextAuth",
            b"linkWithCredential",
            b"linkWithPopup",
            b"linkWithRedirect",
        ])
        .expect("merge_sink_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Email-verification dominator patterns
// ---------------------------------------------------------------------------

/// AhoCorasick automaton for email-verified dominator keywords.
fn email_verified_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "email_verified".as_bytes(),
            b"emailVerified",
            b"email_confirmed",
            b"emailConfirmed",
            b"isVerified",
            b"is_verified",
            b"verifiedEmail",
            b"verified_email",
            b"email_verification_token",
            b"confirm_email",
            b"confirmEmail",
            b"verifyEmail",
            b"verify_email",
            b"EmailVerified",
            b"providerData.email_verified",
            b"id_token_hint",
            b"email:verified",
        ])
        .expect("email_verified_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `source` for OAuth pre-account-takeover patterns.
///
/// Returns one finding per merge sink that is not locally dominated by an
/// email-verification guard within a ±30-line heuristic window.
pub fn detect_oauth_account_fusion(source: &[u8]) -> Vec<SlopFinding> {
    let mut out = Vec::new();
    let sink_ac = merge_sink_ac();

    for mat in sink_ac.find_iter(source) {
        let sink_byte = mat.start();
        let sink_end = mat.end();

        // Extract a ±30-line window around the sink.
        let window_start = window_line_start(source, sink_byte, 30);
        let window_end = window_line_end(source, sink_end, 30);
        let window = &source[window_start..window_end];

        // If no verification guard found in the window, fire.
        if !email_verified_ac().is_match(window) {
            let line = byte_to_line(source, sink_byte);
            let pattern_text =
                std::str::from_utf8(&source[sink_byte..sink_end]).unwrap_or("<utf8-error>");
            out.push(SlopFinding {
                start_byte: sink_byte,
                end_byte: sink_end,
                description: format!(
                    "security:oauth_account_fusion_pretakeover — account merge sink \
                     `{pattern_text}` at line {line} is not dominated by an \
                     email_verified check; attacker can pre-register victim email \
                     and absorb the OAuth identity (CWE-287, OWASP A07)"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::KevCritical,
            });
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Walk backwards from `byte` by up to `lines` newlines.
fn window_line_start(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos > 0 {
        pos -= 1;
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
    }
    0
}

/// Walk forwards from `byte` by up to `lines` newlines.
fn window_line_end(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos < source.len() {
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
        pos += 1;
    }
    source.len()
}

/// Convert a byte offset to a 1-indexed line number.
fn byte_to_line(source: &[u8], byte: usize) -> usize {
    source[..byte.min(source.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_linkacount_without_email_verified() {
        let src = b"
async function oauthCallback(req, res) {
  const user = await User.findOrCreateBy({ email: req.body.email });
  await linkAccount(user, req.oauthProfile);
}
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "linkAccount without email_verified must fire"
        );
        assert!(findings[0].description.contains("oauth_account_fusion"));
        assert_eq!(findings[0].severity, Severity::KevCritical);
    }

    #[test]
    fn suppressed_when_email_verified_guard_present() {
        let src = b"
async function oauthCallback(req, res) {
  if (!req.oauthProfile.email_verified) {
    return res.status(403).json({ error: 'email not verified' });
  }
  const user = await User.findOrCreateBy({ email: req.oauthProfile.email });
  await linkAccount(user, req.oauthProfile);
}
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            findings.is_empty(),
            "email_verified guard must suppress the finding"
        );
    }

    #[test]
    fn flags_passport_authenticate_without_verification() {
        let src = b"
router.get('/auth/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    mergeAccount(req.user, req.session.localUser);
    res.redirect('/dashboard');
  }
);
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "passport.authenticate + mergeAccount without email verification must fire"
        );
    }

    #[test]
    fn suppressed_when_emailconfirmed_used() {
        let src = b"
def oauth_callback(request):
    if not request.social_auth.email_confirmed:
        raise PermissionDenied
    user = User.objects.find_or_create_by(email=request.social_auth.email)
    link_account(user, request.social_auth)
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            findings.is_empty(),
            "email_confirmed guard must suppress the finding"
        );
    }

    #[test]
    fn flags_omniauth_without_verification() {
        let src = b"
def omniauth_callback
  @user = User.find_or_create_by(email: auth.info.email)
  sign_in_and_redirect @user
end
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "OmniAuth find_or_create_by without email_verified must fire"
        );
    }
}
