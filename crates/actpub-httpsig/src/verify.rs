//! High-level, flavour-autodetecting verification entry point.
//!
//! A request carrying a `Signature-Input:` header is treated as RFC 9421;
//! otherwise a `Signature:` header alone is treated as Cavage draft-12.
//! This matches how Mastodon 4.5+ negotiates between the two stacks on
//! the receiving side, and lets callers verify either kind with one
//! function call.

use chrono::{DateTime, Utc};
use http::Request;

use crate::cavage::{CavageVerified, cavage_verify, cavage_verify_with_policy};
use crate::error::Error;
use crate::key::VerifyingKey;
use crate::policy::VerifyPolicy;
use crate::rfc9421::{
    Rfc9421Verified, SIGNATURE_INPUT_HEADER, rfc9421_verify, rfc9421_verify_with_policy,
};

/// Headers whose values [`Verified::signature_base_redacted`] replaces
/// with a placeholder.
///
/// All three are low-entropy authentication credentials that a signer
/// should never cover with a signature in the first place, but a
/// defensive logger still wants to strip them from an audit trail
/// before writing the string to disk.
pub const REDACTED_HEADERS_DEFAULT: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Report summarising a successful verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Verified {
    /// The request was signed using the Cavage draft-12 flavour.
    Cavage(CavageVerified),
    /// The request was signed using RFC 9421.
    Rfc9421(Rfc9421Verified),
}

impl Verified {
    /// Returns the `keyId` / `keyid` that identified the signer.
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            Self::Cavage(c) => &c.key_id,
            Self::Rfc9421(r) => r.input.keyid.as_deref().unwrap_or_default(),
        }
    }

    /// Returns the signature base string that was verified, for audit
    /// logging and troubleshooting.
    ///
    /// **Security note.** The signature base contains the literal
    /// value of every header that participated in the signature,
    /// including anything sensitive the signer accidentally covered
    /// (typically nothing on `ActivityPub`, but defence-in-depth still
    /// matters). Prefer [`Self::signature_base_redacted`] for any
    /// log line that might be captured by a third party.
    #[must_use]
    pub fn signature_base(&self) -> &str {
        match self {
            Self::Cavage(c) => &c.signature_base,
            Self::Rfc9421(r) => &r.signature_base,
        }
    }

    /// Returns the signature base string with the values of any header
    /// named in `sensitive_headers` replaced by `<redacted>`.
    ///
    /// The headers are matched case-insensitively against the line
    /// prefix that [`build_signature_base`](crate::rfc9421) /
    /// [`build_signature_base`](crate::cavage) emit; entries not
    /// present in the signature base pass through unchanged.
    ///
    /// Pass [`REDACTED_HEADERS_DEFAULT`] to match the header set this
    /// crate considers sensitive by default.
    #[must_use]
    pub fn signature_base_redacted(&self, sensitive_headers: &[&str]) -> String {
        let base = self.signature_base();
        let mut out = String::with_capacity(base.len());
        for line in base.split_inclusive('\n') {
            out.push_str(&redact_line(line, sensitive_headers));
        }
        out
    }
}

fn redact_line(line: &str, sensitive: &[&str]) -> String {
    let trimmed = line.trim_end_matches('\n');
    let has_newline = line.ends_with('\n');
    let sensitive_hit = sensitive.iter().any(|h| line_header_matches(trimmed, h));
    let Some((prefix, _)) = trimmed.split_once(':').filter(|_| sensitive_hit) else {
        return line.to_owned();
    };
    let mut out = String::with_capacity(prefix.len() + 16);
    out.push_str(prefix);
    out.push_str(": <redacted>");
    if has_newline {
        out.push('\n');
    }
    out
}

/// Whether `line` is of the form `"<name>": …` for one of the
/// two signature-base grammars (RFC 9421's quoted form or Cavage's
/// pseudo-header form), case-insensitively matching `name`.
fn line_header_matches(line: &str, name: &str) -> bool {
    let stripped = line
        .strip_prefix('"')
        .and_then(|s| s.split_once("\":"))
        .map(|(n, _)| n);
    let cavage = line.split_once(':').map(|(n, _)| n);
    stripped
        .or(cavage)
        .is_some_and(|found| found.eq_ignore_ascii_case(name))
}

/// Verifies a signed HTTP request, autodetecting the signature flavour.
///
/// If the request carries a `Signature-Input:` header the RFC 9421
/// verifier is used; otherwise the Cavage draft-12 verifier is tried.
/// The resolver is called with the signer's `keyId` to fetch a
/// [`VerifyingKey`].
///
/// # Errors
///
/// Propagates every error surface of the two underlying verifiers.
/// [`Error::MissingHeader`] is returned when neither `Signature-Input:`
/// nor `Signature:` is present.
pub fn verify<B, F>(req: &Request<B>, mut resolve_key: F) -> Result<Verified, Error>
where
    F: FnMut(&str) -> Result<VerifyingKey, Error>,
{
    if req.headers().contains_key(SIGNATURE_INPUT_HEADER) {
        return rfc9421_verify(req, &mut resolve_key).map(Verified::Rfc9421);
    }
    cavage_verify(req, |kid| resolve_key(kid)).map(Verified::Cavage)
}

/// Verifies a signed HTTP request **with replay-protection**, picking
/// the correct flavour automatically.
///
/// This is [`verify`]'s policy-aware companion: both `VerifyPolicy` and
/// a `now` timestamp are threaded through to the underlying verifier.
///
/// # Errors
///
/// Propagates every error surface of [`cavage_verify_with_policy`] and
/// [`rfc9421_verify_with_policy`].
pub fn verify_with_policy<B, F>(
    req: &Request<B>,
    policy: &VerifyPolicy,
    now: DateTime<Utc>,
    mut resolve_key: F,
) -> Result<Verified, Error>
where
    F: FnMut(&str) -> Result<VerifyingKey, Error>,
{
    if req.headers().contains_key(SIGNATURE_INPUT_HEADER) {
        return rfc9421_verify_with_policy(req, policy, now, &mut resolve_key)
            .map(Verified::Rfc9421);
    }
    cavage_verify_with_policy(req, policy, now, |kid| resolve_key(kid)).map(Verified::Cavage)
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::cavage::CavageSigner;
    use crate::content_digest::content_digest_header;
    use crate::digest::sha256_digest_header;
    use crate::key::SigningKey;
    use crate::rfc9421::Rfc9421Signer;

    fn base_request(body: &[u8]) -> Request<Vec<u8>> {
        // The autodetecting verifier handles both Cavage (legacy
        // `Digest:`) and RFC 9421 (modern `Content-Digest:`), so the
        // fixture carries both headers simultaneously — real dual-stack
        // deployments do the same.
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", sha256_digest_header(body))
            .header("content-digest", content_digest_header(body))
            .header("content-type", "application/activity+json")
            .body(body.to_vec())
            .expect("valid")
    }

    #[test]
    fn cavage_signed_request_is_dispatched_to_cavage_verifier() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        CavageSigner::new(&key, "https://example.com/actor#kid")
            .sign(&mut req)
            .expect("sign");

        let report = verify(&req, |_| Ok(public.clone())).expect("verify");
        assert!(matches!(report, Verified::Cavage(_)));
        assert_eq!(report.key_id(), "https://example.com/actor#kid");
    }

    #[test]
    fn rfc9421_signed_request_is_dispatched_to_rfc9421_verifier() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        Rfc9421Signer::new(&key, "https://example.com/actor#kid")
            .sign(&mut req)
            .expect("sign");

        let report = verify(&req, |_| Ok(public.clone())).expect("verify");
        assert!(matches!(report, Verified::Rfc9421(_)));
        assert_eq!(report.key_id(), "https://example.com/actor#kid");
    }

    #[test]
    fn rfc9421_takes_precedence_over_cavage_when_both_are_present() {
        // Dual-signed outbound messages (some deployments attach both for
        // broad compatibility). Verifier should prefer the modern flavour.
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        CavageSigner::new(&key, "cavage-kid")
            .sign(&mut req)
            .expect("sign cavage");
        Rfc9421Signer::new(&key, "rfc9421-kid")
            .sign(&mut req)
            .expect("sign 9421");

        let report = verify(&req, |_| Ok(public.clone())).expect("verify");
        assert!(matches!(report, Verified::Rfc9421(_)));
        assert_eq!(report.key_id(), "rfc9421-kid");
    }

    #[test]
    fn unsigned_request_returns_missing_header_error() {
        let req = base_request(b"{}");
        let err =
            verify(&req, |_| panic!("resolver must not be called")).expect_err("unsigned request");
        assert!(matches!(err, Error::MissingHeader(_)));
    }

    #[test]
    fn policy_rejects_cavage_signature_older_than_max_age() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        CavageSigner::new(&key, "kid")
            .with_created(1_700_000_000)
            .sign(&mut req)
            .expect("sign");

        // `now` is 20 hours ahead of `created` — well beyond Mastodon's 12h window.
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000 + 20 * 3600, 0).expect("valid");
        let err = verify_with_policy(&req, &VerifyPolicy::mastodon(), now, |_| Ok(public.clone()))
            .expect_err("stale signature must be rejected");
        assert!(matches!(err, Error::TimestampTooOld { .. }));
    }

    #[test]
    fn policy_rejects_rfc9421_signature_in_the_future() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        // Future `created` — 15 minutes ahead of our `now`.
        Rfc9421Signer::new(&key, "kid")
            .with_created(1_700_000_000 + 15 * 60)
            .sign(&mut req)
            .expect("sign");

        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid");
        let err = verify_with_policy(&req, &VerifyPolicy::mastodon(), now, |_| Ok(public.clone()))
            .expect_err("future-dated signature must be rejected");
        assert!(matches!(err, Error::TimestampInFuture { .. }));
    }

    #[test]
    fn signature_base_redacted_masks_sensitive_header_values_for_cavage() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let secret = "Bearer s3cr3t-token";
        let mut req = base_request(b"{}");
        req.headers_mut()
            .insert("authorization", secret.parse().unwrap());

        CavageSigner::new(&key, "kid")
            .with_headers(["(request-target)", "host", "date", "authorization"])
            .sign(&mut req)
            .expect("sign");

        let report = verify(&req, |_| Ok(public.clone())).expect("verify");
        let redacted = report.signature_base_redacted(REDACTED_HEADERS_DEFAULT);
        assert!(!redacted.contains(secret), "token must be scrubbed");
        assert!(
            redacted.contains("authorization: <redacted>"),
            "redaction marker must be emitted: {redacted}",
        );
        assert!(
            report.signature_base().contains(secret),
            "non-redacted accessor must still expose the original value",
        );
    }

    #[test]
    fn signature_base_redacted_masks_sensitive_header_values_for_rfc9421() {
        use crate::rfc9421::Component;

        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let secret = "SessionID=opaque";
        let mut req = base_request(b"{}");
        req.headers_mut().insert("cookie", secret.parse().unwrap());

        Rfc9421Signer::new(&key, "kid")
            .with_components(vec![
                Component::Method,
                Component::TargetUri,
                Component::Header("cookie".into()),
            ])
            .sign(&mut req)
            .expect("sign");

        let report = verify(&req, |_| Ok(public.clone())).expect("verify");
        let redacted = report.signature_base_redacted(REDACTED_HEADERS_DEFAULT);
        assert!(!redacted.contains(secret), "cookie must be scrubbed");
        assert!(
            redacted.contains("\"cookie\": <redacted>"),
            "RFC 9421 quoted-name lines must be recognised: {redacted}",
        );
    }

    #[test]
    fn policy_accepts_signature_within_skew_tolerance() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = base_request(b"{}");
        // 1 minute into the future — within the Mastodon 5-minute skew window.
        Rfc9421Signer::new(&key, "kid")
            .with_created(1_700_000_000 + 60)
            .sign(&mut req)
            .expect("sign");

        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid");
        verify_with_policy(&req, &VerifyPolicy::mastodon(), now, |_| Ok(public.clone()))
            .expect("signature within skew tolerance must verify");
    }
}
