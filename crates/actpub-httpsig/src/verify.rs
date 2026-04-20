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
    #[must_use]
    pub fn signature_base(&self) -> &str {
        match self {
            Self::Cavage(c) => &c.signature_base,
            Self::Rfc9421(r) => &r.signature_base,
        }
    }
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
    use crate::digest::sha256_digest_header;
    use crate::key::SigningKey;
    use crate::rfc9421::Rfc9421Signer;

    fn base_request(body: &[u8]) -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", sha256_digest_header(body))
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
}
