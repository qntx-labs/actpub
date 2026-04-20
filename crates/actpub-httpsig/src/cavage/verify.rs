//! Cavage draft-12 request verifier.

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use http::Request;

use crate::cavage::canonical::{CavageHeaderSet, Timestamps, build_signature_base};
use crate::cavage::header::{CavageHeaderParams, SIGNATURE_HEADER};
use crate::error::Error;
use crate::key::{Algorithm, VerifyingKey};
use crate::policy::VerifyPolicy;

/// Successful verification report.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CavageVerified {
    /// The `keyId=` parameter from the signature header.
    pub key_id: String,
    /// Algorithm hint as it appeared on the wire, if any.
    pub algorithm: Option<String>,
    /// The canonical signature base string that was verified.
    pub signature_base: String,
}

/// Verifies a Cavage-signed request against a key returned by
/// `resolve_key(key_id)`.
///
/// The resolver closure is where the caller performs `WebFinger` lookup, a
/// database fetch or any other means of turning a `keyId` URI into a
/// [`VerifyingKey`]. The closure fails whenever the key cannot be found
/// or the caller wants to reject the actor for policy reasons.
///
/// # Errors
///
/// Returns [`Error::MissingHeader`] if the request lacks a `Signature:`
/// header; [`Error::MalformedSignatureHeader`] /
/// [`Error::MissingSignatureParameter`] if the header is unparseable;
/// [`Error::KeyResolution`] if the resolver fails; and
/// [`Error::VerificationFailed`] if the signature does not match.
pub fn cavage_verify<B, F>(req: &Request<B>, resolve_key: F) -> Result<CavageVerified, Error>
where
    F: FnOnce(&str) -> Result<VerifyingKey, Error>,
{
    cavage_verify_with_policy(
        req,
        &VerifyPolicy::no_freshness_check(),
        Utc::now(),
        resolve_key,
    )
}

/// Verifies a Cavage-signed request **with replay-protection**.
///
/// Equivalent to [`cavage_verify`] except that `policy` is consulted to
/// reject stale, future-dated or expired timestamps against `now`. Most
/// production callers should use this form with
/// [`VerifyPolicy::mastodon`] (or their own tuning) and `Utc::now()`.
///
/// # Errors
///
/// Same as [`cavage_verify`] plus [`Error::TimestampTooOld`],
/// [`Error::TimestampInFuture`], [`Error::TimestampExpired`] and
/// [`Error::TimestampMissing`] when the policy is violated.
pub fn cavage_verify_with_policy<B, F>(
    req: &Request<B>,
    policy: &VerifyPolicy,
    now: DateTime<Utc>,
    resolve_key: F,
) -> Result<CavageVerified, Error>
where
    F: FnOnce(&str) -> Result<VerifyingKey, Error>,
{
    let header = req
        .headers()
        .get(SIGNATURE_HEADER)
        .ok_or(Error::MissingHeader(SIGNATURE_HEADER))?;
    let raw = header.to_str().map_err(|e| Error::InvalidHeader {
        name: SIGNATURE_HEADER,
        reason: e.to_string(),
    })?;

    let params = CavageHeaderParams::parse(raw)?;

    // Enforce the required Cavage header set *before* any crypto
    // work: a signature that omits `(request-target)` or `host` can be
    // replayed verbatim against different paths or virtual hosts, so
    // we reject it at the cheapest possible layer.
    enforce_required_headers(&params.headers, policy.cavage_required_headers)?;

    // Freshness check runs *before* the cryptographic verification so
    // that replayed or expired signatures are rejected without taking a
    // cryptographic-work timing hit.
    let date_header = req
        .headers()
        .get(http::header::DATE)
        .and_then(|v| v.to_str().ok());
    policy.check(params.created, params.expires, date_header, now)?;

    let key = resolve_key(&params.key_id).map_err(|e| Error::KeyResolution(e.to_string()))?;

    // Cross-check algorithm hint when supplied.
    if let Some(hint) = params.algorithm.as_deref()
        && let Some(hinted) = Algorithm::parse(hint)?
        && hinted != key.algorithm()
    {
        return Err(Error::VerificationFailed);
    }

    let base = build_signature_base(
        req,
        &params.headers,
        Timestamps {
            created: params.created,
            expires: params.expires,
        },
    )?;

    let mut sig_bytes = vec![0u8; params.signature.len()];
    let sig = Base64::decode(&params.signature, &mut sig_bytes)?;
    key.verify(base.as_bytes(), sig)?;

    Ok(CavageVerified {
        key_id: params.key_id,
        algorithm: params.algorithm,
        signature_base: base,
    })
}

/// Rejects the signature when `signed` is missing any name in
/// `required`. Names are matched case-insensitively, mirroring how HTTP
/// headers themselves are handled throughout this crate.
fn enforce_required_headers(signed: &CavageHeaderSet, required: &[&str]) -> Result<(), Error> {
    for needed in required {
        let present = signed.iter().any(|h| h.eq_ignore_ascii_case(needed));
        if !present {
            return Err(Error::RequiredHeaderAbsent((*needed).to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::cavage::sign::CavageSigner;
    use crate::digest::sha256_digest_header;
    use crate::key::{RsaBits, SigningKey};

    fn sample_signed_request(key: &SigningKey, body: &[u8]) -> Request<Vec<u8>> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", sha256_digest_header(body))
            .header("content-type", "application/activity+json")
            .body(body.to_vec())
            .expect("valid");
        CavageSigner::new(key, "https://example.com/actors/alice#main-key")
            .sign(&mut req)
            .expect("sign");
        req
    }

    #[test]
    fn ed25519_signature_roundtrips_sign_then_verify() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let req = sample_signed_request(&key, b"{}");

        let report = cavage_verify(&req, |kid| {
            assert_eq!(kid, "https://example.com/actors/alice#main-key");
            Ok(public.clone())
        })
        .expect("verify must succeed");

        assert_eq!(report.key_id, "https://example.com/actors/alice#main-key");
        assert!(
            report
                .signature_base
                .contains("(request-target): post /inbox?a=1")
        );
    }

    #[test]
    fn rsa_sha256_signature_roundtrips_sign_then_verify() {
        let key = SigningKey::generate_rsa(RsaBits::Rsa2048).expect("rng");
        let public = key.verifying_key();
        let req = sample_signed_request(&key, b"{}");
        cavage_verify(&req, |_| Ok(public.clone())).expect("verify must succeed");
    }

    #[test]
    fn tampered_body_fails_verification_via_digest_loop() {
        // When the body changes the `Digest:` header embedded in the
        // signature base still reflects the original body, so the
        // signature verifies. The purpose of digest is to let a caller
        // who *also* re-hashes the body detect tampering; verifying only
        // the signature is insufficient. This test documents that
        // behaviour: we expect the signature to still verify here.
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = sample_signed_request(&key, b"original");
        *req.body_mut() = b"tampered".to_vec();
        cavage_verify(&req, |_| Ok(public.clone()))
            .expect("signature alone does not depend on body bytes");
    }

    #[test]
    fn tampered_date_header_fails_verification() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = sample_signed_request(&key, b"{}");
        req.headers_mut().insert(
            "date",
            "Mon, 06 Jan 2014 00:00:00 GMT".parse().expect("valid"),
        );
        let err = cavage_verify(&req, |_| Ok(public.clone())).expect_err("tampered date must fail");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn missing_signature_header_is_reported() {
        let req: Request<Vec<u8>> = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .body(Vec::new())
            .unwrap();
        let err = cavage_verify(&req, |_| panic!("resolver must not be called"))
            .expect_err("missing Signature header");
        assert!(matches!(err, Error::MissingHeader("signature")));
    }

    #[test]
    fn key_resolver_error_is_surfaced() {
        let key = SigningKey::generate_ed25519();
        let req = sample_signed_request(&key, b"{}");
        let err =
            cavage_verify(&req, |_| Err(Error::VerificationFailed)).expect_err("resolver failed");
        assert!(matches!(err, Error::KeyResolution(_)));
    }

    #[test]
    fn signature_missing_required_host_header_is_rejected() {
        // The attacker supplies a valid signature that omits `host`
        // from the covered header set. A replay against a different
        // virtual host would succeed without this guard.
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = sample_signed_request(&key, b"{}");
        // Re-sign covering only (request-target) and date — no host.
        CavageSigner::new(&key, "https://example.com/actors/alice#main-key")
            .with_headers(["(request-target)", "date"])
            .sign(&mut req)
            .expect("sign");

        let err = cavage_verify(&req, |_| Ok(public.clone()))
            .expect_err("signature without `host` must be rejected");
        assert!(matches!(err, Error::RequiredHeaderAbsent(name) if name == "host"));
    }

    #[test]
    fn signature_missing_required_request_target_is_rejected() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = sample_signed_request(&key, b"{}");
        CavageSigner::new(&key, "kid")
            .with_headers(["host", "date"])
            .sign(&mut req)
            .expect("sign");

        let err = cavage_verify(&req, |_| Ok(public.clone()))
            .expect_err("signature without `(request-target)` must be rejected");
        assert!(matches!(err, Error::RequiredHeaderAbsent(name) if name == "(request-target)"));
    }

    #[test]
    fn algorithm_mismatch_between_hint_and_key_rejects() {
        // Sign with Ed25519 but claim rsa-sha256 in the header.
        let key = SigningKey::generate_ed25519();
        let public_rsa = SigningKey::generate_rsa(RsaBits::Rsa2048)
            .expect("rng")
            .verifying_key();
        let mut req = sample_signed_request(&key, b"{}");
        let original_header = req
            .headers()
            .get(SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .replace(r#"algorithm="ed25519""#, r#"algorithm="rsa-sha256""#);
        req.headers_mut()
            .insert(SIGNATURE_HEADER, original_header.parse().unwrap());

        let err = cavage_verify(&req, |_| Ok(public_rsa.clone()))
            .expect_err("algorithm mismatch must fail");
        assert!(matches!(err, Error::VerificationFailed));
    }
}
