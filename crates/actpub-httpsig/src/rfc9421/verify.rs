//! RFC 9421 request verifier.

use chrono::{DateTime, Utc};
use http::Request;

use crate::error::Error;
use crate::key::{Algorithm, VerifyingKey};
use crate::policy::VerifyPolicy;
use crate::rfc9421::components::build_signature_base;
use crate::rfc9421::signature::{SIGNATURE_HEADER, parse_signature_dict};
use crate::rfc9421::signature_input::{
    SIGNATURE_INPUT_HEADER, SignatureInput, parse_signature_input_dict,
};

/// Successful RFC 9421 verification report.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rfc9421Verified {
    /// Label of the signature that matched.
    pub label: String,
    /// Parsed `Signature-Input:` entry for that label.
    pub input: SignatureInput,
    /// Rebuilt signature base string, for audit / logging.
    pub signature_base: String,
}

/// Verifies an RFC 9421-signed request against a key returned by
/// `resolve_key(key_id)`.
///
/// When multiple labels are present, this function picks the **first
/// label whose key the resolver accepts** and returns its report. If the
/// resolver fails for every label the last error is returned.
///
/// # Errors
///
/// Returns [`Error::MissingHeader`] if either header is absent, and
/// [`Error::VerificationFailed`] if no label produces a valid signature.
/// See also [`Error::MalformedSignatureHeader`] and
/// [`Error::KeyResolution`].
pub fn rfc9421_verify<B, F>(req: &Request<B>, resolve_key: F) -> Result<Rfc9421Verified, Error>
where
    F: FnMut(&str) -> Result<VerifyingKey, Error>,
{
    rfc9421_verify_with_policy(
        req,
        &VerifyPolicy::no_freshness_check(),
        Utc::now(),
        resolve_key,
    )
}

/// Verifies an RFC 9421-signed request **with replay-protection**.
///
/// Equivalent to [`rfc9421_verify`] except that `policy` is consulted
/// for every candidate label to reject stale, future-dated or expired
/// timestamps against `now`.
///
/// # Errors
///
/// Same as [`rfc9421_verify`] plus [`Error::TimestampTooOld`],
/// [`Error::TimestampInFuture`], [`Error::TimestampExpired`] and
/// [`Error::TimestampMissing`] when the policy is violated.
pub fn rfc9421_verify_with_policy<B, F>(
    req: &Request<B>,
    policy: &VerifyPolicy,
    now: DateTime<Utc>,
    mut resolve_key: F,
) -> Result<Rfc9421Verified, Error>
where
    F: FnMut(&str) -> Result<VerifyingKey, Error>,
{
    let date_header = req
        .headers()
        .get(http::header::DATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let input_raw = req
        .headers()
        .get(SIGNATURE_INPUT_HEADER)
        .ok_or(Error::MissingHeader(SIGNATURE_INPUT_HEADER))?
        .to_str()
        .map_err(|e| Error::InvalidHeader {
            name: SIGNATURE_INPUT_HEADER,
            reason: e.to_string(),
        })?;
    let sig_raw = req
        .headers()
        .get(SIGNATURE_HEADER)
        .ok_or(Error::MissingHeader(SIGNATURE_HEADER))?
        .to_str()
        .map_err(|e| Error::InvalidHeader {
            name: SIGNATURE_HEADER,
            reason: e.to_string(),
        })?;

    let inputs = parse_signature_input_dict(input_raw)?;
    let sigs = parse_signature_dict(sig_raw)?;

    if inputs.is_empty() {
        return Err(Error::MalformedSignatureHeader(
            "empty Signature-Input dictionary".into(),
        ));
    }

    let mut last_err: Option<Error> = None;
    for (label, input) in inputs {
        let Some((_, sig_bytes)) = sigs.iter().find(|(l, _)| l == &label) else {
            last_err = Some(Error::MalformedSignatureHeader(format!(
                "no Signature entry for label `{label}`"
            )));
            continue;
        };

        // Freshness check on a per-label basis so that one rotated
        // label does not invalidate a sibling signature.
        if let Err(e) = policy.check(input.created, input.expires, date_header.as_deref(), now) {
            last_err = Some(e);
            continue;
        }

        let Some(key_id) = input.keyid.as_deref() else {
            last_err = Some(Error::MissingSignatureParameter("keyid"));
            continue;
        };

        let key = match resolve_key(key_id) {
            Ok(k) => k,
            Err(e) => {
                last_err = Some(Error::KeyResolution(e.to_string()));
                continue;
            }
        };

        if let Some(hint) = input.algorithm.as_deref()
            && let Some(hinted) = parse_alg_hint(hint)?
            && hinted != key.algorithm()
        {
            last_err = Some(Error::VerificationFailed);
            continue;
        }

        let inner_list = input.serialise_inner_list();
        let base = build_signature_base(req, &input.components, &inner_list)?;

        if key.verify(base.as_bytes(), sig_bytes).is_err() {
            last_err = Some(Error::VerificationFailed);
            continue;
        }

        return Ok(Rfc9421Verified {
            label,
            input,
            signature_base: base,
        });
    }

    Err(last_err.unwrap_or(Error::VerificationFailed))
}

fn parse_alg_hint(hint: &str) -> Result<Option<Algorithm>, Error> {
    match hint {
        "rsa-v1_5-sha256" | "rsa-sha256" => Ok(Some(Algorithm::RsaSha256)),
        "ed25519" => Ok(Some(Algorithm::Ed25519)),
        other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::digest::sha256_digest_header;
    use crate::key::{RsaBits, SigningKey};
    use crate::rfc9421::sign::Rfc9421Signer;

    fn signed_request(key: &SigningKey) -> Request<Vec<u8>> {
        let body = b"{}";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", sha256_digest_header(body))
            .body(body.to_vec())
            .expect("valid");
        Rfc9421Signer::new(key, "https://example.com/actor#sig")
            .with_created(1_700_000_000)
            .sign(&mut req)
            .expect("sign");
        req
    }

    #[test]
    fn ed25519_roundtrips_sign_then_verify() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let req = signed_request(&key);

        let report = rfc9421_verify(&req, |kid| {
            assert_eq!(kid, "https://example.com/actor#sig");
            Ok(public.clone())
        })
        .expect("verify");

        assert_eq!(report.label, "sig1");
        assert!(report.signature_base.contains(r#""@method": POST"#));
    }

    #[test]
    fn rsa_sha256_roundtrips_sign_then_verify() {
        let key = SigningKey::generate_rsa(RsaBits::Rsa2048).expect("rng");
        let public = key.verifying_key();
        let req = signed_request(&key);
        rfc9421_verify(&req, |_| Ok(public.clone())).expect("verify");
    }

    #[test]
    fn tampered_date_header_fails_verification() {
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = signed_request(&key);
        req.headers_mut().insert(
            "date",
            "Mon, 06 Jan 2014 00:00:00 GMT".parse().expect("valid"),
        );
        let err =
            rfc9421_verify(&req, |_| Ok(public.clone())).expect_err("tampered date must fail");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn algorithm_mismatch_between_hint_and_key_is_rejected() {
        let key = SigningKey::generate_ed25519();
        // Resolver returns an RSA public key — alg hint `ed25519` won't match.
        let rsa_public = SigningKey::generate_rsa(RsaBits::Rsa2048)
            .expect("rng")
            .verifying_key();
        let req = signed_request(&key);
        let err =
            rfc9421_verify(&req, |_| Ok(rsa_public.clone())).expect_err("mismatched alg must fail");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn missing_input_header_is_reported() {
        let key = SigningKey::generate_ed25519();
        let mut req = signed_request(&key);
        req.headers_mut().remove(SIGNATURE_INPUT_HEADER);
        let err = rfc9421_verify(&req, |_| panic!("resolver must not be called"))
            .expect_err("missing input");
        assert!(matches!(err, Error::MissingHeader(SIGNATURE_INPUT_HEADER)));
    }

    #[test]
    fn missing_signature_header_is_reported() {
        let key = SigningKey::generate_ed25519();
        let mut req = signed_request(&key);
        req.headers_mut().remove(SIGNATURE_HEADER);
        let err = rfc9421_verify(&req, |_| panic!("resolver must not be called"))
            .expect_err("missing signature");
        assert!(matches!(err, Error::MissingHeader(SIGNATURE_HEADER)));
    }
}
