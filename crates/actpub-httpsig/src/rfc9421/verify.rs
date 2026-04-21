//! RFC 9421 request verifier.

use chrono::{DateTime, Utc};
use http::Request;

use crate::error::Error;
use crate::key::{Algorithm, VerifyingKey};
use crate::policy::VerifyPolicy;
use crate::rfc9421::components::{Component, build_signature_base};
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

    if !policy.allow_multiple_signatures && inputs.len() > 1 {
        return Err(Error::MalformedSignatureHeader(format!(
            "Signature-Input carries {} labels but policy allows only one",
            inputs.len()
        )));
    }

    let mut last_err: Option<Error> = None;
    for (label, input) in inputs {
        let Some((_, sig_bytes)) = sigs.iter().find(|(l, _)| l == &label) else {
            last_err = Some(Error::MalformedSignatureHeader(format!(
                "no Signature entry for label `{label}`"
            )));
            continue;
        };

        // Cheapest-possible replay guard: reject signatures whose
        // covered-component set omits any identifier in
        // `policy.rfc9421_required_components` before any crypto
        // work runs. A signature that does not cover `@method` /
        // `@target-uri` / `content-digest` can be replayed against
        // a different path, method, or body.
        if let Err(e) =
            enforce_required_components(&input.components, policy.rfc9421_required_components)
        {
            last_err = Some(e);
            continue;
        }

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

        if let Some(hint) = input.algorithm.as_deref() {
            match parse_alg_hint(hint) {
                Ok(Some(hinted)) if hinted != key.algorithm() => {
                    last_err = Some(Error::VerificationFailed);
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
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

/// Parses the RFC 9421 `alg` signature parameter using the same
/// canonical table as the rest of the crate.
///
/// Previously this had its own ad-hoc match that rejected `hs2019`
/// as unsupported; that bypassed [`Algorithm::parse`], which
/// correctly maps `hs2019` to `Ok(None)` (i.e. "derive algorithm
/// from the key, no hint"). The old behaviour broke interop with
/// any Fediverse peer still emitting Mastodon's legacy `hs2019`
/// label and was a maintenance hazard: adding e.g. RSA-PSS to the
/// canonical parser required touching two places.
fn parse_alg_hint(hint: &str) -> Result<Option<Algorithm>, Error> {
    Algorithm::parse(hint)
}

/// Rejects the signature when `signed` is missing any identifier in
/// `required`. Identifiers are matched case-insensitively against
/// [`Component::identifier`], so a policy entry `"content-digest"`
/// matches any casing the signer emitted.
fn enforce_required_components(signed: &[Component], required: &[&str]) -> Result<(), Error> {
    for needed in required {
        let present = signed
            .iter()
            .any(|c| c.identifier().eq_ignore_ascii_case(needed));
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
    use crate::content_digest::content_digest_header;
    use crate::key::{RsaBits, SigningKey};
    use crate::rfc9421::sign::Rfc9421Signer;

    fn signed_request(key: &SigningKey) -> Request<Vec<u8>> {
        let body = b"{}";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("content-digest", content_digest_header(body))
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
    fn parse_alg_hint_accepts_legacy_hs2019_as_key_derived() {
        // P0-N3 (sixth-round audit) regression: the old ad-hoc
        // `parse_alg_hint` implementation hard-errored on every
        // algorithm name outside {rsa-sha256, rsa-v1_5-sha256,
        // ed25519}, including Mastodon's legacy `hs2019` label —
        // which per RFC 9421 §3.1 means "derive algorithm from
        // the key, no hint". The new implementation delegates to
        // the canonical `Algorithm::parse` so `hs2019` returns
        // `Ok(None)` and the verifier falls through to the
        // key-derived algorithm as the RFC requires.
        assert_eq!(
            parse_alg_hint("hs2019").expect("hs2019 must be accepted"),
            None
        );
        // And the canonical names still parse as specific algos.
        assert_eq!(
            parse_alg_hint("rsa-v1_5-sha256").expect("parse"),
            Some(Algorithm::RsaSha256),
        );
        assert_eq!(
            parse_alg_hint("ed25519").expect("parse"),
            Some(Algorithm::Ed25519),
        );
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

    #[test]
    fn multi_label_signature_input_is_rejected_by_default() {
        // Mastodon and the RFC 9421 interop profile both expect a
        // single label; attaching a second one opens a fallback an
        // attacker can exploit to bypass policy.
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = signed_request(&key);
        // Append a second, empty inner list to produce `sig1=(...), attacker=()`.
        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
            + r", attacker=()";
        req.headers_mut()
            .insert(SIGNATURE_INPUT_HEADER, input_raw.parse().unwrap());

        let err = rfc9421_verify(&req, |_| Ok(public.clone()))
            .expect_err("multiple labels must be rejected");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }

    #[test]
    fn multi_label_signature_input_is_accepted_when_policy_allows_it() {
        // Interop escape hatch: some research / middle-box setups do
        // attach multiple signatures. Flipping the policy knob must
        // restore the historical tolerant behaviour.
        use chrono::DateTime;

        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = signed_request(&key);
        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
            + r", attacker=()";
        req.headers_mut()
            .insert(SIGNATURE_INPUT_HEADER, input_raw.parse().unwrap());

        let policy = VerifyPolicy {
            allow_multiple_signatures: true,
            ..VerifyPolicy::no_freshness_check()
        };
        rfc9421_verify_with_policy(
            &req,
            &policy,
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            |_| Ok(public.clone()),
        )
        .expect("the valid sig1 label must still verify");
    }

    #[test]
    fn mastodon_policy_rejects_signature_without_target_uri_component() {
        // A signature covering `@method` + `content-digest` but not
        // `@target-uri` can be replayed verbatim against a different
        // path on the same server; the policy MUST cut it off before
        // any crypto work runs.
        use chrono::DateTime;

        use crate::rfc9421::Component;

        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let body = b"{}";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("content-digest", content_digest_header(body))
            .body(body.to_vec())
            .expect("valid");
        Rfc9421Signer::new(&key, "kid")
            .with_components(vec![
                Component::Method,
                Component::Header("content-digest".into()),
            ])
            .with_created(1_700_000_000)
            .sign(&mut req)
            .expect("sign");

        let err = rfc9421_verify_with_policy(
            &req,
            &VerifyPolicy::mastodon(),
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            |_| Ok(public.clone()),
        )
        .expect_err("missing `@target-uri` must be rejected by the Mastodon policy");
        assert!(
            matches!(&err, Error::RequiredHeaderAbsent(name) if name == "@target-uri"),
            "unexpected error variant: {err:?}",
        );
    }

    #[test]
    fn mastodon_policy_rejects_signature_without_content_digest_component() {
        // Same shape as the previous test but the covered set now
        // omits `content-digest`: an intermediary could replay the
        // signed `@method` + `@target-uri` against a different body.
        use chrono::DateTime;

        use crate::rfc9421::Component;

        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let body = b"{}";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("content-digest", content_digest_header(body))
            .body(body.to_vec())
            .expect("valid");
        Rfc9421Signer::new(&key, "kid")
            .with_components(vec![Component::Method, Component::TargetUri])
            .with_created(1_700_000_000)
            .sign(&mut req)
            .expect("sign");

        let err = rfc9421_verify_with_policy(
            &req,
            &VerifyPolicy::mastodon(),
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            |_| Ok(public.clone()),
        )
        .expect_err("missing `content-digest` must be rejected");
        assert!(
            matches!(&err, Error::RequiredHeaderAbsent(name) if name == "content-digest"),
            "unexpected: {err:?}",
        );
    }

    #[test]
    fn no_freshness_check_policy_tolerates_minimal_covered_components() {
        // Byte-level conformance tests against static RFC 9421
        // fixtures may exercise sparse inner lists; the
        // freshness-disabled preset MUST also disable the
        // required-components gate so those fixtures still verify.
        use crate::rfc9421::Component;

        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let body = b"{}";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .body(body.to_vec())
            .expect("valid");
        Rfc9421Signer::new(&key, "kid")
            .with_components(vec![Component::Method])
            .sign(&mut req)
            .expect("sign");

        rfc9421_verify(&req, |_| Ok(public.clone()))
            .expect("no_freshness_check preset must not enforce required components");
    }

    #[test]
    fn unknown_alg_hint_does_not_short_circuit_multi_label_verification() {
        // Regression for the `?` short-circuit bug: when an earlier
        // label carries an unrecognised `alg=` parameter the verifier
        // must skip it and keep trying later labels, not abort the
        // entire function.
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = signed_request(&key);

        // Tamper the produced Signature-Input header to claim an
        // unknown algorithm for the single present label. The
        // resolver still returns a valid key; prior to the fix the
        // `?` on `parse_alg_hint` bubbled `UnsupportedAlgorithm` out
        // of the function.
        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .replace(r#"alg="ed25519""#, r#"alg="bogus-alg""#);
        req.headers_mut()
            .insert(SIGNATURE_INPUT_HEADER, input_raw.parse().unwrap());

        let err = rfc9421_verify(&req, |_| Ok(public.clone()))
            .expect_err("unknown alg hint must surface as the last recorded error");
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)));
    }
}
