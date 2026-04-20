//! [FEP-8b32] / [W3C VC-DI EdDSA] `eddsa-jcs-2022` cryptosuite.
//!
//! This is the cryptosuite Mitra, Takahē and Mastodon 4.5+ use to bind
//! end-to-end integrity proofs to `ActivityPub` objects, replacing the
//! legacy hop-by-hop HTTP signature for object-level verification.
//!
//! # Algorithm
//!
//! Per [W3C VC-DI EdDSA Cryptosuites v1.0 §3.1.4]:
//!
//! ```text
//! hashData = SHA-256(JCS(canonicalProofConfig)) || SHA-256(JCS(transformedDocument))
//! signature = Ed25519.Sign(signingKey, hashData)
//! proofValue = "z" || base58btc(signature)
//! ```
//!
//! Where:
//!
//! - `canonicalProofConfig` is the proof object **without** the
//!   `proofValue` member, but **with** the `@context` inherited from
//!   the unsigned document (FEP-8b32 §4.5).
//! - `transformedDocument` is the unsigned document — i.e. the signed
//!   document with its `proof` member removed.
//!
//! Verification reverses these steps and checks that
//! `Ed25519.Verify(publicKey, hashData, signature)` succeeds.
//!
//! [FEP-8b32]: https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md
//! [W3C VC-DI EdDSA]: https://www.w3.org/TR/vc-di-eddsa/
//! [W3C VC-DI EdDSA Cryptosuites v1.0 §3.1.4]: https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022

use actpub_httpsig::{Ed25519PublicKey, Ed25519SigningKey};
use aws_lc_rs::digest::{self, SHA256};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use multibase::Base;
use serde_json::Value;
use url::Url;

use crate::error::Error;
use crate::jcs;

/// IANA-registered cryptosuite identifier mandated by FEP-8b32 §3.1
/// for Fediverse-compatible Data Integrity proofs.
pub const CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// `type` value mandated by FEP-8b32 §3 for every Data Integrity
/// proof, regardless of cryptosuite.
pub const PROOF_TYPE: &str = "DataIntegrityProof";

/// `proofPurpose` value mandated for assertions about the signed
/// document's content (the overwhelmingly common case for
/// `ActivityPub`).
pub const PROOF_PURPOSE_ASSERTION: &str = "assertionMethod";

/// Caller-supplied parameters that configure a new
/// [`sign`](sign) operation.
///
/// The signer always populates the `type`, `cryptosuite` and
/// `proofValue` members of the resulting proof; the fields below
/// determine everything else.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProofOptions {
    /// URL identifying the public key the signature can be verified
    /// against. Typically `<actor URL>#<key fragment>`.
    pub verification_method: Url,
    /// Purpose of the proof; almost always
    /// [`PROOF_PURPOSE_ASSERTION`].
    pub proof_purpose: String,
    /// Wall-clock time of signing. The wire format truncates this to
    /// second precision per FEP-8b32 conventions.
    pub created: DateTime<Utc>,
    /// Optional challenge string supplied by a relying party for
    /// challenge–response authentication. Omitted from the proof when
    /// `None`.
    pub challenge: Option<String>,
    /// Optional domain anchor for the proof, used by
    /// challenge-response auth flows. Omitted from the proof when
    /// `None`.
    pub domain: Option<String>,
}

impl ProofOptions {
    /// Convenience constructor for the overwhelming majority case:
    /// an `assertionMethod` proof with the current wall-clock time and
    /// no challenge or domain.
    #[must_use]
    pub fn assertion(verification_method: Url) -> Self {
        Self {
            verification_method,
            proof_purpose: PROOF_PURPOSE_ASSERTION.to_owned(),
            created: Utc::now(),
            challenge: None,
            domain: None,
        }
    }
}

/// Signs `unsigned_document` under the `eddsa-jcs-2022` cryptosuite
/// and returns the document with its `proof` member populated.
///
/// `unsigned_document` MUST be a JSON object. Any pre-existing `proof`
/// member is silently replaced — to attach **multiple** proofs to a
/// single document, sign once, then take the result and call this
/// function again (the second proof will be computed over a document
/// that already carries the first).
///
/// # Errors
///
/// Returns [`Error::NotAnObject`] if `unsigned_document` is not a JSON
/// object, or [`Error::Canonicalisation`] if JCS rejects either the
/// proof config or the unsigned document.
pub fn sign(
    unsigned_document: &Value,
    options: &ProofOptions,
    signing_key: &Ed25519SigningKey,
) -> Result<Value, Error> {
    if !unsigned_document.is_object() {
        return Err(Error::NotAnObject);
    }

    let proof_config = build_proof_config(unsigned_document, options);
    let transformed = strip_proof(unsigned_document.clone());

    let hash_data = compute_hash_data(&proof_config, &transformed)?;
    let raw_signature = signing_key.sign(&hash_data);
    let proof_value = multibase::encode(Base::Base58Btc, raw_signature);

    let mut final_proof = proof_config;
    if let Value::Object(map) = &mut final_proof {
        map.insert("proofValue".to_owned(), Value::String(proof_value));
    }

    let mut signed = unsigned_document.clone();
    if let Value::Object(map) = &mut signed {
        map.insert("proof".to_owned(), final_proof);
    }
    Ok(signed)
}

/// Default maximum age of a Data Integrity proof accepted by
/// [`VerifyOptions`]: 24 hours. Mirrors the Mastodon 4.5 / Mitra
/// convention that a Fediverse proof older than one day is stale.
pub const DEFAULT_PROOF_MAX_AGE: Duration = Duration::hours(24);

/// Default clock-skew tolerance on the future side: 5 minutes. Matches
/// Mastodon's HTTP-Signature policy.
pub const DEFAULT_PROOF_MAX_CLOCK_SKEW_FUTURE: Duration = Duration::minutes(5);

/// Caller-supplied constraints that [`verify`] applies to every
/// Data Integrity proof.
///
/// Every field is mandatory because every field participates in the
/// FEP-8b32 threat model: omitting `expected_verification_method`
/// admits key-confusion attacks, omitting `expected_proof_purpose`
/// admits purpose-laundering, and omitting the timestamp window
/// leaves a captured proof valid forever.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifyOptions<'a> {
    /// The full URL the caller has decided the signing key is
    /// identified by (typically `<actor URL>#<key fragment>`).
    /// [`verify`] rejects any proof whose
    /// `verificationMethod` string is not byte-for-byte equal to
    /// this URL — ensuring the caller has itself fetched the actor
    /// and cross-checked that the named key actually belongs there.
    pub expected_verification_method: &'a Url,
    /// The purpose the caller is willing to accept. Pass
    /// [`PROOF_PURPOSE_ASSERTION`] for content assertions (the
    /// overwhelmingly common case); pass `"authentication"` when
    /// consuming a challenge–response proof.
    pub expected_proof_purpose: &'a str,
    /// Instant the verifier is treating as "now". Injected instead
    /// of read from the clock so integration tests can pin
    /// determinism.
    pub now: DateTime<Utc>,
    /// Reject proofs whose `created` is more than `max_age` older
    /// than `now`. `None` disables the past-side check — use only
    /// for static conformance fixtures.
    pub max_age: Option<Duration>,
    /// Reject proofs whose `created` is more than
    /// `max_clock_skew_future` ahead of `now`. `None` disables the
    /// future-side check.
    pub max_clock_skew_future: Option<Duration>,
}

impl<'a> VerifyOptions<'a> {
    /// Options for the overwhelmingly common case: an
    /// `assertionMethod` proof, with the Mastodon-equivalent 24 h
    /// past / 5 min future window.
    #[must_use]
    pub const fn assertion(expected_verification_method: &'a Url, now: DateTime<Utc>) -> Self {
        Self {
            expected_verification_method,
            expected_proof_purpose: PROOF_PURPOSE_ASSERTION,
            now,
            max_age: Some(DEFAULT_PROOF_MAX_AGE),
            max_clock_skew_future: Some(DEFAULT_PROOF_MAX_CLOCK_SKEW_FUTURE),
        }
    }
}

/// Full FEP-8b32 verification for `signed_document.proof`.
///
/// Proves that the proof is an authentic `eddsa-jcs-2022` Data
/// Integrity signature produced by the holder of `verifying_key`,
/// **and** that every FEP-8b32 mandatory field binds the proof to
/// the exact caller context described by `options`.
///
/// Specifically, this function rejects:
///
/// - documents whose `proof.type` is not `DataIntegrityProof`;
/// - proofs whose `cryptosuite` is not `eddsa-jcs-2022`;
/// - proofs whose `verificationMethod` does not match
///   [`VerifyOptions::expected_verification_method`] (key confusion);
/// - proofs whose `proofPurpose` does not match
///   [`VerifyOptions::expected_proof_purpose`] (purpose laundering);
/// - proofs whose `created` timestamp is missing, malformed, older
///   than `max_age`, or more than `max_clock_skew_future` in the
///   future;
/// - proofs whose cryptographic signature does not validate against
///   `verifying_key` over the canonical hash data.
///
/// # Errors
///
/// Returns [`Error::MissingProof`], [`Error::UnsupportedProofType`],
/// [`Error::UnsupportedCryptosuite`], [`Error::InvalidProofValue`],
/// [`Error::InvalidProofField`], [`Error::VerificationMethodMismatch`],
/// [`Error::ProofPurposeMismatch`], [`Error::ProofTimestampTooOld`],
/// [`Error::ProofTimestampInFuture`], [`Error::Canonicalisation`], or
/// [`Error::SignatureMismatch`].
pub fn verify(
    signed_document: &Value,
    verifying_key: &Ed25519PublicKey,
    options: &VerifyOptions<'_>,
) -> Result<(), Error> {
    let proof_node = signed_document.get("proof").ok_or(Error::MissingProof)?;
    match proof_node {
        Value::Object(_) => {
            verify_single_proof(signed_document, proof_node, verifying_key, options)
        }
        Value::Array(chain) => {
            // FEP-8b32 / W3C VC-DI §4.2 proof sets: every proof in
            // the array must validate against the same document
            // under the caller's constraints. Missing / mixed-shape
            // entries are rejected so a silently-dropped bogus
            // proof cannot hide behind a single valid sibling.
            if chain.is_empty() {
                return Err(Error::InvalidProofField {
                    field: "proof",
                    reason: "proof chain is empty".to_owned(),
                });
            }
            for entry in chain {
                if !entry.is_object() {
                    return Err(Error::InvalidProofField {
                        field: "proof",
                        reason: "proof chain entries must be objects".to_owned(),
                    });
                }
                verify_single_proof(signed_document, entry, verifying_key, options)?;
            }
            Ok(())
        }
        _ => Err(Error::InvalidProofField {
            field: "proof",
            reason: "must be an object or an array of objects".to_owned(),
        }),
    }
}

/// Verifies ONE proof block against the document under
/// `options`. Factored out so [`verify`] can loop over a FEP-8b32
/// proof chain without duplicating the binding / hash / signature
/// pipeline.
fn verify_single_proof(
    signed_document: &Value,
    proof: &Value,
    verifying_key: &Ed25519PublicKey,
    options: &VerifyOptions<'_>,
) -> Result<(), Error> {
    let raw_signature = decode_proof_value(proof)?;

    check_proof_header(proof)?;
    check_verification_method(proof, options.expected_verification_method)?;
    check_proof_purpose(proof, options.expected_proof_purpose)?;
    check_created_timestamp(
        proof,
        options.now,
        options.max_age,
        options.max_clock_skew_future,
    )?;

    let proof_config = strip_proof_value(proof.clone());
    let transformed = strip_proof(signed_document.clone());
    let hash_data = compute_hash_data(&proof_config, &transformed)?;

    verifying_key
        .verify(&hash_data, &raw_signature)
        .map_err(|_| Error::SignatureMismatch)
}

/// Like [`verify`] but resolves the public key from a
/// FEP-521a [`Multikey`](actpub_activitystreams::Multikey) block.
///
/// This is the convenient form for inbox handlers that have already
/// fetched the signing actor and want to verify against one of the
/// actor's `assertionMethod` keys. All [`VerifyOptions`] constraints
/// are enforced exactly as by [`verify`].
///
/// # Errors
///
/// Same as [`verify`], plus [`Error::InvalidMultikey`] when the
/// multibase-encoded key cannot be decoded as Ed25519.
pub fn verify_with_multikey(
    signed_document: &Value,
    multikey: &actpub_activitystreams::Multikey,
    options: &VerifyOptions<'_>,
) -> Result<(), Error> {
    let decoded = actpub_httpsig::Multikey::decode(&multikey.public_key_multibase)
        .map_err(|e| Error::InvalidMultikey(e.to_string()))?;
    verify(signed_document, &decoded.key, options)
}

fn check_verification_method(proof: &Value, expected: &Url) -> Result<(), Error> {
    let found = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidProofField {
            field: "verificationMethod",
            reason: "missing or non-string".to_owned(),
        })?;
    if found != expected.as_str() {
        return Err(Error::VerificationMethodMismatch {
            expected: expected.to_string(),
            found: found.to_owned(),
        });
    }
    Ok(())
}

fn check_proof_purpose(proof: &Value, expected: &str) -> Result<(), Error> {
    let found = proof
        .get("proofPurpose")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidProofField {
            field: "proofPurpose",
            reason: "missing or non-string".to_owned(),
        })?;
    if found != expected {
        return Err(Error::ProofPurposeMismatch {
            expected: expected.to_owned(),
            found: found.to_owned(),
        });
    }
    Ok(())
}

fn check_created_timestamp(
    proof: &Value,
    now: DateTime<Utc>,
    max_age: Option<Duration>,
    max_skew_future: Option<Duration>,
) -> Result<(), Error> {
    let raw = proof
        .get("created")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidProofField {
            field: "created",
            reason: "missing or non-string".to_owned(),
        })?;
    let created = parse_created_timestamp(raw)?;

    if let Some(skew) = max_skew_future
        && created > now + skew
    {
        return Err(Error::ProofTimestampInFuture { created, now });
    }
    if let Some(max_age) = max_age
        && now.signed_duration_since(created) > max_age
    {
        return Err(Error::ProofTimestampTooOld { created, now });
    }
    Ok(())
}

/// Parses a FEP-8b32 `created` timestamp.
///
/// FEP-8b32 defers to `xsd:dateTime`, whose lexical space **allows
/// timezone to be omitted** (unqualified instants are treated as
/// local to the publisher). The W3C VC-DI cryptosuite adds a
/// preference for RFC 3339 / ISO 8601 with a trailing `Z`, and our
/// signer emits that form. Interop forces us to parse both:
///
/// 1. **RFC 3339** (`2026-04-20T10:00:00Z`, `…+00:00`): the cryptosuite
///    canonical form — tried first and accepted as-is.
/// 2. **XSD `dateTime` with no timezone** (`2026-04-20T10:00:00`,
///    optionally with fractional seconds): interpreted as UTC so
///    the downstream freshness window has a deterministic anchor,
///    matching `Fedify` / `SpaceBar`'s historical behaviour.
///
/// Any other shape is rejected with a descriptive error so a peer
/// sending a timezone-free local timestamp does not silently slip
/// past the freshness gate under an incorrect offset assumption.
fn parse_created_timestamp(raw: &str) -> Result<DateTime<Utc>, Error> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        return Ok(parsed.with_timezone(&Utc));
    }
    for fmt in &["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, fmt) {
            return Ok(naive.and_utc());
        }
    }
    Err(Error::InvalidProofField {
        field: "created",
        reason: format!(
            "`{raw}` is neither an RFC 3339 timestamp nor a timezone-less \
             XSD dateTime"
        ),
    })
}

fn build_proof_config(unsigned_document: &Value, options: &ProofOptions) -> Value {
    let created = options.created.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut map = serde_json::Map::with_capacity(8);
    map.insert("type".to_owned(), Value::String(PROOF_TYPE.to_owned()));
    map.insert(
        "cryptosuite".to_owned(),
        Value::String(CRYPTOSUITE.to_owned()),
    );
    map.insert(
        "verificationMethod".to_owned(),
        Value::String(options.verification_method.to_string()),
    );
    map.insert(
        "proofPurpose".to_owned(),
        Value::String(options.proof_purpose.clone()),
    );
    map.insert("created".to_owned(), Value::String(created));
    if let Some(challenge) = &options.challenge {
        map.insert("challenge".to_owned(), Value::String(challenge.clone()));
    }
    if let Some(domain) = &options.domain {
        map.insert("domain".to_owned(), Value::String(domain.clone()));
    }
    if let Some(ctx) = unsigned_document.get("@context") {
        map.insert("@context".to_owned(), ctx.clone());
    }
    Value::Object(map)
}

fn strip_proof(mut document: Value) -> Value {
    if let Value::Object(map) = &mut document {
        map.remove("proof");
    }
    document
}

fn strip_proof_value(mut proof: Value) -> Value {
    if let Value::Object(map) = &mut proof {
        map.remove("proofValue");
    }
    proof
}

fn compute_hash_data(proof_config: &Value, transformed: &Value) -> Result<[u8; 64], Error> {
    let proof_canonical = jcs::canonicalize(proof_config)?;
    let doc_canonical = jcs::canonicalize(transformed)?;
    let proof_hash = digest::digest(&SHA256, &proof_canonical);
    let doc_hash = digest::digest(&SHA256, &doc_canonical);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(proof_hash.as_ref());
    out[32..].copy_from_slice(doc_hash.as_ref());
    Ok(out)
}

fn check_proof_header(proof: &Value) -> Result<(), Error> {
    let type_ =
        proof
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidProofField {
                field: "type",
                reason: "missing or non-string".to_owned(),
            })?;
    if type_ != PROOF_TYPE {
        return Err(Error::UnsupportedProofType(type_.to_owned()));
    }
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidProofField {
            field: "cryptosuite",
            reason: "missing or non-string".to_owned(),
        })?;
    if cryptosuite != CRYPTOSUITE {
        return Err(Error::UnsupportedCryptosuite(cryptosuite.to_owned()));
    }
    Ok(())
}

fn decode_proof_value(proof: &Value) -> Result<[u8; 64], Error> {
    let pv = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidProofValue("missing or non-string".to_owned()))?;
    let (_base, bytes) =
        multibase::decode(pv).map_err(|e| Error::InvalidProofValue(format!("multibase: {e}")))?;
    if bytes.len() != 64 {
        return Err(Error::InvalidProofValue(format!(
            "Ed25519 signatures are 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use actpub_httpsig::Ed25519SigningKey;
    use chrono::TimeZone as _;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    fn fixed_options() -> ProofOptions {
        ProofOptions {
            verification_method: fixed_vm(),
            proof_purpose: PROOF_PURPOSE_ASSERTION.to_owned(),
            created: Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap(),
            challenge: None,
            domain: None,
        }
    }

    fn fixed_vm() -> Url {
        "https://example.com/users/alice#ed25519-key"
            .parse()
            .unwrap()
    }

    /// Static verification options tied to [`fixed_options`]'s
    /// fixed instant — freshness checks disabled so the suite is
    /// time-invariant.
    fn test_opts(vm: &Url) -> VerifyOptions<'_> {
        VerifyOptions {
            expected_verification_method: vm,
            expected_proof_purpose: PROOF_PURPOSE_ASSERTION,
            now: Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap(),
            max_age: None,
            max_clock_skew_future: None,
        }
    }

    fn sample_create() -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v2"
            ],
            "id": "https://example.com/activities/01HQ4N7G",
            "type": "Create",
            "actor": "https://example.com/users/alice",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "object": {
                "id": "https://example.com/notes/01HQ4N7H",
                "type": "Note",
                "content": "<p>hi signed Fediverse</p>"
            }
        })
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let vm = fixed_vm();
        verify(&signed, &key.public_key(), &test_opts(&vm)).expect("self-verify must succeed");
    }

    #[test]
    fn signed_document_attaches_full_proof_block() {
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let proof = signed.get("proof").expect("proof attached");

        assert_eq!(proof["type"], json!(PROOF_TYPE));
        assert_eq!(proof["cryptosuite"], json!(CRYPTOSUITE));
        assert_eq!(proof["proofPurpose"], json!(PROOF_PURPOSE_ASSERTION));
        assert_eq!(proof["created"], json!("2026-04-20T10:00:00Z"));
        assert_eq!(
            proof["verificationMethod"],
            json!("https://example.com/users/alice#ed25519-key"),
        );
        let pv = proof["proofValue"]
            .as_str()
            .expect("proofValue is a string");
        assert!(pv.starts_with('z'), "proofValue is multibase z58btc: {pv}");

        // FEP-8b32 §4.5: proof block inherits the document @context so
        // verifiers can resolve `DataIntegrityProof` term in isolation.
        assert_eq!(proof["@context"], sample_create()["@context"]);
    }

    #[test]
    fn challenge_and_domain_appear_in_proof_when_set() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut opts = fixed_options();
        opts.proof_purpose = "authentication".to_owned();
        opts.challenge = Some("nonce-abc".to_owned());
        opts.domain = Some("example.org".to_owned());

        let signed = sign(&sample_create(), &opts, &key).unwrap();
        let proof = &signed["proof"];
        assert_eq!(proof["challenge"], json!("nonce-abc"));
        assert_eq!(proof["domain"], json!("example.org"));
        // This test signs with `proofPurpose = authentication`; the
        // verifier now enforces purpose binding, so we must declare
        // the expected purpose explicitly.
        let vm = fixed_vm();
        let verify_opts = VerifyOptions {
            expected_proof_purpose: "authentication",
            ..test_opts(&vm)
        };
        verify(&signed, &key.public_key(), &verify_opts).expect("auth proof must verify");
    }

    #[test]
    fn verify_rejects_tampered_document_body() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // Mutate a nested field after signing.
        signed["object"]["content"] = json!("<p>tampered</p>");

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("tampering with the body must invalidate the proof");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_tampered_proof_metadata() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // Move the `created` timestamp by one second after signing.
        signed["proof"]["created"] = json!("2026-04-20T10:00:01Z");

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("tampering with proof metadata must invalidate the proof");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // Replace proofValue with a syntactically-valid but semantically
        // wrong signature: re-sign garbage with the same key.
        let bogus_sig = key.sign(b"not the original hash data");
        signed["proof"]["proofValue"] = json!(multibase::encode(Base::Base58Btc, bogus_sig));

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("a swapped signature must not verify");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_proof_signed_by_a_different_key() {
        let signer = Ed25519SigningKey::generate().unwrap();
        let attacker = Ed25519SigningKey::generate().unwrap();

        let signed = sign(&sample_create(), &fixed_options(), &signer).unwrap();
        let vm = fixed_vm();
        let err = verify(&signed, &attacker.public_key(), &test_opts(&vm))
            .expect_err("verifying against the wrong public key must fail");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_missing_proof() {
        let vm = fixed_vm();
        let err = verify(
            &sample_create(),
            &Ed25519SigningKey::generate().unwrap().public_key(),
            &test_opts(&vm),
        )
        .expect_err("documents without proof must be rejected");
        assert!(matches!(err, Error::MissingProof));
    }

    #[test]
    fn verify_rejects_wrong_proof_type() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["type"] = json!("RsaSignature2017");

        let vm = fixed_vm();
        let err =
            verify(&signed, &key.public_key(), &test_opts(&vm)).expect_err("wrong type must fail");
        assert!(matches!(err, Error::UnsupportedProofType(s) if s == "RsaSignature2017"));
    }

    #[test]
    fn verify_rejects_wrong_cryptosuite() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["cryptosuite"] = json!("ecdsa-rdfc-2019");

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("wrong cryptosuite must fail");
        assert!(matches!(err, Error::UnsupportedCryptosuite(s) if s == "ecdsa-rdfc-2019"));
    }

    #[test]
    fn verify_rejects_malformed_proof_value() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["proofValue"] = json!("zNotARealMultibaseString!!");

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("garbage proofValue must fail");
        assert!(matches!(err, Error::InvalidProofValue(_)));
    }

    #[test]
    fn verify_rejects_signature_with_wrong_length() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // 32-byte payload encodes as a much shorter multibase string than
        // a 64-byte Ed25519 signature; the length check must reject it.
        let short = multibase::encode(Base::Base58Btc, [0u8; 32]);
        signed["proof"]["proofValue"] = json!(short);

        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("wrong length must fail");
        assert!(matches!(err, Error::InvalidProofValue(_)));
    }

    #[test]
    fn sign_rejects_non_object_documents() {
        let key = Ed25519SigningKey::generate().unwrap();
        let err = sign(&json!([1, 2, 3]), &fixed_options(), &key)
            .expect_err("array documents cannot carry an inline proof");
        assert!(matches!(err, Error::NotAnObject));
    }

    #[test]
    fn signature_is_deterministic_under_jcs() {
        // Ed25519 signatures are deterministic, JCS is deterministic,
        // and `created` is fixed: signing the same document twice MUST
        // produce byte-identical proofValue.
        let key = Ed25519SigningKey::generate().unwrap();
        let signed_a = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let signed_b = sign(&sample_create(), &fixed_options(), &key).unwrap();
        assert_eq!(
            signed_a["proof"]["proofValue"],
            signed_b["proof"]["proofValue"]
        );
    }

    #[test]
    fn key_order_in_input_does_not_change_signature() {
        // Two semantically equal documents that differ only in member
        // order MUST produce the same proofValue (this is the entire
        // reason JCS canonicalises before hashing).
        let key = Ed25519SigningKey::generate().unwrap();
        let doc_a = json!({
            "type": "Note",
            "content": "hi",
            "id": "https://example.com/n/1"
        });
        let doc_b = json!({
            "id": "https://example.com/n/1",
            "content": "hi",
            "type": "Note"
        });
        let sig_a = sign(&doc_a, &fixed_options(), &key).unwrap();
        let sig_b = sign(&doc_b, &fixed_options(), &key).unwrap();
        assert_eq!(sig_a["proof"]["proofValue"], sig_b["proof"]["proofValue"]);
    }

    #[test]
    fn verify_with_multikey_round_trips_via_fep521a_block() {
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();

        let encoded = actpub_httpsig::Multikey::encode_ed25519(&key.public_key());
        let multikey = actpub_activitystreams::Multikey::new(
            "https://example.com/users/alice#ed25519-key"
                .parse()
                .unwrap(),
            "https://example.com/users/alice".parse().unwrap(),
            encoded,
        );

        let vm = fixed_vm();
        verify_with_multikey(&signed, &multikey, &test_opts(&vm))
            .expect("verifying via FEP-521a multikey block must succeed");
    }

    #[test]
    fn verify_rejects_proof_whose_verification_method_differs_from_expected() {
        // P0-3 regression: the proof claims to be signed by key A,
        // and the caller asks us to verify against key B. Even
        // though the signature math itself succeeds, the verifier
        // MUST refuse the binding so a captured signature cannot be
        // laundered under a different identity.
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let wrong_vm: Url = "https://example.com/users/alice#other-key".parse().unwrap();
        let err = verify(&signed, &key.public_key(), &test_opts(&wrong_vm))
            .expect_err("verificationMethod mismatch must be rejected");
        assert!(matches!(err, Error::VerificationMethodMismatch { .. }));
    }

    #[test]
    fn verify_rejects_authentication_proof_when_assertion_is_expected() {
        // P0-3 regression: a proof signed with
        // `proofPurpose = authentication` (e.g. for a challenge-
        // response login flow) MUST NOT verify when the caller is
        // asking for a content assertion. Otherwise an
        // authentication proof obtained during a single login can
        // be re-used forever as evidence that the actor "asserts"
        // some captured document.
        let key = Ed25519SigningKey::generate().unwrap();
        let mut opts = fixed_options();
        opts.proof_purpose = "authentication".to_owned();
        let signed = sign(&sample_create(), &opts, &key).unwrap();
        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("authentication proof must not verify as assertion");
        assert!(
            matches!(
                err,
                Error::ProofPurposeMismatch { ref expected, ref found }
                    if expected == PROOF_PURPOSE_ASSERTION && found == "authentication",
            ),
            "unexpected: {err:?}",
        );
    }

    #[test]
    fn verify_rejects_proof_with_stale_created_timestamp() {
        // P0-3 regression: without a `max_age` cap, a 10-year-old
        // signed document would verify indefinitely. The verifier
        // MUST reject any proof whose `created` is older than the
        // caller's window.
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let vm = fixed_vm();
        let opts = VerifyOptions {
            now: Utc.with_ymd_and_hms(2026, 4, 22, 10, 0, 0).unwrap(), // +48 h
            max_age: Some(Duration::hours(24)),
            max_clock_skew_future: Some(Duration::minutes(5)),
            ..test_opts(&vm)
        };
        let err =
            verify(&signed, &key.public_key(), &opts).expect_err("48 h > 24 h max_age must reject");
        assert!(matches!(err, Error::ProofTimestampTooOld { .. }));
    }

    #[test]
    fn verify_rejects_proof_whose_created_is_in_the_future() {
        // Clock-skew defence: if the signer claims `created` is
        // 10 minutes ahead of the verifier's clock while the
        // allowed skew is 5 minutes, the proof is rejected.
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let vm = fixed_vm();
        let opts = VerifyOptions {
            now: Utc.with_ymd_and_hms(2026, 4, 20, 9, 50, 0).unwrap(), // 10 min before `created`
            max_age: None,
            max_clock_skew_future: Some(Duration::minutes(5)),
            ..test_opts(&vm)
        };
        let err = verify(&signed, &key.public_key(), &opts)
            .expect_err("future-dated created must be rejected");
        assert!(matches!(err, Error::ProofTimestampInFuture { .. }));
    }

    #[test]
    fn verify_accepts_proof_chain_of_two_valid_proofs() {
        // P1-N4 regression: FEP-8b32 / W3C VC-DI §4.2 proof sets —
        // when `proof` is an ARRAY, every entry must validate. The
        // verifier used to only index into `proof.proofValue`,
        // which returns `None` on an array and aborted with
        // `InvalidProofValue` before even looking at the entries.
        let key = Ed25519SigningKey::generate().unwrap();
        // Build two independent proofs of the same document by
        // signing twice with the SAME key and the SAME options —
        // `eddsa-jcs-2022` is deterministic, so both proofs carry
        // identical proofValue bytes, which is fine for this test
        // (both will validate).
        let signed_a = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let proof_a = signed_a["proof"].clone();
        let mut signed_chain = sample_create();
        signed_chain["proof"] = Value::Array(vec![proof_a.clone(), proof_a]);

        let vm = fixed_vm();
        verify(&signed_chain, &key.public_key(), &test_opts(&vm))
            .expect("a chain of two identical valid proofs must verify");
    }

    #[test]
    fn verify_rejects_proof_chain_with_one_bogus_proof() {
        // P1-N4 regression: a chain is only valid if EVERY entry
        // validates. A silently-dropped bogus sibling must not
        // hide behind a valid one.
        let key = Ed25519SigningKey::generate().unwrap();
        let signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        let valid_proof = signed["proof"].clone();
        let mut bogus_proof = valid_proof.clone();
        // Mutate proofValue to a syntactically valid but
        // semantically wrong signature.
        bogus_proof["proofValue"] = json!("z11111111111111111111111111111");

        let mut signed_chain = sample_create();
        signed_chain["proof"] = Value::Array(vec![valid_proof, bogus_proof]);

        let vm = fixed_vm();
        let err = verify(&signed_chain, &key.public_key(), &test_opts(&vm))
            .expect_err("chain with a bogus proof must be rejected");
        // The bogus proofValue fails signature math or the length /
        // multibase check — either surfaces as a rejection.
        assert!(
            matches!(err, Error::SignatureMismatch | Error::InvalidProofValue(_)),
            "unexpected: {err:?}",
        );
    }

    #[test]
    fn verify_rejects_empty_proof_chain() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sample_create();
        signed["proof"] = Value::Array(vec![]);
        let vm = fixed_vm();
        let err = verify(&signed, &key.public_key(), &test_opts(&vm))
            .expect_err("empty proof chain must be rejected");
        assert!(matches!(err, Error::InvalidProofField { field, .. } if field == "proof"));
    }

    #[test]
    fn parse_created_accepts_rfc3339_with_z() {
        let parsed = parse_created_timestamp("2026-04-20T10:00:00Z").unwrap();
        assert_eq!(parsed, Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap());
    }

    #[test]
    fn parse_created_accepts_xsd_datetime_without_timezone() {
        // P1-N5 regression: `xsd:dateTime` lexical space allows
        // omitting the timezone. Fedify and SpaceBar have been
        // observed emitting timezone-less timestamps; rejecting
        // them would break interop for no security gain.
        let parsed = parse_created_timestamp("2026-04-20T10:00:00").unwrap();
        assert_eq!(parsed, Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap());
    }

    #[test]
    fn parse_created_accepts_xsd_datetime_with_fractional_seconds_no_tz() {
        let parsed = parse_created_timestamp("2026-04-20T10:00:00.123").unwrap();
        // Second-precision equality: the 123 ms sub-second part
        // is carried forward but does not influence the freshness
        // window, which is measured in seconds or coarser.
        let expected = Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap();
        assert_eq!(
            parsed.signed_duration_since(expected).num_milliseconds(),
            123,
        );
    }

    #[test]
    fn parse_created_rejects_garbage() {
        let err = parse_created_timestamp("not a date").expect_err("garbage must fail");
        assert!(matches!(err, Error::InvalidProofField { field, .. } if field == "created"));
    }
}
