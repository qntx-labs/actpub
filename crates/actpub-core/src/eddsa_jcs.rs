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
use chrono::{DateTime, SecondsFormat, Utc};
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

/// Verifies that `signed_document.proof` is an authentic
/// `eddsa-jcs-2022` Data Integrity proof produced by the holder of
/// `verifying_key`.
///
/// # Errors
///
/// Returns [`Error::MissingProof`] when no `proof` member is present,
/// [`Error::UnsupportedProofType`] / [`Error::UnsupportedCryptosuite`]
/// when the proof header does not match this cryptosuite,
/// [`Error::InvalidProofValue`] when `proofValue` cannot be decoded
/// into a 64-byte Ed25519 signature, [`Error::Canonicalisation`] for
/// JCS failures, and [`Error::SignatureMismatch`] when the signature
/// does not validate against the document and key.
pub fn verify(signed_document: &Value, verifying_key: &Ed25519PublicKey) -> Result<(), Error> {
    let proof = signed_document.get("proof").ok_or(Error::MissingProof)?;
    let raw_signature = decode_proof_value(proof)?;

    check_proof_header(proof)?;

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
/// actor's `assertionMethod` keys.
///
/// # Errors
///
/// Same as [`verify`], plus [`Error::InvalidMultikey`] when the
/// multibase-encoded key cannot be decoded as Ed25519.
pub fn verify_with_multikey(
    signed_document: &Value,
    multikey: &actpub_activitystreams::Multikey,
) -> Result<(), Error> {
    let decoded = actpub_httpsig::Multikey::decode(&multikey.public_key_multibase)
        .map_err(|e| Error::InvalidMultikey(e.to_string()))?;
    verify(signed_document, &decoded.key)
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
            verification_method: "https://example.com/users/alice#ed25519-key"
                .parse()
                .unwrap(),
            proof_purpose: PROOF_PURPOSE_ASSERTION.to_owned(),
            created: Utc.with_ymd_and_hms(2026, 4, 20, 10, 0, 0).unwrap(),
            challenge: None,
            domain: None,
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
        verify(&signed, &key.public_key()).expect("self-verify must succeed");
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
        verify(&signed, &key.public_key()).expect("auth proof must verify");
    }

    #[test]
    fn verify_rejects_tampered_document_body() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // Mutate a nested field after signing.
        signed["object"]["content"] = json!("<p>tampered</p>");

        let err = verify(&signed, &key.public_key())
            .expect_err("tampering with the body must invalidate the proof");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_tampered_proof_metadata() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        // Move the `created` timestamp by one second after signing.
        signed["proof"]["created"] = json!("2026-04-20T10:00:01Z");

        let err = verify(&signed, &key.public_key())
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

        let err =
            verify(&signed, &key.public_key()).expect_err("a swapped signature must not verify");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_proof_signed_by_a_different_key() {
        let signer = Ed25519SigningKey::generate().unwrap();
        let attacker = Ed25519SigningKey::generate().unwrap();

        let signed = sign(&sample_create(), &fixed_options(), &signer).unwrap();
        let err = verify(&signed, &attacker.public_key())
            .expect_err("verifying against the wrong public key must fail");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_missing_proof() {
        let err = verify(
            &sample_create(),
            &Ed25519SigningKey::generate().unwrap().public_key(),
        )
        .expect_err("documents without proof must be rejected");
        assert!(matches!(err, Error::MissingProof));
    }

    #[test]
    fn verify_rejects_wrong_proof_type() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["type"] = json!("RsaSignature2017");

        let err = verify(&signed, &key.public_key()).expect_err("wrong type must fail");
        assert!(matches!(err, Error::UnsupportedProofType(s) if s == "RsaSignature2017"));
    }

    #[test]
    fn verify_rejects_wrong_cryptosuite() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["cryptosuite"] = json!("ecdsa-rdfc-2019");

        let err = verify(&signed, &key.public_key()).expect_err("wrong cryptosuite must fail");
        assert!(matches!(err, Error::UnsupportedCryptosuite(s) if s == "ecdsa-rdfc-2019"));
    }

    #[test]
    fn verify_rejects_malformed_proof_value() {
        let key = Ed25519SigningKey::generate().unwrap();
        let mut signed = sign(&sample_create(), &fixed_options(), &key).unwrap();
        signed["proof"]["proofValue"] = json!("zNotARealMultibaseString!!");

        let err = verify(&signed, &key.public_key()).expect_err("garbage proofValue must fail");
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

        let err = verify(&signed, &key.public_key()).expect_err("wrong length must fail");
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

        verify_with_multikey(&signed, &multikey)
            .expect("verifying via FEP-521a multikey block must succeed");
    }
}
