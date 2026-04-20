//! [FEP-8b32 Object Integrity Proof][fep8b32] / W3C
//! [Data Integrity 1.0][di] proof block.
//!
//! Object Integrity Proofs let any AS 2.0 object carry one or more
//! cryptographic signatures inline in the document, independent of the
//! HTTP transport. This is what FEP-8b32 calls a `proof` and what the
//! W3C VC ecosystem calls a Data Integrity proof — they are the same
//! shape.
//!
//! The single field that varies between cryptosuites is
//! [`proof_value`](Proof::proof_value): an opaque multibase-encoded
//! signature whose semantics depend on
//! [`cryptosuite`](Proof::cryptosuite). For `eddsa-jcs-2022` the value
//! is a base58btc-encoded raw Ed25519 signature over the JCS
//! canonicalisation of the document with `proofValue` removed.
//!
//! This crate models the wire form only; the actual cryptosuite
//! implementation lives in the upcoming `actpub-core` crate so that
//! the data layer remains free of crypto dependencies.
//!
//! [fep8b32]: https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md
//! [di]: https://www.w3.org/TR/vc-data-integrity/

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use url::Url;

/// FEP-8b32 / W3C Data Integrity Proof block.
///
/// The mandatory fields per FEP-8b32 §3.2 are
/// [`type_`](Self::type_), [`cryptosuite`](Self::cryptosuite),
/// [`created`](Self::created),
/// [`verification_method`](Self::verification_method),
/// [`proof_purpose`](Self::proof_purpose) and
/// [`proof_value`](Self::proof_value). The remaining fields appear in
/// specialised use cases (challenge–response auth, proof chaining).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_field_names,
    reason = "the `proof_purpose`, `proof_value` and `previous_proof` field names are mandated verbatim by the W3C Data Integrity / FEP-8b32 vocabulary and cannot be renamed without breaking interoperability"
)]
pub struct Proof {
    /// Discriminator for the proof scheme. MUST be
    /// [`Proof::DATA_INTEGRITY_PROOF`] when the proof is a Data
    /// Integrity / FEP-8b32 proof.
    #[serde(rename = "type")]
    pub type_: String,

    /// Cryptosuite identifier (e.g. `"eddsa-jcs-2022"`,
    /// `"eddsa-rdfc-2022"`, `"ecdsa-jcs-2019"`). FEP-8b32 currently
    /// mandates `eddsa-jcs-2022` for Fediverse interoperability.
    pub cryptosuite: String,

    /// Wall-clock time at which the signer produced the proof. RFC 3339
    /// / `xsd:dateTime` form on the wire.
    pub created: DateTime<FixedOffset>,

    /// URL identifying the verification method (key) used to produce
    /// the signature. MUST resolve via the actor's `assertionMethod`
    /// or `authentication` list.
    pub verification_method: Url,

    /// Reason the signature was generated. Per FEP-8b32 §3.2 always
    /// `"assertionMethod"` for content-signing in the Fediverse;
    /// `"authentication"` is reserved for challenge–response flows.
    pub proof_purpose: String,

    /// Opaque cryptosuite-specific signature value, multibase-encoded.
    pub proof_value: String,

    /// Optional domain to which this proof is bound (e.g. for
    /// preventing cross-domain replay).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Optional challenge nonce for interactive authentication
    /// proofs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Optional URL of a previous proof in a proof chain (e.g. used by
    /// FEP-1b12 group `Announce` re-signing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<Url>,

    /// Forward-compatible bag for proof parameters that future
    /// cryptosuites may add.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Proof {
    /// The mandatory `type` discriminator value for Data Integrity /
    /// FEP-8b32 proofs.
    pub const DATA_INTEGRITY_PROOF: &'static str = "DataIntegrityProof";

    /// The `eddsa-jcs-2022` cryptosuite identifier — the Fediverse
    /// baseline per FEP-8b32 §3.1.
    pub const CRYPTOSUITE_EDDSA_JCS_2022: &'static str = "eddsa-jcs-2022";

    /// The `proofPurpose` value used by FEP-8b32 to attest that the
    /// signed document is asserted by the signer.
    pub const PURPOSE_ASSERTION_METHOD: &'static str = "assertionMethod";

    /// The `proofPurpose` value used by FEP-8b32 challenge-response
    /// authentication.
    pub const PURPOSE_AUTHENTICATION: &'static str = "authentication";
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn fep_8b32_minimal_proof_roundtrips() {
        // chrono serialises a UTC `FixedOffset` as `Z` (RFC 3339 short form);
        // the test fixture uses the same form for byte-stable roundtrip.
        let raw = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-04-20T10:00:00Z",
            "verificationMethod": "https://example.com/users/alice#ed25519-key",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3F4nT9mC8rE7QXJyV9hP2wKzN8sA5bL"
        });
        let proof: Proof = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(proof.type_, Proof::DATA_INTEGRITY_PROOF);
        assert_eq!(proof.cryptosuite, Proof::CRYPTOSUITE_EDDSA_JCS_2022);
        assert_eq!(proof.proof_purpose, Proof::PURPOSE_ASSERTION_METHOD);
        let back = serde_json::to_value(&proof).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn proof_with_challenge_and_previous_roundtrips() {
        let raw = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-04-20T10:00:00Z",
            "verificationMethod": "https://example.com/users/alice#ed25519-key",
            "proofPurpose": "authentication",
            "proofValue": "z3F4nT9mC8rE7QXJyV9hP2wKzN8sA5bL",
            "domain": "example.com",
            "challenge": "8b9c0d1e",
            "previousProof": "https://example.com/proofs/123"
        });
        let proof: Proof = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(proof.domain.as_deref(), Some("example.com"));
        assert_eq!(proof.challenge.as_deref(), Some("8b9c0d1e"));
        assert!(proof.previous_proof.is_some());
        let back = serde_json::to_value(&proof).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn extra_proof_parameters_roundtrip() {
        // Forward-compatible bag for cryptosuite-specific extensions.
        let raw = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "future-suite-2030",
            "created": "2026-04-20T10:00:00Z",
            "verificationMethod": "https://example.com/key",
            "proofPurpose": "assertionMethod",
            "proofValue": "zABC",
            "futureParam": "futureValue"
        });
        let proof: Proof = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(proof.extra.len(), 1);
        let back = serde_json::to_value(&proof).unwrap();
        assert_eq!(back, raw);
    }
}
