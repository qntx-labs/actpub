//! Crate-wide error type for [`actpub-core`](crate).
//!
//! Errors are returned by every fallible API in this crate. Variants are
//! `#[non_exhaustive]` so that adding a new failure mode is not a
//! breaking change.

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Top-level error type for `actpub-core`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// JCS canonicalisation failed because the input JSON could not be
    /// expressed in the canonical form (e.g. it contained `NaN` or
    /// `Infinity`, which JCS forbids).
    #[error("JCS canonicalisation failed: {0}")]
    Canonicalisation(String),

    /// The document being verified did not carry a `proof` member.
    #[error("document is missing the `proof` field")]
    MissingProof,

    /// The document was not a JSON object (only objects can carry
    /// proofs).
    #[error("document must be a JSON object")]
    NotAnObject,

    /// The proof's `type` was not the value mandated by FEP-8b32.
    #[error("proof has unsupported `type` `{0}`, expected `DataIntegrityProof`")]
    UnsupportedProofType(String),

    /// The proof's `cryptosuite` was not one this crate can verify.
    #[error("proof has unsupported `cryptosuite` `{0}`, expected `eddsa-jcs-2022`")]
    UnsupportedCryptosuite(String),

    /// `proofValue` was missing, malformed, or used the wrong multibase
    /// prefix or wrong length for the declared cryptosuite.
    #[error("proof.proofValue is missing or malformed: {0}")]
    InvalidProofValue(String),

    /// The Ed25519 verification step failed: either the signature is
    /// not authentic for the given key and document, or the document
    /// has been tampered with after signing.
    #[error("Ed25519 signature did not verify against the document")]
    SignatureMismatch,

    /// A required proof field was missing or had the wrong JSON shape.
    #[error("invalid proof field `{field}`: {reason}")]
    InvalidProofField {
        /// Name of the proof field whose value was invalid.
        field: &'static str,
        /// Human-readable explanation.
        reason: String,
    },

    /// The Multikey block could not be decoded into a usable Ed25519
    /// public key.
    #[error("multikey decoding failed: {0}")]
    InvalidMultikey(String),

    /// The proof's `verificationMethod` URL did not match the key
    /// the caller asked us to verify against. Carrying both URLs in
    /// the error is important for the FEP-8b32 threat model: a
    /// silent acceptance here is the `key confusion` attack where a
    /// captured signature is re-bound to a different identity.
    #[error("proof.verificationMethod `{found}` does not match expected `{expected}`")]
    VerificationMethodMismatch {
        /// The URL the caller expected.
        expected: String,
        /// The URL the proof claimed.
        found: String,
    },

    /// The proof's `proofPurpose` did not match the context the
    /// caller declared (typically `assertionMethod` for content
    /// assertions vs. `authentication` for challenge–response login).
    /// Without this gate, a signature issued for one purpose can be
    /// laundered as if it had been issued for another.
    #[error("proof.proofPurpose `{found}` does not match expected `{expected}`")]
    ProofPurposeMismatch {
        /// The purpose the caller expected.
        expected: String,
        /// The purpose the proof declared.
        found: String,
    },

    /// The proof's `created` timestamp is older than the caller's
    /// `max_age` window. Data Integrity proofs without an
    /// expiration grow stale indefinitely unless the verifier
    /// caps their lifetime explicitly.
    #[error("proof.created `{created}` is older than the verifier's window (`now = {now}`)")]
    ProofTimestampTooOld {
        /// Parsed `created` instant.
        created: DateTime<Utc>,
        /// The `now` the verifier was called with.
        now: DateTime<Utc>,
    },

    /// The proof's `created` timestamp sits more than the allowed
    /// clock-skew window into the future — almost certainly a
    /// forgery or a signer with a badly-set clock.
    #[error(
        "proof.created `{created}` is further in the future than the verifier's skew window (`now = {now}`)"
    )]
    ProofTimestampInFuture {
        /// Parsed `created` instant.
        created: DateTime<Utc>,
        /// The `now` the verifier was called with.
        now: DateTime<Utc>,
    },

    /// A low-level cryptographic error from the underlying HTTP-Sig
    /// crate.
    #[error(transparent)]
    HttpSig(#[from] actpub_httpsig::Error),
}
