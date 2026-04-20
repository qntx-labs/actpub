//! Error types for [`actpub-httpsig`](crate).

use thiserror::Error;

/// Enumeration of every failure mode that this crate can surface.
///
/// The enum is non-exhaustive so that additional signature schemes or
/// cryptographic algorithms can be added in minor releases without
/// breaking downstream code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The provided PEM document could not be parsed.
    #[error("invalid PEM document: {0}")]
    InvalidPem(String),

    /// The PEM document had an unexpected `-----BEGIN <LABEL>-----` line.
    #[error("unexpected PEM label `{0}`, expected one of: {1}")]
    UnexpectedPemLabel(String, &'static str),

    /// A PKCS#8 DER blob could not be decoded.
    #[error("invalid PKCS#8 DER: {0}")]
    InvalidPkcs8(String),

    /// The key's algorithm identifier was not supported.
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The RSA key size was outside the supported range.
    #[error(
        "unsupported RSA key size {0} bits; only {min}-{max} supported",
        min = 2048,
        max = 4096
    )]
    UnsupportedRsaSize(u32),

    /// An underlying `aws-lc-rs` primitive failed.
    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),

    /// Generation of a new key failed at the RNG layer.
    #[error("key generation failed: {0}")]
    KeyGeneration(&'static str),

    /// A signature's Base64 encoding was malformed.
    #[error("invalid Base64 in signature: {0}")]
    InvalidBase64(#[from] base64ct::Error),

    /// Multibase decoding of a FEP-521a `publicKeyMultibase` failed.
    #[error("invalid multibase: {0}")]
    InvalidMultibase(#[from] multibase::Error),

    /// The multicodec prefix on a Multikey was unrecognised or truncated.
    #[error("invalid multikey codec prefix")]
    InvalidMultikeyPrefix,

    /// The raw key material following the multicodec prefix had the wrong length.
    #[error("invalid multikey body length: expected {expected}, got {actual}")]
    InvalidMultikeyLength {
        /// Expected number of key bytes.
        expected: usize,
        /// Actual number of key bytes.
        actual: usize,
    },

    /// A required HTTP header is missing.
    #[error("missing HTTP header `{0}`")]
    MissingHeader(&'static str),

    /// An HTTP header's value was not valid UTF-8 or otherwise unparseable.
    #[error("invalid HTTP header `{name}`: {reason}")]
    InvalidHeader {
        /// Header name that could not be parsed.
        name: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// The `Signature` header's parameter list was malformed.
    #[error("malformed Signature header: {0}")]
    MalformedSignatureHeader(String),

    /// The signature did not verify against the provided key.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The resolver closure returned an error while fetching the signer's key.
    #[error("key resolution failed: {0}")]
    KeyResolution(String),

    /// The `Digest` / `Content-Digest` header did not match the body.
    #[error("digest mismatch: body SHA-256 did not match `Digest` header")]
    DigestMismatch,

    /// The requested digest algorithm is not supported.
    #[error("unsupported digest algorithm `{0}`")]
    UnsupportedDigestAlgorithm(String),

    /// The signature-base string includes a header that the request does not carry.
    #[error("cannot build signature base: required header `{0}` is absent from the request")]
    RequiredHeaderAbsent(String),

    /// A signature parameter required by the standard is missing.
    #[error("required signature parameter `{0}` is missing")]
    MissingSignatureParameter(&'static str),

    /// The signature carried no `created` parameter and no `Date`
    /// header, and the active [`VerifyPolicy`](crate::VerifyPolicy)
    /// requires one.
    #[error("no `created` parameter or `Date` header on a signature that requires freshness")]
    TimestampMissing,

    /// The signature is older than the policy's `max_age`.
    #[error("signature is too old: timestamp {timestamp}, now {now}")]
    TimestampTooOld {
        /// The signed timestamp, either from `created` or the `Date` header.
        timestamp: chrono::DateTime<chrono::Utc>,
        /// The verifier's current wall-clock time.
        now: chrono::DateTime<chrono::Utc>,
    },

    /// The signature claims to have been produced further in the future
    /// than the policy's `max_clock_skew_future` tolerance allows.
    #[error("signature claims a future timestamp: timestamp {timestamp}, now {now}")]
    TimestampInFuture {
        /// The signed timestamp.
        timestamp: chrono::DateTime<chrono::Utc>,
        /// The verifier's current wall-clock time.
        now: chrono::DateTime<chrono::Utc>,
    },

    /// The signature's `expires` parameter indicates it has lapsed.
    #[error("signature expired at {expires}, now {now}")]
    TimestampExpired {
        /// The `expires` parameter interpreted as a UTC timestamp.
        expires: chrono::DateTime<chrono::Utc>,
        /// The verifier's current wall-clock time.
        now: chrono::DateTime<chrono::Utc>,
    },
}
