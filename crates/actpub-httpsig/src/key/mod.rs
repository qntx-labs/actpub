//! Cryptographic key abstractions.
//!
//! This module hides the backend (currently `aws-lc-rs`) behind a single
//! [`SigningKey`] / [`VerifyingKey`] pair that the rest of the crate uses
//! without concerning itself with the algorithm. Conversion to and from
//! PEM / PKCS#8 / FEP-521a Multikey lives under submodules.

mod ed25519;
mod multikey;
mod pem;
mod rsa;

use std::fmt;

pub use self::ed25519::{Ed25519PublicKey, Ed25519SigningKey};
pub use self::multikey::Multikey;
use self::pem::{
    ed25519_public_key_from_pem, ed25519_public_key_to_pem, ed25519_signing_key_from_pem,
    ed25519_signing_key_to_pem, rsa_public_key_from_pem, rsa_public_key_to_pem,
    rsa_signing_key_from_pem, rsa_signing_key_to_pem,
};
pub use self::rsa::{RsaBits, RsaPublicKey, RsaSigningKey};
use crate::error::Error;

/// Algorithm identifier for a signing / verifying key.
///
/// The lexical `name()` strings match the values that appear in the
/// `algorithm=` parameter of a Cavage `Signature:` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// RSA PKCS#1 v1.5 with SHA-256, used by Mastodon's default actor key.
    RsaSha256,
    /// Ed25519 (`EdDSA` over Curve25519).
    Ed25519,
}

impl Algorithm {
    /// Returns the Cavage-compatible lexical name for this algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519 => "ed25519",
        }
    }

    /// Parses a Cavage / RFC 9421-compatible name back into an
    /// [`Algorithm`].
    ///
    /// Accepts both naming conventions in use across the Fediverse:
    ///
    /// - Cavage draft-12 `rsa-sha256`, `ed25519`, `ed25519-sha512`
    /// - RFC 9421 §3.3.2 `rsa-v1_5-sha256`
    /// - Legacy `hs2019` (Mastodon), which requests auto-detection
    ///   from the key itself — returned as `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAlgorithm`] for anything else.
    pub fn parse(name: &str) -> Result<Option<Self>, Error> {
        match name {
            "rsa-sha256" | "rsa-v1_5-sha256" => Ok(Some(Self::RsaSha256)),
            "ed25519" | "ed25519-sha512" => Ok(Some(Self::Ed25519)),
            "hs2019" => Ok(None),
            other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// A key capable of producing detached signatures.
#[non_exhaustive]
pub enum SigningKey {
    /// Ed25519 backend.
    Ed25519(Ed25519SigningKey),
    /// RSA PKCS#1 v1.5 backend.
    Rsa(RsaSigningKey),
}

impl SigningKey {
    /// Generates a fresh Ed25519 signing key using the system RNG.
    ///
    /// # Panics
    ///
    /// Panics if `aws-lc-rs` cannot draw bytes from the operating system.
    /// Every platform we support (Linux, macOS, Windows, the major BSDs)
    /// guarantees this succeeds, so a panic here indicates a broken host.
    /// Callers that prefer to handle this failure gracefully can call
    /// [`Ed25519SigningKey::generate`] directly.
    #[must_use]
    pub fn generate_ed25519() -> Self {
        #[allow(
            clippy::expect_used,
            reason = "the system RNG is a hard dependency of every supported platform; a failure here indicates a broken host and is unrecoverable"
        )]
        let key = Ed25519SigningKey::generate().expect("system RNG must be available for Ed25519");
        Self::Ed25519(key)
    }

    /// Generates a fresh RSA signing key of the requested width.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] on RNG or key-scheduling failure.
    pub fn generate_rsa(bits: RsaBits) -> Result<Self, Error> {
        RsaSigningKey::generate(bits).map(Self::Rsa)
    }

    /// Loads a signing key from a PEM document, autodetecting the
    /// algorithm from the embedded OID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPem`], [`Error::UnexpectedPemLabel`] or
    /// [`Error::UnsupportedAlgorithm`] as appropriate.
    pub fn from_pem(pem_text: &str) -> Result<Self, Error> {
        // Try Ed25519 first — its OID is tiny (3 bytes) so the substring
        // match in `pem` is unambiguous; fall back to RSA on
        // UnsupportedAlgorithm.
        match ed25519_signing_key_from_pem(pem_text) {
            Ok(k) => Ok(Self::Ed25519(k)),
            Err(Error::UnsupportedAlgorithm(_) | Error::UnexpectedPemLabel(_, _)) => {
                rsa_signing_key_from_pem(pem_text).map(Self::Rsa)
            }
            Err(e) => Err(e),
        }
    }

    /// Encodes the signing key as a PKCS#8 `PRIVATE KEY` PEM.
    #[must_use]
    pub fn to_pem(&self) -> String {
        match self {
            Self::Ed25519(k) => ed25519_signing_key_to_pem(k),
            Self::Rsa(k) => rsa_signing_key_to_pem(k),
        }
    }

    /// Returns the algorithm identifier for this key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Rsa(_) => Algorithm::RsaSha256,
        }
    }

    /// Returns the verifying half of this key pair.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(k) => VerifyingKey::Ed25519(k.public_key()),
            Self::Rsa(k) => VerifyingKey::Rsa(k.public_key()),
        }
    }

    /// Signs `message` and returns the raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the underlying primitive fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Self::Ed25519(k) => Ok(k.sign(message)),
            Self::Rsa(k) => k.sign(message),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningKey")
            .field(&self.algorithm())
            .finish()
    }
}

/// A key capable of verifying detached signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// Ed25519 backend.
    Ed25519(Ed25519PublicKey),
    /// RSA PKCS#1 v1.5 backend.
    Rsa(RsaPublicKey),
}

impl VerifyingKey {
    /// Loads a public key from a PEM `PUBLIC KEY` document.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPem`], [`Error::UnexpectedPemLabel`], or
    /// [`Error::UnsupportedAlgorithm`] as appropriate.
    pub fn from_pem(pem_text: &str) -> Result<Self, Error> {
        match ed25519_public_key_from_pem(pem_text) {
            Ok(k) => Ok(Self::Ed25519(k)),
            Err(Error::UnsupportedAlgorithm(_) | Error::UnexpectedPemLabel(_, _)) => {
                rsa_public_key_from_pem(pem_text).map(Self::Rsa)
            }
            Err(e) => Err(e),
        }
    }

    /// Encodes the public key as a `SubjectPublicKeyInfo` PEM.
    #[must_use]
    pub fn to_pem(&self) -> String {
        match self {
            Self::Ed25519(k) => ed25519_public_key_to_pem(k),
            Self::Rsa(k) => rsa_public_key_to_pem(k),
        }
    }

    /// Returns the algorithm identifier for this key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Rsa(_) => Algorithm::RsaSha256,
        }
    }

    /// Verifies a detached signature of `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VerificationFailed`] if the signature is
    /// malformed or does not match the message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self {
            Self::Ed25519(k) => k.verify(message, signature),
            Self::Rsa(k) => k.verify(message, signature),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn ed25519_pem_roundtrip_through_top_level_enum() {
        let key = SigningKey::generate_ed25519();
        let pem = key.to_pem();
        let reloaded = SigningKey::from_pem(&pem).expect("reload");
        assert_eq!(reloaded.algorithm(), Algorithm::Ed25519);
        assert_eq!(
            key.verifying_key(),
            reloaded.verifying_key(),
            "verifying keys must match after PEM roundtrip",
        );
    }

    #[test]
    fn rsa_pem_roundtrip_through_top_level_enum() {
        let key = SigningKey::generate_rsa(RsaBits::Rsa2048).expect("rng");
        let pem = key.to_pem();
        let reloaded = SigningKey::from_pem(&pem).expect("reload");
        assert_eq!(reloaded.algorithm(), Algorithm::RsaSha256);
    }

    #[test]
    fn sign_and_verify_through_enum_dispatch() {
        for key in [
            SigningKey::generate_ed25519(),
            SigningKey::generate_rsa(RsaBits::Rsa2048).expect("rng"),
        ] {
            let msg = b"payload";
            let sig = key.sign(msg).expect("sign");
            key.verifying_key()
                .verify(msg, &sig)
                .expect("verify must succeed for the matching key");
        }
    }

    #[test]
    fn algorithm_parse_handles_known_names() {
        assert_eq!(
            Algorithm::parse("rsa-sha256").expect("parse"),
            Some(Algorithm::RsaSha256),
        );
        // RFC 9421 §3.3.2 name for the same primitive.
        assert_eq!(
            Algorithm::parse("rsa-v1_5-sha256").expect("parse"),
            Some(Algorithm::RsaSha256),
        );
        assert_eq!(
            Algorithm::parse("ed25519").expect("parse"),
            Some(Algorithm::Ed25519),
        );
        assert_eq!(
            Algorithm::parse("ed25519-sha512").expect("parse"),
            Some(Algorithm::Ed25519),
        );
        // Legacy `hs2019` requests autodetection.
        assert_eq!(Algorithm::parse("hs2019").expect("parse"), None);
    }

    #[test]
    fn algorithm_parse_rejects_unknown_names() {
        let err = Algorithm::parse("hmac-sha256").expect_err("unknown algorithm");
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)));
    }
}
