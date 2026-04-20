//! Ed25519 signing and verification backed by [`aws_lc_rs`].

use std::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::error::Error;

/// Length of a raw Ed25519 public key in bytes.
pub(crate) const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of a raw Ed25519 signature in bytes.
pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;

/// An Ed25519 key pair capable of producing signatures.
pub struct Ed25519SigningKey {
    inner: Ed25519KeyPair,
    /// Cached PKCS#8 encoding so we can hand back the same bytes via
    /// [`Self::to_pkcs8_der`] after an in-memory generation.
    pkcs8_der: Vec<u8>,
}

impl Ed25519SigningKey {
    /// Generates a fresh Ed25519 key pair using the system RNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the underlying RNG fails, which
    /// effectively only happens on platforms where `aws-lc-rs` cannot
    /// initialise a secure random source.
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| Error::KeyGeneration("Ed25519 PKCS#8 generation failed"))?;
        let inner = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| Error::KeyGeneration("Ed25519 PKCS#8 parse after generate"))?;
        Ok(Self {
            inner,
            pkcs8_der: pkcs8.as_ref().to_vec(),
        })
    }

    /// Loads an Ed25519 key pair from a PKCS#8 DER blob.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPkcs8`] if the DER cannot be decoded as an
    /// Ed25519 `PrivateKeyInfo`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let inner = Ed25519KeyPair::from_pkcs8(der)
            .map_err(|e| Error::InvalidPkcs8(format!("Ed25519: {e}")))?;
        Ok(Self {
            inner,
            pkcs8_der: der.to_vec(),
        })
    }

    /// Returns the PKCS#8 v2 DER encoding of the private key.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// Returns the corresponding public key.
    ///
    /// # Panics
    ///
    /// Panics only if `aws-lc-rs` produces a public key whose length is
    /// not exactly 32 bytes — which the Ed25519 algorithm forbids by
    /// construction. A panic here therefore indicates a bug in
    /// `aws-lc-rs` and not in our code.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        #[allow(
            clippy::expect_used,
            reason = "aws-lc-rs guarantees an Ed25519 public key is exactly 32 bytes"
        )]
        let bytes: [u8; ED25519_PUBLIC_KEY_LEN] = self
            .inner
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is exactly 32 bytes");
        Ed25519PublicKey { bytes }
    }

    /// Produces a detached Ed25519 signature over `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).as_ref().to_vec()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("Ed25519SigningKey").finish_non_exhaustive()
    }
}

/// A verifying half of an Ed25519 key pair.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey {
    bytes: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519PublicKey {
    /// Wraps a raw 32-byte public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMultikeyLength`] if the slice is not exactly
    /// 32 bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; ED25519_PUBLIC_KEY_LEN] =
            raw.try_into().map_err(|_| Error::InvalidMultikeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: raw.len(),
            })?;
        Ok(Self { bytes })
    }

    /// Returns the raw 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Verifies a detached signature of `message` against this public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VerificationFailed`] if the signature is invalid,
    /// malformed, or if `message` has been tampered with.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(Error::VerificationFailed);
        }
        UnparsedPublicKey::new(&signature::ED25519, self.bytes)
            .verify(message, signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are safe to print but we still use hex for readability.
        f.debug_tuple("Ed25519PublicKey")
            .field(&format_args!("{}", hex(&self.bytes)))
            .finish()
    }
}

#[allow(
    clippy::expect_used,
    reason = "writing to an owned `String` via `core::fmt::Write` is infallible; the `Result` only exists to satisfy the trait"
)]
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to an owned String is infallible");
    }
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn generate_then_sign_and_verify_roundtrips() {
        let key = Ed25519SigningKey::generate().expect("rng available");
        let public = key.public_key();
        let msg = b"activitypub inbox delivery";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        public.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = Ed25519SigningKey::generate().expect("rng available");
        let public = key.public_key();
        let sig = key.sign(b"original message");
        let err = public
            .verify(b"tampered message", &sig)
            .expect_err("tampered message must not verify");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn wrong_signature_length_is_rejected() {
        let key = Ed25519SigningKey::generate().expect("rng available");
        let public = key.public_key();
        let err = public
            .verify(b"msg", &[0u8; 32])
            .expect_err("short signature must not verify");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn pkcs8_roundtrip_preserves_key() {
        let original = Ed25519SigningKey::generate().expect("rng available");
        let reloaded = Ed25519SigningKey::from_pkcs8_der(original.to_pkcs8_der())
            .expect("reload must succeed");
        assert_eq!(original.public_key(), reloaded.public_key());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let err = Ed25519PublicKey::from_bytes(&[0u8; 16]).expect_err("16 bytes must be rejected");
        assert!(matches!(
            err,
            Error::InvalidMultikeyLength {
                expected: 32,
                actual: 16
            }
        ));
    }
}
