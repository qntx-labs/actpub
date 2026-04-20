//! RSA PKCS#1 v1.5 SHA-256 signing and verification, backed by [`aws_lc_rs`].
//!
//! RSA with PKCS#1 v1.5 SHA-256 is the original Cavage HTTP-Signatures
//! algorithm used across the Fediverse (Mastodon, Pleroma, Lemmy, Misskey,
//! …). `aws-lc-rs` provides a constant-time implementation that avoids
//! [RUSTSEC-2023-0071] affecting the pure-Rust `rsa` crate.
//!
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{self, KeyPair as SignatureKeyPair, UnparsedPublicKey};

use crate::error::Error;

/// Supported RSA key sizes. Fediverse actors use 2048 by default; Mastodon
/// allows 4096 and other implementations occasionally go higher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RsaBits {
    /// 2048-bit modulus, the Mastodon default.
    Rsa2048,
    /// 4096-bit modulus.
    Rsa4096,
}

impl RsaBits {
    /// Returns the numeric bit length.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa4096 => 4096,
        }
    }

    const fn as_key_size(self) -> KeySize {
        match self {
            Self::Rsa2048 => KeySize::Rsa2048,
            Self::Rsa4096 => KeySize::Rsa4096,
        }
    }
}

/// An RSA key pair capable of producing PKCS#1 v1.5 SHA-256 signatures.
///
/// Internally stores the `aws-lc-rs` `rsa::KeyPair` for signing, together
/// with the original PKCS#8 DER so that the key can be serialised back
/// out symmetrically (Mastodon and friends distribute PEM-wrapped
/// PKCS#8). The modulus width in bits is cached for convenience.
pub struct RsaSigningKey {
    inner: RsaKeyPair,
    pkcs8_der: Vec<u8>,
    public_spki_der: Vec<u8>,
    bits: u32,
}

impl RsaSigningKey {
    /// Generates a fresh RSA key pair of the requested size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] on RNG or key-scheduling failure.
    pub fn generate(bits: RsaBits) -> Result<Self, Error> {
        let pair = RsaKeyPair::generate(bits.as_key_size())
            .map_err(|_| Error::KeyGeneration("RSA generation failed"))?;
        let pkcs8_der = pair
            .as_der()
            .map_err(|_| Error::KeyGeneration("RSA PKCS#8 v1 serialisation failed"))?
            .as_ref()
            .to_vec();
        Self::build(pair, pkcs8_der, bits.as_u32())
    }

    /// Loads an RSA key pair from a PKCS#8 DER blob.
    ///
    /// Accepts any 256-bit-aligned modulus width in the
    /// `2048..=8192` range, matching the backend's
    /// `RSA_PKCS1_2048_8192_SHA256` verification profile. The lower
    /// bound is the NIST SP 800-131A minimum and the upper bound is
    /// the largest key size the backend supports; values outside the
    /// range are rejected, as are odd widths that cannot represent
    /// valid RSA moduli.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPkcs8`] if the DER cannot be decoded
    /// as an RSA `PrivateKeyInfo`, and [`Error::UnsupportedRsaSize`]
    /// for any other width.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let pair =
            RsaKeyPair::from_pkcs8(der).map_err(|e| Error::InvalidPkcs8(format!("RSA: {e}")))?;
        let bits = u32::try_from(pair.public_modulus_len() * 8).unwrap_or(u32::MAX);
        if !(2048..=8192).contains(&bits) || bits % 256 != 0 {
            return Err(Error::UnsupportedRsaSize(bits));
        }
        Self::build(pair, der.to_vec(), bits)
    }

    /// Builds the struct, computing the SPKI DER once at construction.
    fn build(pair: RsaKeyPair, pkcs8_der: Vec<u8>, bits: u32) -> Result<Self, Error> {
        // `signature::KeyPair::public_key()` → `&rsa::PublicKey`, whose
        // `AsDer<PublicKeyX509Der>` impl produces the SubjectPublicKeyInfo
        // we distribute via `publicKey.publicKeyPem`.
        let spki = pair
            .public_key()
            .as_der()
            .map_err(|_| Error::Crypto("RSA SPKI serialisation failed"))?
            .as_ref()
            .to_vec();
        Ok(Self {
            inner: pair,
            pkcs8_der,
            public_spki_der: spki,
            bits,
        })
    }

    /// Returns the PKCS#8 v1 DER encoding of the private key.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// Returns the modulus length in bits.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Returns the public half of this key pair.
    #[must_use]
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            spki_der: self.public_spki_der.clone(),
        }
    }

    /// Signs `message` using RSA PKCS#1 v1.5 SHA-256.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the low-level primitive fails, which
    /// only happens on internal allocator exhaustion.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; self.inner.public_modulus_len()];
        self.inner
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut sig)
            .map_err(|_| Error::Crypto("RSA PKCS#1 SHA-256 signing failed"))?;
        Ok(sig)
    }
}

impl fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}

/// The verifying half of an RSA key pair.
#[derive(Clone)]
pub struct RsaPublicKey {
    spki_der: Vec<u8>,
}

impl RsaPublicKey {
    /// Wraps a raw `SubjectPublicKeyInfo` DER blob.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPkcs8`] if the DER is truncated.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        if der.is_empty() {
            return Err(Error::InvalidPkcs8("empty SPKI DER".into()));
        }
        Ok(Self {
            spki_der: der.to_vec(),
        })
    }

    /// Returns the `SubjectPublicKeyInfo` DER representation.
    #[must_use]
    pub fn as_spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// Verifies an RSA PKCS#1 v1.5 SHA-256 signature of `message`.
    ///
    /// Accepts signatures created by any SHA-256-based PKCS#1 v1.5 RSA key
    /// in the 2048–8192 bit range, matching what `aws-lc-rs` considers
    /// interoperable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VerificationFailed`] if the signature is invalid
    /// or the key is malformed.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            self.spki_der.as_slice(),
        )
        .verify(message, signature_bytes)
        .map_err(|_| Error::VerificationFailed)
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("spki_bytes", &self.spki_der.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.spki_der == other.spki_der
    }
}

impl Eq for RsaPublicKey {}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    /// Generating a fresh 4096-bit RSA key is slow (~500 ms on CI), so we
    /// use 2048 for speed unless a specific test exercises the larger size.
    fn fresh_key() -> RsaSigningKey {
        RsaSigningKey::generate(RsaBits::Rsa2048).expect("rng available")
    }

    #[test]
    fn generate_then_sign_and_verify_roundtrips() {
        let key = fresh_key();
        let public = key.public_key();
        let msg = b"ActivityPub inbox delivery";
        let sig = key.sign(msg).expect("sign must succeed");
        // 2048-bit key produces 256-byte signature.
        assert_eq!(sig.len(), 256);
        public.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = fresh_key();
        let public = key.public_key();
        let sig = key.sign(b"original message").expect("sign");
        let err = public
            .verify(b"tampered message", &sig)
            .expect_err("tampered message must not verify");
        assert!(matches!(err, Error::VerificationFailed));
    }

    #[test]
    fn pkcs8_roundtrip_preserves_key() {
        let original = fresh_key();
        let reloaded =
            RsaSigningKey::from_pkcs8_der(original.to_pkcs8_der()).expect("reload must succeed");
        assert_eq!(original.bits(), reloaded.bits());
        // Round-trip signing and cross-verification.
        let msg = b"cross-verify me";
        let sig = reloaded.sign(msg).expect("sign");
        original
            .public_key()
            .verify(msg, &sig)
            .expect("reloaded key must produce signatures the original can verify");
    }

    #[test]
    fn rsa_bits_reports_correct_width() {
        let key = fresh_key();
        assert_eq!(key.bits(), 2048);
    }
}
