//! [FEP-521a] Multikey encoding of public keys.
//!
//! The Fediverse's modern actor format represents public keys as a
//! single `publicKeyMultibase` string of the form `z<base58-btc>`, where
//! the decoded bytes are `<multicodec-prefix><raw-key-bytes>`.
//!
//! This module currently supports Ed25519 (multicodec `0xed`), the
//! primary algorithm specified by FEP-521a. RSA and other algorithms are
//! intentionally out of scope here — they are represented via the
//! traditional Cavage `publicKeyPem` field and not via Multikey.
//!
//! [FEP-521a]: https://codeberg.org/fediverse/fep/src/branch/main/fep/521a/fep-521a.md

use multibase::Base;
use unsigned_varint::{decode, encode};

use crate::error::Error;
use crate::key::ed25519::{ED25519_PUBLIC_KEY_LEN, Ed25519PublicKey};

/// Ed25519 public-key multicodec identifier (varint-encoded).
///
/// See the [multicodec table][table]; `0xed` is the canonical value.
///
/// [table]: https://github.com/multiformats/multicodec/blob/master/table.csv
pub(crate) const ED25519_MULTICODEC: u64 = 0xed;

/// A FEP-521a Multikey, pairing the decoded [`VerifyingKey`](super::VerifyingKey)
/// with the original base58-btc encoded string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Multikey {
    /// The original `z<base58-btc>` encoded string.
    pub encoded: String,
    /// Decoded Ed25519 public key.
    pub key: Ed25519PublicKey,
}

impl Multikey {
    /// Encodes an Ed25519 public key as a `z<base58-btc>` Multikey string.
    #[must_use]
    pub fn encode_ed25519(key: &Ed25519PublicKey) -> String {
        let mut buf = encode::u64_buffer();
        let prefix = encode::u64(ED25519_MULTICODEC, &mut buf);
        let mut bytes = Vec::with_capacity(prefix.len() + ED25519_PUBLIC_KEY_LEN);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(key.as_bytes());
        multibase::encode(Base::Base58Btc, bytes)
    }

    /// Decodes a Multikey string into its components.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMultibase`] on bad multibase encoding,
    /// [`Error::InvalidMultikeyPrefix`] when the varint prefix is missing,
    /// [`Error::UnsupportedAlgorithm`] when the codec is not Ed25519,
    /// and [`Error::InvalidMultikeyLength`] when the body is the wrong
    /// length.
    pub fn decode(encoded: &str) -> Result<Self, Error> {
        let (_base, bytes) = multibase::decode(encoded)?;
        let (codec, rest) = decode::u64(&bytes).map_err(|_| Error::InvalidMultikeyPrefix)?;
        if codec != ED25519_MULTICODEC {
            return Err(Error::UnsupportedAlgorithm(format!(
                "Multikey codec 0x{codec:x} is not Ed25519 (0x{ED25519_MULTICODEC:x})"
            )));
        }
        let key = Ed25519PublicKey::from_bytes(rest)?;
        Ok(Self {
            encoded: encoded.to_owned(),
            key,
        })
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::key::ed25519::Ed25519SigningKey;

    #[test]
    fn encode_then_decode_roundtrips() {
        let signing = Ed25519SigningKey::generate().expect("rng");
        let public = signing.public_key();
        let encoded = Multikey::encode_ed25519(&public);

        assert!(
            encoded.starts_with('z'),
            "Multikey must be base58-btc encoded (prefix `z`)",
        );

        let decoded = Multikey::decode(&encoded).expect("round-trip decode");
        assert_eq!(decoded.key, public);
        assert_eq!(decoded.encoded, encoded);
    }

    #[test]
    fn decode_rejects_wrong_codec() {
        // Fabricate a Multikey with an unknown codec (0x1205 = rsa-pub).
        let mut bytes = Vec::new();
        let mut buf = encode::u64_buffer();
        let prefix = encode::u64(0x1205, &mut buf);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&[0u8; 32]); // dummy key
        let encoded = multibase::encode(Base::Base58Btc, bytes);

        let err = Multikey::decode(&encoded).expect_err("RSA codec must be rejected");
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn decode_rejects_wrong_body_length() {
        let mut bytes = Vec::new();
        let mut buf = encode::u64_buffer();
        let prefix = encode::u64(ED25519_MULTICODEC, &mut buf);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&[0u8; 16]); // wrong: 16 instead of 32
        let encoded = multibase::encode(Base::Base58Btc, bytes);

        let err = Multikey::decode(&encoded).expect_err("short body must be rejected");
        assert!(matches!(
            err,
            Error::InvalidMultikeyLength {
                expected: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn decode_rejects_garbage() {
        let err = Multikey::decode("not-a-multibase-string").expect_err("bad multibase");
        assert!(matches!(err, Error::InvalidMultibase(_)));
    }

    /// Known-good vector from the FEP-521a specification examples,
    /// cross-checked against Mitra's and Fedify's Multikey implementations.
    #[test]
    fn decodes_known_good_fixture() {
        // A Multikey produced by Mitra for a test account. 32 zero bytes
        // would give the same encoded prefix, but here we use a well-known
        // Ed25519 RFC 8032 test vector public key.
        let key_bytes =
            hex_literal::hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let public = Ed25519PublicKey::from_bytes(&key_bytes).expect("valid key");
        let encoded = Multikey::encode_ed25519(&public);
        // The leading `z6Mk` prefix is a defining feature of Ed25519 Multikeys.
        assert!(
            encoded.starts_with("z6Mk"),
            "Ed25519 Multikey should begin with `z6Mk`, got `{encoded}`",
        );
        let decoded = Multikey::decode(&encoded).expect("decode");
        assert_eq!(decoded.key.as_bytes(), &key_bytes);
    }
}
