//! Bidirectional [FEP-521a] [`Multikey`] bridge between the
//! activitystreams data layer and the httpsig crypto layer.
//!
//! The two crates intentionally model Multikeys differently:
//!
//! - [`actpub_activitystreams::Multikey`] is the wire-format struct
//!   (`id` / `controller` / `publicKeyMultibase`) that appears inside
//!   an actor's `assertionMethod` array.
//! - [`actpub_httpsig::Multikey`] is the decoded form pairing the
//!   multibase string with a usable [`Ed25519PublicKey`].
//!
//! This module provides the two helpers that move between them so
//! callers do not have to invoke the underlying multibase / multicodec
//! routines themselves. The verification-side helper
//! [`crate::eddsa_jcs::verify_with_multikey`] is built on top of
//! [`decode_ed25519`].
//!
//! [FEP-521a]: https://codeberg.org/fediverse/fep/src/branch/main/fep/521a/fep-521a.md
//! [`Ed25519PublicKey`]: actpub_httpsig::Ed25519PublicKey

use actpub_activitystreams::Multikey as AsMultikey;
use actpub_httpsig::{Ed25519PublicKey, Multikey as HsMultikey};
use url::Url;

use crate::error::Error;

/// Wraps an Ed25519 public key into the FEP-521a [`Multikey`] block
/// shape ready to be published in an actor's `assertionMethod` /
/// `verificationMethod` / `authentication` list.
///
/// `key_id` is typically `<actor URL>#<fragment>` and `controller` is
/// the actor's `id` URL.
///
/// [`Multikey`]: actpub_activitystreams::Multikey
#[must_use]
pub fn publish_ed25519(
    public_key: &Ed25519PublicKey,
    key_id: Url,
    controller: Url,
) -> AsMultikey {
    let encoded = HsMultikey::encode_ed25519(public_key);
    AsMultikey::new(key_id, controller, encoded)
}

/// Decodes the FEP-521a [`Multikey`] block carried in an actor's
/// `assertionMethod` into a usable [`Ed25519PublicKey`].
///
/// # Errors
///
/// Returns [`Error::InvalidMultikey`] when the embedded multibase
/// string cannot be decoded as a 32-byte Ed25519 public key, including
/// when it advertises a non-Ed25519 multicodec prefix.
///
/// [`Multikey`]: actpub_activitystreams::Multikey
pub fn decode_ed25519(multikey: &AsMultikey) -> Result<Ed25519PublicKey, Error> {
    HsMultikey::decode(&multikey.public_key_multibase)
        .map(|m| m.key)
        .map_err(|e| Error::InvalidMultikey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use actpub_httpsig::Ed25519SigningKey;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn publish_then_decode_round_trips_an_ed25519_key() {
        let signing = Ed25519SigningKey::generate().unwrap();
        let public = signing.public_key();

        let key_id: Url = "https://example.com/users/alice#ed25519-key"
            .parse()
            .unwrap();
        let controller: Url = "https://example.com/users/alice".parse().unwrap();
        let block = publish_ed25519(&public, key_id.clone(), controller.clone());

        assert_eq!(block.id, key_id);
        assert_eq!(block.controller, controller);
        assert_eq!(block.kind, AsMultikey::TYPE);
        assert!(
            block.public_key_multibase.starts_with("z6Mk"),
            "Ed25519 multikey must begin with z6Mk, got {}",
            block.public_key_multibase,
        );

        let decoded = decode_ed25519(&block).unwrap();
        assert_eq!(decoded, public);
    }

    #[test]
    fn decode_rejects_garbage_multibase() {
        let block = AsMultikey::new(
            "https://example.com/users/alice#bad".parse().unwrap(),
            "https://example.com/users/alice".parse().unwrap(),
            "this is not multibase",
        );
        let err = decode_ed25519(&block).expect_err("garbage must not decode");
        assert!(matches!(err, Error::InvalidMultikey(_)));
    }

    #[test]
    fn decode_rejects_non_ed25519_codec() {
        // A made-up RSA multikey (`zNot…`) — the codec check inside
        // `actpub_httpsig::Multikey::decode` MUST reject anything that
        // is not Ed25519's `0xed`.
        let block = AsMultikey::new(
            "https://example.com/users/alice#rsa".parse().unwrap(),
            "https://example.com/users/alice".parse().unwrap(),
            "z3uAxMxs",
        );
        let err = decode_ed25519(&block).expect_err("non-Ed25519 codec must be rejected");
        assert!(matches!(err, Error::InvalidMultikey(_)));
    }
}
