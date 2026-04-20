//! [FEP-521a Multikey][fep521a] verification-method type.
//!
//! FEP-521a defines a uniform way to publish per-actor verification
//! keys via the W3C [Controlled Identifiers][cid] vocabulary. Each
//! `assertionMethod` (or `authentication`) entry is either a bare URL
//! reference to a remote key document or an inlined [`Multikey`] block
//! carrying a `multibase`-encoded public key.
//!
//! The `publicKeyMultibase` payload uses the `multicodec` envelope to
//! describe the key type:
//!
//! | Codec prefix (varint) | Algorithm |
//! |-----------------------|-----------|
//! | `0xed01`              | Ed25519   |
//! | `0x1200`              | secp256r1 (P-256) |
//! | `0x1205`              | RSA       |
//!
//! This crate models the wire form only. Encoding/decoding the
//! multibase payload back to raw key bytes is handled by
//! `actpub-httpsig::Multikey`, keeping cryptographic primitives in the
//! crypto crate.
//!
//! [fep521a]: https://codeberg.org/fediverse/fep/src/branch/main/fep/521a/fep-521a.md
//! [cid]: https://www.w3.org/TR/cid-1.0/

use serde::{Deserialize, Serialize};
use url::Url;

use crate::value::UrlOr;

/// FEP-521a `Multikey` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Multikey {
    /// Globally unique identifier for this key, typically the actor URL
    /// suffixed with a `#key-N` fragment.
    pub id: Url,

    /// Type discriminator. MUST be `"Multikey"` per FEP-521a §3.
    #[serde(rename = "type")]
    pub kind: String,

    /// Actor that owns and rotates this key.
    pub controller: Url,

    /// Multibase-encoded multicodec public key payload (e.g.
    /// `z6Mk…` for Ed25519, `zDn…` for P-256).
    pub public_key_multibase: String,
}

impl Multikey {
    /// The fixed type discriminator value mandated by FEP-521a.
    pub const TYPE: &'static str = "Multikey";

    /// Builds a [`Multikey`] with the canonical `"Multikey"` type.
    #[must_use]
    pub fn new(id: Url, controller: Url, public_key_multibase: impl Into<String>) -> Self {
        Self {
            id,
            kind: Self::TYPE.to_owned(),
            controller,
            public_key_multibase: public_key_multibase.into(),
        }
    }
}

/// A reference to a verification method, either as a bare URL or an
/// inlined [`Multikey`] document.
///
/// This is the value type shared by `ActivityPub` `assertionMethod` and
/// `authentication` arrays per FEP-521a §4 and the W3C Controlled
/// Identifiers spec.
pub type AssertionMethod = UrlOr<Multikey>;

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn inline_multikey_roundtrips() {
        let raw = json!({
            "id": "https://example.com/users/alice#ed25519-key",
            "type": "Multikey",
            "controller": "https://example.com/users/alice",
            "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
        });
        let key: Multikey = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(key.kind, Multikey::TYPE);
        assert!(key.public_key_multibase.starts_with('z'));
        let back = serde_json::to_value(&key).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn assertion_method_accepts_bare_url_form() {
        let raw = json!("https://example.com/users/alice#main-key");
        let am: AssertionMethod = serde_json::from_value(raw.clone()).unwrap();
        assert!(matches!(am, AssertionMethod::Url(_)));
        let back = serde_json::to_value(&am).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn assertion_method_accepts_inlined_multikey_form() {
        let raw = json!({
            "id": "https://example.com/users/alice#main-key",
            "type": "Multikey",
            "controller": "https://example.com/users/alice",
            "publicKeyMultibase": "z6Mk…"
        });
        let am: AssertionMethod = serde_json::from_value(raw.clone()).unwrap();
        assert!(matches!(am, AssertionMethod::Object(_)));
        let back = serde_json::to_value(&am).unwrap();
        assert_eq!(back, raw);
    }
}
