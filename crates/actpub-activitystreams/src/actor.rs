//! `ActivityPub` actor extension types.
//!
//! `ActivityPub` augments AS 2.0 actor objects (`Person`, `Group`,
//! `Service`, `Application`, `Organization`) with cryptographic and
//! transport metadata that the bare AS 2.0 vocabulary does not define:
//!
//! - [`PublicKey`] — the W3C Security v1 `publicKey` block embedded on
//!   every Mastodon-style actor, used by HTTP Signature verification
//!   to look up the signing key by `keyId`.
//! - [`Endpoints`] — the `ActivityPub` §4.1 `endpoints` block listing the
//!   actor's shared inbox and (optionally) Linked Data Signatures or
//!   client-to-server OAuth endpoints.
//!
//! These are modelled as small focused structs rather than free-form
//! JSON because every Fediverse implementation reads and writes the
//! same fields.

use serde::{Deserialize, Serialize};
use url::Url;

/// W3C Security v1 `publicKey` block.
///
/// Mastodon, Pleroma, Misskey, Lemmy and every other Cavage-era
/// implementation expose actors with this exact shape:
///
/// ```json
/// "publicKey": {
///   "id":          "https://example.com/users/alice#main-key",
///   "owner":       "https://example.com/users/alice",
///   "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIB…"
/// }
/// ```
///
/// The PEM payload is an X.509 `SubjectPublicKeyInfo` (PKIX) document and
/// is the canonical way to publish an actor's RSA-2048 (or, more
/// recently, Ed25519) verification key for HTTP Signatures. Modern FEP
/// implementations additionally publish [`Multikey`](crate::Multikey)
/// entries via `assertionMethod`, but `publicKey` remains the
/// must-have legacy field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    /// Globally unique identifier for this key, typically the actor URL
    /// suffixed with a `#fragment` (e.g. `#main-key`).
    pub id: Url,

    /// The actor that owns and rotates this key. MUST equal the actor's
    /// `id` for the receiver to accept signatures made with it.
    pub owner: Url,

    /// PKIX `SubjectPublicKeyInfo` PEM, including the
    /// `-----BEGIN PUBLIC KEY-----` armour.
    pub public_key_pem: String,
}

impl PublicKey {
    /// Builds a [`PublicKey`] from its three fields.
    #[must_use]
    pub fn new(id: Url, owner: Url, public_key_pem: impl Into<String>) -> Self {
        Self {
            id,
            owner,
            public_key_pem: public_key_pem.into(),
        }
    }
}

/// `ActivityPub` §4.1 `endpoints` block.
///
/// Servers publish auxiliary URLs through this object. The most widely
/// used field by far is [`shared_inbox`](Self::shared_inbox), which
/// lets remote senders deliver one POST per server instead of one POST
/// per follower. The OAuth fields support C2S clients (rare in
/// production today). The `proxyUrl` and `provideClientKey` /
/// `signClientKey` fields are reserved for Linked Data Signatures and
/// remain in the spec for forward-compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    /// Server-wide inbox into which any actor on this server can be
    /// addressed. Receiving servers MAY deliver a single POST here in
    /// place of N per-follower deliveries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_inbox: Option<Url>,

    /// Endpoint where a remote client can obtain an OAuth 2.0
    /// authorization code on behalf of an actor on this server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_authorization_endpoint: Option<Url>,

    /// Endpoint where a remote client can exchange an OAuth 2.0
    /// authorization code for a bearer token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_token_endpoint: Option<Url>,

    /// LD-Signatures: endpoint that supplies a fresh client key for
    /// HTTP-signature exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provide_client_key: Option<Url>,

    /// LD-Signatures: endpoint that signs an arbitrary client-supplied
    /// key on behalf of this actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_client_key: Option<Url>,

    /// Generic proxy endpoint for fetching authenticated remote
    /// resources, defined for forward-compatibility with
    /// `ActivityPub` §7.1.2 client-to-server semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<Url>,
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn public_key_roundtrips_in_mastodon_shape() {
        let raw = json!({
            "id": "https://mastodon.social/users/alice#main-key",
            "owner": "https://mastodon.social/users/alice",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIB…\n-----END PUBLIC KEY-----\n"
        });
        let key: PublicKey = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(key.owner.as_str(), "https://mastodon.social/users/alice");
        let back = serde_json::to_value(&key).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn endpoints_with_only_shared_inbox_omits_other_fields() {
        let endpoints = Endpoints {
            shared_inbox: Some(Url::parse("https://mastodon.social/inbox").unwrap()),
            ..Endpoints::default()
        };
        let v = serde_json::to_value(&endpoints).unwrap();
        assert_eq!(v, json!({ "sharedInbox": "https://mastodon.social/inbox" }));
    }

    #[test]
    fn endpoints_full_roundtrip() {
        let raw = json!({
            "sharedInbox": "https://example.com/inbox",
            "oauthAuthorizationEndpoint": "https://example.com/oauth/authorize",
            "oauthTokenEndpoint": "https://example.com/oauth/token"
        });
        let endpoints: Endpoints = serde_json::from_value(raw.clone()).unwrap();
        assert!(endpoints.shared_inbox.is_some());
        assert!(endpoints.oauth_authorization_endpoint.is_some());
        let back = serde_json::to_value(&endpoints).unwrap();
        assert_eq!(back, raw);
    }
}
