//! `NodeInfo` schema types (2.0 / 2.1).
//!
//! See [http://nodeinfo.diaspora.software/](http://nodeinfo.diaspora.software/)
//! for the canonical JSON Schemas.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

/// The `NodeInfo` schema version this document conforms to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Version {
    /// `NodeInfo` 2.0 — [schema](http://nodeinfo.diaspora.software/ns/schema/2.0).
    #[serde(rename = "2.0")]
    V2_0,

    /// `NodeInfo` 2.1 — [schema](http://nodeinfo.diaspora.software/ns/schema/2.1).
    #[serde(rename = "2.1")]
    V2_1,
}

impl Version {
    /// Returns the version as the lexical string used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2_0 => "2.0",
            Self::V2_1 => "2.1",
        }
    }

    /// Returns the full schema URI this version corresponds to, as emitted
    /// in the `rel` field of the `/.well-known/nodeinfo` discovery document.
    #[must_use]
    pub const fn schema_uri(self) -> &'static str {
        match self {
            Self::V2_0 => "http://nodeinfo.diaspora.software/ns/schema/2.0",
            Self::V2_1 => "http://nodeinfo.diaspora.software/ns/schema/2.1",
        }
    }
}

/// A federation protocol supported by a NodeInfo-described server.
///
/// The strings here are drawn from the `NodeInfo` 2.1 enum; unknown values
/// round-trip through [`Self::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Protocol {
    /// The W3C `ActivityPub` protocol.
    ActivityPub,
    /// Diaspora.
    Diaspora,
    /// `GNUSocial`.
    GnuSocial,
    /// Libertree.
    Libertree,
    /// `OStatus` (legacy).
    OStatus,
    /// Pump.io.
    PumpIo,
    /// Tent.
    Tent,
    /// XMPP with pub-sub.
    Xmpp,
    /// Zot.
    Zot,
    /// Matrix.
    Matrix,
    /// An unrecognised protocol identifier, preserved verbatim.
    #[serde(untagged)]
    Other(String),
}

/// An inbound bridge service defined in `NodeInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum InboundService {
    /// Atom 1.0 feed.
    #[serde(rename = "atom1.0")]
    Atom1_0,
    /// GNU Social.
    GnuSocial,
    /// IMAP.
    Imap,
    /// Pnut.
    Pnut,
    /// POP3.
    Pop3,
    /// Pump.io.
    PumpIo,
    /// RSS 2.0 feed.
    #[serde(rename = "rss2.0")]
    Rss2_0,
    /// Twitter.
    Twitter,
    /// Unknown service identifier.
    #[serde(untagged)]
    Other(String),
}

/// An outbound bridge service defined in `NodeInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundService {
    /// Atom 1.0 feed.
    #[serde(rename = "atom1.0")]
    Atom1_0,
    /// Blogger.
    Blogger,
    /// `BuddyCloud`.
    Buddycloud,
    /// Diaspora.
    Diaspora,
    /// Dreamwidth.
    Dreamwidth,
    /// Drupal.
    Drupal,
    /// Facebook.
    Facebook,
    /// Friendica.
    Friendica,
    /// GNU Social.
    GnuSocial,
    /// Google.
    Google,
    /// `InsaneJournal`.
    InsaneJournal,
    /// `LiveJournal`.
    LiveJournal,
    /// `LibertyHub`.
    Libertree,
    /// `LinkedIn`.
    LinkedIn,
    /// Lotus.
    LotusNotes,
    /// `MySpace`.
    MySpace,
    /// Pinterest.
    Pinterest,
    /// Pnut.
    Pnut,
    /// Posterous.
    Posterous,
    /// Pump.io.
    PumpIo,
    /// Redmatrix (legacy).
    RedMatrix,
    /// RSS 2.0 feed.
    #[serde(rename = "rss2.0")]
    Rss2_0,
    /// SMTP.
    Smtp,
    /// Tent.
    Tent,
    /// Tumblr.
    Tumblr,
    /// Twitter.
    Twitter,
    /// `WordPress`.
    WordPress,
    /// Xmpp.
    Xmpp,
    /// An unrecognised service identifier, preserved verbatim.
    #[serde(untagged)]
    Other(String),
}

/// Set of inbound/outbound bridge services.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Services {
    /// Inbound services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<InboundService>,

    /// Outbound services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound: Vec<OutboundService>,
}

/// Metadata about the software powering a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Software {
    /// Canonical software name (e.g. `mastodon`, `lemmy`, `mitra`).
    ///
    /// Per `NodeInfo` 2.0/2.1 schemas the name must match a strict regex,
    /// but this crate preserves the raw string to interoperate with the
    /// relaxed FEP-0151 profile.
    pub name: String,

    /// Version string. Required, but may be an empty string.
    pub version: String,

    /// Repository URL (`NodeInfo` 2.1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<Url>,

    /// Homepage URL (`NodeInfo` 2.1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<Url>,
}

impl Software {
    /// Constructs a minimal [`Software`] description.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            repository: None,
            homepage: None,
        }
    }
}

/// Per-user activity counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserCount {
    /// Total registered users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,

    /// Users active in the last 180 days.
    #[serde(rename = "activeHalfyear", skip_serializing_if = "Option::is_none")]
    pub active_halfyear: Option<u64>,

    /// Users active in the last 30 days.
    #[serde(rename = "activeMonth", skip_serializing_if = "Option::is_none")]
    pub active_month: Option<u64>,
}

/// Aggregate server usage statistics.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Per-user counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<UserCount>,

    /// Total number of posts authored by local users.
    #[serde(rename = "localPosts", skip_serializing_if = "Option::is_none")]
    pub local_posts: Option<u64>,

    /// Total number of comments authored by local users.
    #[serde(rename = "localComments", skip_serializing_if = "Option::is_none")]
    pub local_comments: Option<u64>,
}

/// A `NodeInfo` 2.0 / 2.1 document.
///
/// Unified container for both versions — fields that exist only in 2.1
/// (e.g. [`Software::repository`]) are `Option`-typed and omitted on the
/// wire when unset, keeping the document conformant under both schemas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Schema version this document conforms to.
    pub version: Version,

    /// Software metadata.
    pub software: Software,

    /// Federation protocols implemented by this server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<Protocol>,

    /// Bridge services, if any.
    #[serde(default, skip_serializing_if = "skip_empty_services")]
    pub services: Services,

    /// Whether the server accepts new registrations.
    #[serde(rename = "openRegistrations")]
    pub open_registrations: bool,

    /// Aggregate usage statistics.
    #[serde(default)]
    pub usage: Usage,

    /// Arbitrary software-specific metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

const fn skip_empty_services(s: &Services) -> bool {
    s.inbound.is_empty() && s.outbound.is_empty()
}

impl NodeInfo {
    /// Returns a new builder at the given schema version.
    #[must_use]
    pub fn builder(version: Version, software: Software) -> NodeInfoBuilder {
        NodeInfoBuilder {
            inner: Self {
                version,
                software,
                protocols: Vec::new(),
                services: Services::default(),
                open_registrations: false,
                usage: Usage::default(),
                metadata: serde_json::Value::Null,
            },
        }
    }
}

/// Builder for [`NodeInfo`] produced by [`NodeInfo::builder`].
#[derive(Debug)]
pub struct NodeInfoBuilder {
    inner: NodeInfo,
}

impl NodeInfoBuilder {
    /// Appends a supported protocol.
    #[must_use]
    pub fn protocol(mut self, p: Protocol) -> Self {
        self.inner.protocols.push(p);
        self
    }

    /// Replaces all protocols.
    #[must_use]
    pub fn protocols(mut self, ps: Vec<Protocol>) -> Self {
        self.inner.protocols = ps;
        self
    }

    /// Replaces the services block.
    #[must_use]
    pub fn services(mut self, services: Services) -> Self {
        self.inner.services = services;
        self
    }

    /// Sets the `openRegistrations` flag.
    #[must_use]
    pub const fn open_registrations(mut self, open: bool) -> Self {
        self.inner.open_registrations = open;
        self
    }

    /// Sets the usage block.
    #[must_use]
    pub const fn usage(mut self, usage: Usage) -> Self {
        self.inner.usage = usage;
        self
    }

    /// Attaches arbitrary metadata.
    #[must_use]
    pub fn metadata<V: Into<serde_json::Value>>(mut self, v: V) -> Self {
        self.inner.metadata = v.into();
        self
    }

    /// Attaches a single typed metadata entry, producing an object on the
    /// wire. Useful when the caller wants to emit a `metadata` object with
    /// named keys.
    #[must_use]
    pub fn metadata_entry(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        let mut map = match self.inner.metadata {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        map.insert(key.into(), value.into());
        self.inner.metadata = serde_json::Value::Object(map);
        self
    }

    /// Finalises the [`NodeInfo`].
    #[must_use]
    pub fn build(self) -> NodeInfo {
        self.inner
    }
}

// Hook so that `#[serde(default)]` on `metadata` accepts `null`.
#[allow(dead_code, reason = "used by serde via type defaults")]
const fn metadata_default() -> serde_json::Value {
    serde_json::Value::Null
}

/// Compact helper for inserting multiple metadata entries.
#[must_use]
pub(crate) fn metadata_from<I>(iter: I) -> serde_json::Value
where
    I: IntoIterator<Item = (String, serde_json::Value)>,
{
    let map: BTreeMap<String, serde_json::Value> = iter.into_iter().collect();
    serde_json::to_value(map).unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn version_roundtrips() {
        let v = Version::V2_1;
        assert_eq!(v.as_str(), "2.1");
        assert_eq!(
            v.schema_uri(),
            "http://nodeinfo.diaspora.software/ns/schema/2.1"
        );
        let j = serde_json::to_value(v).unwrap();
        assert_eq!(j, json!("2.1"));
    }

    #[test]
    fn protocol_roundtrips_known() {
        let p: Protocol = serde_json::from_value(json!("activitypub")).unwrap();
        assert_eq!(p, Protocol::ActivityPub);
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back, json!("activitypub"));
    }

    #[test]
    fn protocol_preserves_unknown() {
        let p: Protocol = serde_json::from_value(json!("bluesky")).unwrap();
        assert_eq!(p, Protocol::Other("bluesky".to_owned()));
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back, json!("bluesky"));
    }

    #[test]
    fn mastodon_style_nodeinfo_roundtrips() {
        let raw = json!({
            "version": "2.1",
            "software": {
                "name": "mastodon",
                "version": "4.5.0",
                "repository": "https://github.com/mastodon/mastodon",
                "homepage": "https://joinmastodon.org/"
            },
            "protocols": ["activitypub"],
            "services": {
                "inbound": [],
                "outbound": []
            },
            "openRegistrations": true,
            "usage": {
                "users": {
                    "total": 1234,
                    "activeHalfyear": 400,
                    "activeMonth": 50
                },
                "localPosts": 9999,
                "localComments": 8888
            },
            "metadata": {}
        });

        let info: NodeInfo = serde_json::from_value(raw).unwrap();
        assert_eq!(info.version, Version::V2_1);
        assert_eq!(info.software.name, "mastodon");
        assert_eq!(info.protocols, vec![Protocol::ActivityPub]);
        assert_eq!(info.usage.users.unwrap().total, Some(1234));
        assert!(info.open_registrations);

        let back = serde_json::to_value(&info).unwrap();
        // `services` with two empty arrays should round-trip through the skip logic.
        assert_eq!(back["software"]["name"], "mastodon");
        assert_eq!(back["protocols"], json!(["activitypub"]));
    }

    #[test]
    fn builder_produces_minimal_valid_document() {
        let info = NodeInfo::builder(Version::V2_0, Software::new("test-server", "0.1.0"))
            .protocol(Protocol::ActivityPub)
            .open_registrations(false)
            .build();

        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["version"], json!("2.0"));
        assert_eq!(v["openRegistrations"], json!(false));
        assert!(v.get("services").is_none());
    }

    #[test]
    fn metadata_entry_builds_object() {
        let info = NodeInfo::builder(Version::V2_1, Software::new("my-server", "1.0.0"))
            .metadata_entry("supports_feps", json!(["521a", "8b32"]))
            .build();

        assert_eq!(info.metadata["supports_feps"], json!(["521a", "8b32"]));
    }
}
