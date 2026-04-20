//! `NodeInfo` schema types (2.0 / 2.1).
//!
//! See [http://nodeinfo.diaspora.software/](http://nodeinfo.diaspora.software/)
//! for the canonical JSON Schemas. All enum values are drawn directly from
//! the published schemas; unknown values round-trip losslessly through the
//! `Other(String)` variants so the crate can interoperate with forward-
//! compatible servers and third-party extensions.

use serde::{Deserialize, Serialize};
use url::Url;

/// The `NodeInfo` schema version this document conforms to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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
/// The ten named variants are the exact `protocols` enumeration of the
/// [NodeInfo 2.1 schema][schema]; unknown values (including community
/// extensions such as `matrix` or `bluesky` used by bridges) round-trip
/// losslessly through [`Self::Other`].
///
/// [schema]: http://nodeinfo.diaspora.software/ns/schema/2.1
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Protocol {
    /// The W3C `ActivityPub` protocol.
    ActivityPub,
    /// Buddycloud federation.
    Buddycloud,
    /// Distributed Friendika Network.
    Dfrn,
    /// Diaspora.
    Diaspora,
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
    /// An unrecognised protocol identifier, preserved verbatim.
    ///
    /// Common non-schema values seen in the wild include `matrix`,
    /// `bluesky`, `gnusocial`, and `nostr`. All are preserved through this
    /// fallback variant.
    #[serde(untagged)]
    Other(String),
}

/// An inbound bridge service defined in `NodeInfo`.
///
/// Enumeration matches the `inbound` values from the `services` definition
/// in the [NodeInfo 2.1 schema][schema].
///
/// [schema]: http://nodeinfo.diaspora.software/ns/schema/2.1
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
    /// An unrecognised service identifier, preserved verbatim.
    #[serde(untagged)]
    Other(String),
}

/// An outbound bridge service defined in `NodeInfo`.
///
/// Enumeration matches the `outbound` values from the `services` definition
/// in the [NodeInfo 2.1 schema][schema].
///
/// [schema]: http://nodeinfo.diaspora.software/ns/schema/2.1
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
    /// Libertree.
    Libertree,
    /// `LinkedIn`.
    LinkedIn,
    /// `LiveJournal`.
    LiveJournal,
    /// `MediaGoblin`.
    MediaGoblin,
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
///
/// Per the `NodeInfo` schema, both `inbound` and `outbound` are required
/// arrays (they may be empty).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Services {
    /// Inbound services.
    #[serde(default)]
    pub inbound: Vec<InboundService>,

    /// Outbound services.
    #[serde(default)]
    pub outbound: Vec<OutboundService>,
}

impl Services {
    /// Constructs a [`Services`] block.
    #[must_use]
    pub const fn new(inbound: Vec<InboundService>, outbound: Vec<OutboundService>) -> Self {
        Self { inbound, outbound }
    }
}

/// Metadata about the software powering a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Software {
    /// Canonical software name (e.g. `mastodon`, `lemmy`, `mitra`).
    ///
    /// Per `NodeInfo` 2.0/2.1 schemas the name must match a strict regex
    /// (`^[a-z0-9-]+$`), but this crate preserves the raw string to
    /// interoperate with the relaxed FEP-0151 profile.
    pub name: String,

    /// Version string.
    pub version: String,

    /// Repository URL (`NodeInfo` 2.1 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<Url>,

    /// Homepage URL (`NodeInfo` 2.1 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

    /// Sets the repository URL and returns `self` for chaining.
    #[must_use]
    pub fn with_repository(mut self, repository: Url) -> Self {
        self.repository = Some(repository);
        self
    }

    /// Sets the homepage URL and returns `self` for chaining.
    #[must_use]
    pub fn with_homepage(mut self, homepage: Url) -> Self {
        self.homepage = Some(homepage);
        self
    }
}

/// Per-user activity counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserCount {
    /// Total registered users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,

    /// Users active in the last 180 days.
    #[serde(
        rename = "activeHalfyear",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_halfyear: Option<u64>,

    /// Users active in the last 30 days.
    #[serde(
        rename = "activeMonth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_month: Option<u64>,
}

impl UserCount {
    /// Constructs a [`UserCount`] from its components.
    #[must_use]
    pub const fn new(
        total: Option<u64>,
        active_halfyear: Option<u64>,
        active_month: Option<u64>,
    ) -> Self {
        Self {
            total,
            active_halfyear,
            active_month,
        }
    }

    /// Sets the total registered-user count and returns `self`.
    #[must_use]
    pub const fn with_total(mut self, total: u64) -> Self {
        self.total = Some(total);
        self
    }
}

/// Aggregate server usage statistics.
///
/// Per the `NodeInfo` schema the `users` field is required; the other fields
/// are optional but conventionally reported by large instances.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Usage {
    /// Per-user counts (required field; may contain all `None` values if
    /// the server chooses not to disclose them).
    #[serde(default)]
    pub users: UserCount,

    /// Total number of posts authored by local users.
    #[serde(
        rename = "localPosts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub local_posts: Option<u64>,

    /// Total number of comments authored by local users.
    #[serde(
        rename = "localComments",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub local_comments: Option<u64>,
}

impl Usage {
    /// Constructs a [`Usage`] with only the required `users` field set.
    #[must_use]
    pub const fn new(users: UserCount) -> Self {
        Self {
            users,
            local_posts: None,
            local_comments: None,
        }
    }

    /// Sets the total number of posts authored by local users.
    #[must_use]
    pub const fn with_local_posts(mut self, posts: u64) -> Self {
        self.local_posts = Some(posts);
        self
    }

    /// Sets the total number of comments authored by local users.
    #[must_use]
    pub const fn with_local_comments(mut self, comments: u64) -> Self {
        self.local_comments = Some(comments);
        self
    }
}

/// A `NodeInfo` 2.0 / 2.1 document.
///
/// All seven top-level fields required by the `NodeInfo` 2.1 schema are
/// always present on the wire — empty arrays and empty `metadata` objects
/// are emitted rather than omitted, to keep the document strictly
/// conformant under both 2.0 and 2.1.
///
/// Fields that are specific to 2.1 (e.g. [`Software::repository`]) remain
/// `Option`-typed and are omitted when unset, so a document built with
/// [`Version::V2_0`] still validates under the 2.0 schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NodeInfo {
    /// Schema version this document conforms to.
    pub version: Version,

    /// Software metadata.
    pub software: Software,

    /// Federation protocols implemented by this server.
    #[serde(default)]
    pub protocols: Vec<Protocol>,

    /// Bridge services (always emitted, even when both arrays are empty).
    #[serde(default)]
    pub services: Services,

    /// Whether the server accepts new registrations.
    #[serde(rename = "openRegistrations")]
    pub open_registrations: bool,

    /// Aggregate usage statistics.
    #[serde(default)]
    pub usage: Usage,

    /// Arbitrary software-specific metadata (always emitted, defaulting to
    /// an empty object per the schema).
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
}

fn default_metadata() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
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
                metadata: default_metadata(),
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
    /// wire.
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
    fn every_schema_protocol_roundtrips() {
        // Covers the exact 10-value `protocols` enumeration of the
        // NodeInfo 2.1 schema. A regression here means either a schema
        // drift (an enum variant was renamed/removed) or a serde rename
        // typo on our side.
        for (canonical, expected) in [
            ("activitypub", Protocol::ActivityPub),
            ("buddycloud", Protocol::Buddycloud),
            ("dfrn", Protocol::Dfrn),
            ("diaspora", Protocol::Diaspora),
            ("libertree", Protocol::Libertree),
            ("ostatus", Protocol::OStatus),
            ("pumpio", Protocol::PumpIo),
            ("tent", Protocol::Tent),
            ("xmpp", Protocol::Xmpp),
            ("zot", Protocol::Zot),
        ] {
            let p: Protocol =
                serde_json::from_value(json!(canonical)).expect("known value must deserialise");
            assert_eq!(
                p, expected,
                "{canonical} should deserialise to {expected:?}"
            );

            let back = serde_json::to_value(&p).expect("known value must serialise");
            assert_eq!(
                back,
                json!(canonical),
                "{expected:?} should serialise back to {canonical}",
            );
        }
    }

    #[test]
    fn protocol_preserves_unknown_variant() {
        // Matrix, Bluesky, Nostr and similar community extensions are not
        // part of the NodeInfo schema but appear in production documents;
        // they must be preserved verbatim through `Other(String)`.
        let p: Protocol =
            serde_json::from_value(json!("bluesky")).expect("unknown value must deserialise");
        assert_eq!(p, Protocol::Other("bluesky".to_owned()));

        let back = serde_json::to_value(&p).expect("Other variant must serialise");
        assert_eq!(back, json!("bluesky"));
    }

    #[test]
    fn outbound_service_mediagoblin_roundtrips() {
        let s: OutboundService = serde_json::from_value(json!("mediagoblin")).unwrap();
        assert_eq!(s, OutboundService::MediaGoblin);
        let back = serde_json::to_value(&s).unwrap();
        assert_eq!(back, json!("mediagoblin"));
    }

    #[test]
    fn mastodon_style_nodeinfo_roundtrips_verbatim() {
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

        let info: NodeInfo = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(info.version, Version::V2_1);
        assert_eq!(info.software.name, "mastodon");
        assert_eq!(info.protocols, vec![Protocol::ActivityPub]);
        assert_eq!(info.usage.users.total, Some(1234));
        assert!(info.open_registrations);

        let back = serde_json::to_value(&info).unwrap();
        assert_eq!(back, raw, "roundtrip must preserve verbatim JSON");
    }

    #[test]
    fn builder_always_emits_required_fields() {
        let info = NodeInfo::builder(Version::V2_0, Software::new("test-server", "0.1.0"))
            .protocol(Protocol::ActivityPub)
            .open_registrations(false)
            .build();

        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["version"], json!("2.0"));
        assert_eq!(v["protocols"], json!(["activitypub"]));
        assert_eq!(v["services"], json!({"inbound": [], "outbound": []}));
        assert_eq!(v["openRegistrations"], json!(false));
        assert_eq!(v["metadata"], json!({}));
        // `usage.users` must be present even when empty
        assert!(v["usage"].get("users").is_some());
    }

    #[test]
    fn metadata_entry_builds_object() {
        let info = NodeInfo::builder(Version::V2_1, Software::new("my-server", "1.0.0"))
            .metadata_entry("supports_feps", json!(["521a", "8b32"]))
            .build();

        assert_eq!(info.metadata["supports_feps"], json!(["521a", "8b32"]));
    }

    #[test]
    fn software_builder_sets_optional_fields() {
        let sw = Software::new("mastodon", "4.5.0")
            .with_repository("https://github.com/mastodon/mastodon".parse().unwrap())
            .with_homepage("https://joinmastodon.org/".parse().unwrap());

        let v = serde_json::to_value(&sw).unwrap();
        assert_eq!(
            v["repository"],
            json!("https://github.com/mastodon/mastodon")
        );
        assert_eq!(v["homepage"], json!("https://joinmastodon.org/"));
    }
}
