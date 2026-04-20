//! The `NodeInfo` discovery document served at `/.well-known/nodeinfo`.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::schema::Version;

/// Common prefix shared by all `NodeInfo` schema `rel` URIs.
///
/// Specific versions are formed by appending `"2.0"`, `"2.1"`, etc., giving
/// URIs such as `http://nodeinfo.diaspora.software/ns/schema/2.1`.
pub const SCHEMA_REL_PREFIX: &str = "http://nodeinfo.diaspora.software/ns/schema/";

/// A `NodeInfo` discovery document, served at `/.well-known/nodeinfo`.
///
/// Points clients at one or more versioned `NodeInfo` schema documents. At
/// least one link should be present; clients typically pick the most
/// recent version they support.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Discovery {
    /// Links to specific schema documents.
    pub links: Vec<DiscoveryLink>,
}

impl Discovery {
    /// Creates a discovery document advertising a single `NodeInfo` endpoint.
    ///
    /// # Examples
    ///
    /// ```
    /// # use actpub_nodeinfo::{Discovery, Version};
    /// let disco = Discovery::for_version(
    ///     Version::V2_1,
    ///     "https://example.com/nodeinfo/2.1".parse().unwrap(),
    /// );
    /// assert_eq!(disco.links.len(), 1);
    /// ```
    #[must_use]
    pub fn for_version(version: Version, href: Url) -> Self {
        Self {
            links: vec![DiscoveryLink::new(version, href)],
        }
    }

    /// Appends another version endpoint and returns `self` for chaining.
    #[must_use]
    pub fn with_version(mut self, version: Version, href: Url) -> Self {
        self.links.push(DiscoveryLink::new(version, href));
        self
    }

    /// Returns the link with the highest advertised `NodeInfo` version this
    /// crate understands.
    ///
    /// Prefers 2.1 over 2.0; returns `None` if no recognised schema rel is
    /// present.
    #[must_use]
    pub fn preferred_link(&self) -> Option<&DiscoveryLink> {
        self.find_link(Version::V2_1)
            .or_else(|| self.find_link(Version::V2_0))
    }

    /// Returns the link matching the given version, if any.
    #[must_use]
    pub fn find_link(&self, version: Version) -> Option<&DiscoveryLink> {
        self.links.iter().find(|l| l.rel == version.schema_uri())
    }
}

/// A single discovery link pointing at a specific schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DiscoveryLink {
    /// Schema relation URI (e.g. `http://nodeinfo.diaspora.software/ns/schema/2.1`).
    pub rel: String,

    /// URL of the concrete `NodeInfo` document for this version.
    pub href: Url,
}

impl DiscoveryLink {
    /// Constructs a link for a specific `NodeInfo` [`Version`].
    #[must_use]
    pub fn new(version: Version, href: Url) -> Self {
        Self {
            rel: version.schema_uri().to_owned(),
            href,
        }
    }

    /// Returns the [`Version`] this link advertises, if recognised.
    #[must_use]
    pub fn version(&self) -> Option<Version> {
        match self.rel.as_str() {
            s if s == Version::V2_1.schema_uri() => Some(Version::V2_1),
            s if s == Version::V2_0.schema_uri() => Some(Version::V2_0),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn discovery_roundtrips_mastodon_style() {
        let raw = json!({
            "links": [
                {
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
                    "href": "https://mastodon.social/nodeinfo/2.0"
                },
                {
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                    "href": "https://mastodon.social/nodeinfo/2.1"
                }
            ]
        });

        let d: Discovery = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(d.links.len(), 2);

        let preferred = d.preferred_link().unwrap();
        assert_eq!(preferred.version(), Some(Version::V2_1));

        let back = serde_json::to_value(&d).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn for_version_builds_single_link() {
        let d = Discovery::for_version(
            Version::V2_1,
            "https://example.com/nodeinfo/2.1".parse().unwrap(),
        );
        assert_eq!(d.links.len(), 1);
        assert_eq!(d.links[0].version(), Some(Version::V2_1));
    }

    #[test]
    fn discovery_link_version_is_none_for_unknown() {
        let link = DiscoveryLink::new(Version::V2_0, "https://example.com/ni/99".parse().unwrap());
        // Tamper with the rel to simulate an unknown schema URI.
        let mut unknown = link;
        unknown.rel = "http://example.com/schema/99".to_owned();
        assert_eq!(unknown.version(), None);
    }
}
