//! Activity Streams 2.0 [`Link`] object.
//!
//! A `Link` is an indirect reference to a resource, providing metadata about
//! that resource such as its language, MIME type, dimensions, and relation.
//! In AS 2.0 a [`Link`] is *disjoint* from an
//! [`Object`](crate::Object) — the two base types never overlap on the same
//! node. Accordingly this module defines [`Link`] as its own strict struct
//! rather than reusing the universal [`Object`](crate::Object) container.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::kind;
use crate::value::{HasId, OneOrMany};

/// An Activity Streams 2.0 [`Link`](https://www.w3.org/TR/activitystreams-vocabulary/#dfn-link).
///
/// The `kind` field distinguishes link subtypes such as
/// [`Mention`](kind::link::MENTION) and [`Hashtag`](kind::link::HASHTAG).
///
/// # Examples
///
/// ```
/// # use actpub_activitystreams::Link;
/// # use url::Url;
/// let link = Link::new(Url::parse("https://example/note/1").unwrap());
/// let json = serde_json::to_string(&link).unwrap();
/// assert!(json.contains(r#""type":"Link""#));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    /// Optional identifier for this link object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,

    /// Type of this link. Defaults to [`"Link"`](kind::core::LINK).
    #[serde(rename = "type", default = "Link::default_kind")]
    pub kind: OneOrMany<String>,

    /// The target URL referenced by this link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<Url>,

    /// Link relation types (RFC 5988).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel: Option<OneOrMany<String>>,

    /// MIME type of the referenced resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Plain-text display name for the link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Localized display names keyed by BCP-47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_map: Option<BTreeMap<String, String>>,

    /// BCP-47 language tag describing the language of the referenced resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hreflang: Option<String>,

    /// Display height for media links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,

    /// Display width for media links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u64>,

    /// Preview resource associated with the link target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Box<crate::object::ObjectRef>>,

    /// Additional or extension properties preserved verbatim across
    /// (de)serialization.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Link {
    fn default_kind() -> OneOrMany<String> {
        OneOrMany::one(kind::core::LINK.to_owned())
    }

    /// Creates a new bare [`Link`] pointing at `href`.
    #[must_use]
    pub fn new(href: Url) -> Self {
        Self {
            id: None,
            kind: Self::default_kind(),
            href: Some(href),
            rel: None,
            media_type: None,
            name: None,
            name_map: None,
            hreflang: None,
            height: None,
            width: None,
            preview: None,
            extra: BTreeMap::new(),
        }
    }

    /// Creates a [`Mention`](kind::link::MENTION) link pointing to an actor.
    #[must_use]
    pub fn mention(href: Url) -> Self {
        let mut link = Self::new(href);
        link.kind = OneOrMany::one(kind::link::MENTION.to_owned());
        link
    }

    /// Creates a [`Hashtag`](kind::link::HASHTAG) link with the given name.
    #[must_use]
    pub fn hashtag(href: Url, name: impl Into<String>) -> Self {
        let mut link = Self::new(href);
        link.kind = OneOrMany::one(kind::link::HASHTAG.to_owned());
        link.name = Some(name.into());
        link
    }

    /// Returns `true` if this link declares the given type name.
    #[must_use]
    pub fn is_kind(&self, kind: &str) -> bool {
        self.kind.iter().any(|k| k == kind)
    }
}

impl HasId for Link {
    fn id(&self) -> Option<&Url> {
        self.id.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn link_defaults_type_to_link() {
        let link = Link::new(Url::parse("https://example/x").unwrap());
        let v = serde_json::to_value(&link).unwrap();
        assert_eq!(v["type"], json!("Link"));
    }

    #[test]
    fn mention_sets_mention_type() {
        let link = Link::mention(Url::parse("https://example/u/alice").unwrap());
        assert!(link.is_kind(kind::link::MENTION));
    }

    #[test]
    fn mastodon_style_mention_roundtrips() {
        let raw = json!({
            "type": "Mention",
            "href": "https://mastodon.social/@alice",
            "name": "@alice@mastodon.social"
        });
        let link: Link = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(link.name.as_deref(), Some("@alice@mastodon.social"));
        let back = serde_json::to_value(&link).unwrap();
        assert_eq!(back, raw);
    }
}
