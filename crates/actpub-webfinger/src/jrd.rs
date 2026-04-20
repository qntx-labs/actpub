//! JSON Resource Descriptor (JRD) types as defined in
//! [RFC 7033 §4.4](https://datatracker.ietf.org/doc/html/rfc7033#section-4.4).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::rels;

/// A `WebFinger` JSON Resource Descriptor (JRD).
///
/// JRDs are emitted by the `/.well-known/webfinger` endpoint to describe a
/// resource identified by the `subject` field. Each JRD may declare
/// [`aliases`](Self::aliases) for the same resource, scalar
/// [`properties`](Self::properties) drawn from arbitrary URI schemes, and
/// a list of [`links`](Self::links) to related resources.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Jrd {
    /// The URI of the resource described by this JRD.
    pub subject: String,

    /// Alternative URIs that also identify the subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,

    /// Scalar properties keyed by URI. Per RFC 7033 a property value may be
    /// either a string or JSON `null`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Option<String>>,

    /// Links describing related resources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<JrdLink>,
}

impl Jrd {
    /// Returns a new [`JrdBuilder`] initialised with the given subject.
    pub fn builder(subject: impl Into<String>) -> JrdBuilder {
        JrdBuilder {
            inner: Self {
                subject: subject.into(),
                ..Self::default()
            },
        }
    }

    /// Finds the first link with the given [`rel`](JrdLink::rel).
    #[must_use]
    pub fn find_link(&self, rel: &str) -> Option<&JrdLink> {
        self.links.iter().find(|l| l.rel == rel)
    }

    /// Returns the `ActivityPub` actor link for this subject.
    ///
    /// The canonical form is `rel="self"` with
    /// `type="application/activity+json"`. If no such link exists but one
    /// with the JSON-LD profile media type does, that is returned instead.
    #[must_use]
    pub fn activitypub_actor(&self) -> Option<&JrdLink> {
        self.links
            .iter()
            .find(|l| {
                l.rel == rels::SELF
                    && matches!(
                        l.media_type.as_deref(),
                        Some(mt) if mt == rels::MEDIA_TYPE_ACTIVITYPUB
                    )
            })
            .or_else(|| {
                self.links.iter().find(|l| {
                    l.rel == rels::SELF
                        && matches!(
                            l.media_type.as_deref(),
                            Some(mt) if mt.starts_with("application/ld+json")
                        )
                })
            })
    }
}

/// Builder for [`Jrd`] produced by [`Jrd::builder`].
#[derive(Debug)]
pub struct JrdBuilder {
    inner: Jrd,
}

impl JrdBuilder {
    /// Appends an alias URI.
    #[must_use]
    pub fn alias(mut self, alias: impl Into<String>) -> Self {
        self.inner.aliases.push(alias.into());
        self
    }

    /// Appends a property.
    #[must_use]
    pub fn property(mut self, key: impl Into<String>, value: Option<String>) -> Self {
        self.inner.properties.insert(key.into(), value);
        self
    }

    /// Appends a link.
    #[must_use]
    pub fn link(mut self, link: JrdLink) -> Self {
        self.inner.links.push(link);
        self
    }

    /// Finalises the [`Jrd`].
    #[must_use]
    pub fn build(self) -> Jrd {
        self.inner
    }
}

/// A link entry inside a [`Jrd`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JrdLink {
    /// Link relation (IANA registered name or URI).
    pub rel: String,

    /// Media type of the resource referenced by [`href`](Self::href).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// URI of the related resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<Url>,

    /// Localised titles keyed by BCP-47 language tag.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub titles: BTreeMap<String, String>,

    /// Link-specific properties.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Option<String>>,

    /// URI template for links that synthesise a URI from parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl JrdLink {
    /// Returns a new [`JrdLinkBuilder`].
    pub fn builder(rel: impl Into<String>) -> JrdLinkBuilder {
        JrdLinkBuilder {
            inner: Self {
                rel: rel.into(),
                ..Self::default()
            },
        }
    }
}

/// Builder for [`JrdLink`] produced by [`JrdLink::builder`].
#[derive(Debug)]
pub struct JrdLinkBuilder {
    inner: JrdLink,
}

impl JrdLinkBuilder {
    /// Sets the MIME type (`type` property).
    #[must_use]
    pub fn media_type(mut self, media_type: impl Into<String>) -> Self {
        self.inner.media_type = Some(media_type.into());
        self
    }

    /// Sets the `href` URL.
    #[must_use]
    pub fn href(mut self, href: Url) -> Self {
        self.inner.href = Some(href);
        self
    }

    /// Sets a localised title.
    #[must_use]
    pub fn title(mut self, lang: impl Into<String>, title: impl Into<String>) -> Self {
        self.inner.titles.insert(lang.into(), title.into());
        self
    }

    /// Sets a property.
    #[must_use]
    pub fn property(mut self, key: impl Into<String>, value: Option<String>) -> Self {
        self.inner.properties.insert(key.into(), value);
        self
    }

    /// Sets the URI template.
    #[must_use]
    pub fn template(mut self, template: impl Into<String>) -> Self {
        self.inner.template = Some(template.into());
        self
    }

    /// Finalises the [`JrdLink`].
    #[must_use]
    pub fn build(self) -> JrdLink {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn jrd_serializes_only_set_fields() {
        let jrd = Jrd::builder("acct:alice@example.com").build();
        let v = serde_json::to_value(&jrd).unwrap();
        assert_eq!(v, json!({ "subject": "acct:alice@example.com" }));
    }

    #[test]
    fn mastodon_style_jrd_roundtrips() {
        let raw = json!({
            "subject": "acct:Gargron@mastodon.social",
            "aliases": [
                "https://mastodon.social/@Gargron",
                "https://mastodon.social/users/Gargron"
            ],
            "links": [
                {
                    "rel": "http://webfinger.net/rel/profile-page",
                    "type": "text/html",
                    "href": "https://mastodon.social/@Gargron"
                },
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": "https://mastodon.social/users/Gargron"
                },
                {
                    "rel": "http://ostatus.org/schema/1.0/subscribe",
                    "template": "https://mastodon.social/authorize_interaction?uri={uri}"
                }
            ]
        });

        let jrd: Jrd = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(jrd.subject, "acct:Gargron@mastodon.social");
        assert_eq!(jrd.aliases.len(), 2);
        assert_eq!(jrd.links.len(), 3);

        let actor = jrd.activitypub_actor().expect("has actor link");
        assert_eq!(
            actor.href.as_ref().map(Url::as_str),
            Some("https://mastodon.social/users/Gargron")
        );

        let subscribe = jrd.find_link(rels::OSTATUS_SUBSCRIBE).unwrap();
        assert!(subscribe.template.is_some());
        assert!(subscribe.href.is_none());

        let back = serde_json::to_value(&jrd).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn builder_round_trips_through_serde() {
        let jrd = Jrd::builder("acct:alice@example.com")
            .alias("https://example.com/@alice")
            .link(
                JrdLink::builder(rels::ACTIVITYPUB_ACTOR)
                    .href("https://example.com/users/alice".parse().unwrap())
                    .media_type("application/activity+json")
                    .build(),
            )
            .build();

        let actor = jrd.activitypub_actor().unwrap();
        assert_eq!(actor.rel, "self");
        let json = serde_json::to_value(&jrd).unwrap();
        let back: Jrd = serde_json::from_value(json).unwrap();
        assert_eq!(back, jrd);
    }

    #[test]
    fn property_with_null_value_roundtrips() {
        let raw = json!({
            "subject": "acct:alice@example.com",
            "properties": { "http://example/schema/foo": null }
        });
        let jrd: Jrd = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(jrd.properties.get("http://example/schema/foo"), Some(&None));
        let back = serde_json::to_value(&jrd).unwrap();
        assert_eq!(back, raw);
    }
}
