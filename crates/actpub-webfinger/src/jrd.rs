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
#[non_exhaustive]
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
    ///
    /// Media-type matching is performed against the bare
    /// `type/subtype` prefix so a parameter-carrying header like
    /// `application/ld+json; profile="…"` still matches, while
    /// unrelated subtypes that happen to share a string prefix
    /// (e.g. `application/ld+jsonx`) do not.
    #[must_use]
    pub fn activitypub_actor(&self) -> Option<&JrdLink> {
        self.links
            .iter()
            .find(|l| {
                l.rel == rels::SELF
                    && matches!(
                        l.media_type.as_deref(),
                        Some(mt) if bare_media_type(mt).eq_ignore_ascii_case(rels::MEDIA_TYPE_ACTIVITYPUB)
                    )
            })
            .or_else(|| {
                self.links.iter().find(|l| {
                    l.rel == rels::SELF
                        && matches!(
                            l.media_type.as_deref(),
                            Some(mt) if bare_media_type(mt).eq_ignore_ascii_case("application/ld+json")
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
///
/// Per [RFC 7033 §4.4.4][rel], the `href` and `template` members are
/// mutually exclusive: only one MUST be present in a given link. This
/// invariant is checked at runtime by [`JrdLink::validate`] and asserted
/// by [`JrdLinkBuilder`] in debug builds.
///
/// [rel]: https://datatracker.ietf.org/doc/html/rfc7033#section-4.4.4
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
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

    /// Checks that this link satisfies the RFC 7033 §4.4.4 invariants.
    ///
    /// Currently enforces mutual exclusion between [`href`](Self::href)
    /// and [`template`](Self::template).
    ///
    /// # Errors
    ///
    /// Returns `Err` if both `href` and `template` are set.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.href.is_some() && self.template.is_some() {
            return Err("JRD link must not have both `href` and `template`");
        }
        Ok(())
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

    /// Sets the `href` URL, clearing any previously-set `template`.
    ///
    /// Per RFC 7033 §4.4.4, the two fields are mutually exclusive, so
    /// this setter atomically clears the other.
    #[must_use]
    pub fn href(mut self, href: Url) -> Self {
        self.inner.href = Some(href);
        self.inner.template = None;
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

    /// Sets the URI template, clearing any previously-set `href`.
    ///
    /// Per RFC 7033 §4.4.4, the two fields are mutually exclusive, so
    /// this setter atomically clears the other.
    #[must_use]
    pub fn template(mut self, template: impl Into<String>) -> Self {
        self.inner.template = Some(template.into());
        self.inner.href = None;
        self
    }

    /// Finalises the [`JrdLink`].
    #[must_use]
    pub fn build(self) -> JrdLink {
        self.inner
    }
}

/// Extracts the bare `type/subtype` prefix of a media-type string,
/// stripping any RFC 6838 parameters.
///
/// `application/ld+json; profile="…"` → `"application/ld+json"`; a
/// string without a `;` is returned as-is after trimming. Used by
/// [`Jrd::activitypub_actor`] so a parameterised `type=` link still
/// matches the canonical `WebFinger` media-type names without being
/// fooled by unrelated subtypes that happen to share a string
/// prefix (`application/ld+jsonx`).
fn bare_media_type(mt: &str) -> &str {
    mt.split(';').next().unwrap_or(mt).trim()
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
        // RFC 7033 §4.4.3 permits JSON `null` as a property value to
        // indicate "known-absent" (as opposed to "unknown"), and this
        // distinction must survive a roundtrip.
        let raw = json!({
            "subject": "acct:alice@example.com",
            "properties": { "http://example/schema/foo": null }
        });
        let jrd: Jrd = serde_json::from_value(raw.clone()).expect("deserialise");
        assert_eq!(
            jrd.properties.get("http://example/schema/foo"),
            Some(&None),
            "null property must deserialise to Some(None), not None",
        );
        let back = serde_json::to_value(&jrd).expect("serialise");
        assert_eq!(back, raw);
    }

    #[test]
    fn jrd_link_validate_accepts_href_only() {
        let link = JrdLink::builder(rels::ACTIVITYPUB_ACTOR)
            .href("https://example.com/a".parse().expect("valid URL"))
            .build();
        assert!(link.validate().is_ok());
    }

    #[test]
    fn jrd_link_validate_accepts_template_only() {
        let link = JrdLink::builder(rels::OSTATUS_SUBSCRIBE)
            .template("https://example.com/subscribe?uri={uri}")
            .build();
        assert!(link.validate().is_ok());
    }

    #[test]
    fn jrd_link_validate_rejects_both_href_and_template() {
        // Construct an invalid link directly (the builder cannot produce
        // this state) to verify the validator catches it.
        let mut link = JrdLink::builder(rels::SELF).build();
        link.href = Some("https://example.com/a".parse().expect("valid URL"));
        link.template = Some("https://example.com/t?u={u}".to_owned());
        assert!(
            link.validate().is_err(),
            "RFC 7033 §4.4.4 forbids both `href` and `template` on a single link",
        );
    }

    #[test]
    fn jrd_link_builder_href_after_template_clears_template() {
        // The builder's exclusivity guarantee: setting `href` after
        // `template` must drop the template to maintain the RFC 7033
        // invariant; this keeps the resulting link valid by construction.
        let link = JrdLink::builder(rels::SELF)
            .template("https://example.com/t?u={u}")
            .href("https://example.com/a".parse().expect("valid URL"))
            .build();
        assert!(link.template.is_none(), "template must be cleared");
        assert!(link.href.is_some(), "href must be retained");
        assert!(link.validate().is_ok());
    }

    #[test]
    fn activitypub_actor_falls_back_to_ld_json_profile() {
        // Some implementations (notably Lemmy older versions) emit the
        // actor link using the full JSON-LD media type instead of the
        // shorthand. The helper must find it either way.
        let jrd: Jrd = serde_json::from_value(json!({
            "subject": "acct:alice@example.com",
            "links": [{
                "rel": "self",
                "type": "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                "href": "https://example.com/users/alice"
            }]
        }))
        .expect("JSON-LD profile JRD must parse");

        let actor = jrd
            .activitypub_actor()
            .expect("should fall back to ld+json profile");
        assert_eq!(
            actor.href.as_ref().map(Url::as_str),
            Some("https://example.com/users/alice"),
        );
    }

    #[test]
    fn find_link_returns_none_for_missing_rel() {
        let jrd = Jrd::builder("acct:alice@example.com").build();
        assert!(jrd.find_link("http://example.com/rel/missing").is_none());
    }

    #[test]
    fn activitypub_actor_rejects_media_types_that_only_share_the_ld_json_prefix() {
        // P1-N4 (sixth-round audit) regression: the earlier
        // `starts_with("application/ld+json")` test matched bogus
        // subtypes like `application/ld+jsonx` and
        // `application/ld+jsonsomething`. The bare-media-type
        // helper strips parameters before comparing the bare
        // `type/subtype`, so only legitimate AS2.0 JSON-LD
        // responses are recognised.
        let jrd: Jrd = serde_json::from_value(json!({
            "subject": "acct:alice@example.com",
            "links": [{
                "rel": "self",
                // Attacker-supplied media type that a prefix match
                // would have accepted as JSON-LD.
                "type": "application/ld+jsonx",
                "href": "https://example.com/attacker"
            }]
        }))
        .expect("JRD must parse");
        assert!(
            jrd.activitypub_actor().is_none(),
            "prefix-only media-type impersonation must NOT be accepted as the AP actor link",
        );
    }

    #[test]
    fn activitypub_actor_is_case_insensitive_on_media_type() {
        // RFC 6838 makes media types case-insensitive; a peer
        // emitting `APPLICATION/ACTIVITY+JSON` is still a valid
        // AP actor link.
        let jrd: Jrd = serde_json::from_value(json!({
            "subject": "acct:alice@example.com",
            "links": [{
                "rel": "self",
                "type": "Application/Activity+JSON",
                "href": "https://example.com/users/alice"
            }]
        }))
        .expect("JRD must parse");
        let actor = jrd
            .activitypub_actor()
            .expect("case-insensitive media-type must be recognised");
        assert_eq!(
            actor.href.as_ref().map(Url::as_str),
            Some("https://example.com/users/alice"),
        );
    }
}
