//! The universal Activity Streams 2.0 [`Object`] container.
//!
//! AS 2.0 defines a rich vocabulary of object types (Actor, Activity,
//! Collection, Note, …) that share the majority of their properties.
//! Rather than materialize every specialisation as an independent Rust
//! struct, this crate models all of them through a single [`Object`] type
//! with every standard property represented directly as a typed field.
//! The [`kind`](crate::kind) module provides string constants for
//! distinguishing variants, and [`Object::is_kind`] gives an ergonomic
//! check against them.
//!
//! This mirrors the design of the popular `activitystreams` Rust crate and
//! of reference implementations such as `activitypub-federation-rust`; it
//! is the most interoperable style for a Fediverse where many
//! implementations emit structurally ambiguous JSON-LD.

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::kind;
use crate::value::{HasId, OneOrMany, Public, UrlOr};

/// A reference-valued property that may appear as a bare URL or as an
/// inlined [`Object`].
///
/// [`Object`] is recursive in its own properties, so the inline arm is
/// boxed to keep the struct size predictable.
pub type ObjectRef = UrlOr<Box<Object>>;

/// A language map keyed by BCP-47 language tag, as used by `contentMap`,
/// `summaryMap`, and `nameMap`.
pub type LanguageMap = BTreeMap<String, String>;

/// The universal Activity Streams 2.0 object container.
///
/// Every specification-defined property across [Object][obj],
/// [Activity][act], [Collection][coll], and [CollectionPage][page] is
/// represented as a typed field. Properties that are absent on the wire
/// are deserialised as `None` (for scalar fields) or an empty
/// [`OneOrMany`] (for array fields). Unknown properties are preserved
/// verbatim in [`extra`](Self::extra), ensuring lossless round-trips
/// across implementations that emit non-standard extensions.
///
/// [obj]: https://www.w3.org/TR/activitystreams-core/#object
/// [act]: https://www.w3.org/TR/activitystreams-core/#activities
/// [coll]: https://www.w3.org/TR/activitystreams-core/#collections
/// [page]: https://www.w3.org/TR/activitystreams-core/#dfn-collectionpage
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Object {
    /// Globally unique identifier of this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,

    /// Type(s) of this object. Multiple types are permitted; most
    /// Fediverse implementations emit exactly one.
    #[serde(rename = "type", default, skip_serializing_if = "OneOrMany::is_empty")]
    pub kind: OneOrMany<String>,

    /// Files or media objects attached to this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub attachment: OneOrMany<ObjectRef>,

    /// The actors attributed as creators of this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub attributed_to: OneOrMany<ObjectRef>,

    /// Intended audience for this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub audience: OneOrMany<ObjectRef>,

    /// Plain-text or HTML content of this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Localised content variants keyed by BCP-47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_map: Option<LanguageMap>,

    /// AS 2.0 application-level `context` property.
    ///
    /// Note: this is *not* the JSON-LD `@context` — that is handled by
    /// [`WithContext`](crate::WithContext).
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub context: OneOrMany<ObjectRef>,

    /// Plain-text display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Localised display names keyed by BCP-47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_map: Option<LanguageMap>,

    /// End time for an interval-valued object (`xsd:dateTime`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<DateTime<FixedOffset>>,

    /// Entity that generated this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub generator: OneOrMany<ObjectRef>,

    /// Small iconic representation of this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub icon: OneOrMany<ObjectRef>,

    /// Primary image associated with this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub image: OneOrMany<ObjectRef>,

    /// Objects this object is in reply to.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub in_reply_to: OneOrMany<ObjectRef>,

    /// Associated physical or virtual location.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub location: OneOrMany<ObjectRef>,

    /// Preview resource associated with this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub preview: OneOrMany<ObjectRef>,

    /// Publication timestamp (`xsd:dateTime`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<FixedOffset>>,

    /// Collection of replies to this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<Box<ObjectRef>>,

    /// Start time for an interval-valued object (`xsd:dateTime`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<DateTime<FixedOffset>>,

    /// Plain-text or HTML summary of this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Localised summary variants keyed by BCP-47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_map: Option<LanguageMap>,

    /// Tags (mentions, hashtags, emoji) linked to this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub tag: OneOrMany<ObjectRef>,

    /// Last-updated timestamp (`xsd:dateTime`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<FixedOffset>>,

    /// URL(s) providing alternate representations of this object.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub url: OneOrMany<ObjectRef>,

    /// Public primary recipients.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub to: OneOrMany<ObjectRef>,

    /// Private primary recipients (stripped before delivery).
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub bto: OneOrMany<ObjectRef>,

    /// Public secondary recipients.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub cc: OneOrMany<ObjectRef>,

    /// Private secondary recipients (stripped before delivery).
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub bcc: OneOrMany<ObjectRef>,

    /// MIME type of this object's payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// `xsd:duration` lexical form (e.g. `"PT5M"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,

    /// One or more actors performing the activity.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub actor: OneOrMany<ObjectRef>,

    /// Object of the activity. Omitted for `IntransitiveActivity`.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub object: OneOrMany<ObjectRef>,

    /// Indirect target of the activity.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub target: OneOrMany<ObjectRef>,

    /// Result of the activity.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub result: OneOrMany<ObjectRef>,

    /// Origin from which the activity proceeds.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub origin: OneOrMany<ObjectRef>,

    /// Instrument used to perform the activity.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub instrument: OneOrMany<ObjectRef>,

    /// Number of items in the collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u64>,

    /// Current page of a paged collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<Box<ObjectRef>>,

    /// First page of a paged collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<Box<ObjectRef>>,

    /// Last page of a paged collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<Box<ObjectRef>>,

    /// Items in an unordered collection.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub items: OneOrMany<ObjectRef>,

    /// Items in an ordered collection.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub ordered_items: OneOrMany<ObjectRef>,

    /// Collection this page is part of.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_of: Option<Box<ObjectRef>>,

    /// Next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<Box<ObjectRef>>,

    /// Previous page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<Box<ObjectRef>>,

    /// Starting index (`OrderedCollectionPage` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,

    /// Unknown or extension properties preserved verbatim.
    ///
    /// This captures any JSON property that does not map to a typed field,
    /// ensuring lossless round-tripping through non-standard extensions
    /// (e.g. Mastodon's `toot:` namespace fields, Lemmy's moderation
    /// metadata, Misskey reactions).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Object {
    /// Creates an empty [`Object`] with no properties set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`Object`] with the given type.
    #[must_use]
    pub fn with_kind(kind: impl Into<String>) -> Self {
        Self {
            kind: OneOrMany::one(kind.into()),
            ..Self::default()
        }
    }

    /// Sets the [`id`](Self::id).
    #[must_use]
    pub fn with_id(mut self, id: Url) -> Self {
        self.id = Some(id);
        self
    }

    /// Returns `true` if any of this object's declared types equals `kind`.
    #[must_use]
    pub fn is_kind(&self, kind: &str) -> bool {
        self.kind.iter().any(|k| k == kind)
    }

    /// Returns the primary (first) type name, if any.
    #[must_use]
    pub fn primary_kind(&self) -> Option<&str> {
        self.kind.first().map(String::as_str)
    }

    /// Returns `true` if this object is any of the five standard actor
    /// types (Person, Group, Organization, Application, Service).
    #[must_use]
    pub fn is_actor(&self) -> bool {
        self.is_kind(kind::actor::PERSON)
            || self.is_kind(kind::actor::GROUP)
            || self.is_kind(kind::actor::ORGANIZATION)
            || self.is_kind(kind::actor::APPLICATION)
            || self.is_kind(kind::actor::SERVICE)
    }

    /// Returns `true` if this object is any kind of collection or page.
    #[must_use]
    pub fn is_collection(&self) -> bool {
        self.is_kind(kind::core::COLLECTION)
            || self.is_kind(kind::core::ORDERED_COLLECTION)
            || self.is_kind(kind::core::COLLECTION_PAGE)
            || self.is_kind(kind::core::ORDERED_COLLECTION_PAGE)
    }

    /// Returns `true` if the [`to`](Self::to), [`cc`](Self::cc),
    /// [`bto`](Self::bto), [`bcc`](Self::bcc), or [`audience`](Self::audience)
    /// properties address the `ActivityPub` `Public` pseudo-actor in any of
    /// its spellings.
    #[must_use]
    pub fn is_public(&self) -> bool {
        fn any_public(refs: &OneOrMany<ObjectRef>) -> bool {
            refs.iter().any(|r| match r {
                UrlOr::Url(u) => Public::is_public(u.as_str()),
                UrlOr::Object(o) => o.id.as_ref().is_some_and(|u| Public::is_public(u.as_str())),
            })
        }

        any_public(&self.to)
            || any_public(&self.cc)
            || any_public(&self.bto)
            || any_public(&self.bcc)
            || any_public(&self.audience)
    }
}

impl HasId for Object {
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
    fn empty_object_roundtrips_as_empty_json() {
        let obj = Object::new();
        let v = serde_json::to_value(&obj).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn with_kind_emits_type() {
        let obj = Object::with_kind("Note");
        let v = serde_json::to_value(&obj).unwrap();
        assert_eq!(v, json!({ "type": "Note" }));
    }

    #[test]
    fn kind_helpers_work() {
        let note = Object::with_kind("Note");
        assert!(note.is_kind("Note"));
        assert_eq!(note.primary_kind(), Some("Note"));
        assert!(!note.is_actor());
        assert!(!note.is_collection());
    }

    #[test]
    fn actor_detection_covers_all_standard_types() {
        for t in [
            kind::actor::PERSON,
            kind::actor::GROUP,
            kind::actor::ORGANIZATION,
            kind::actor::APPLICATION,
            kind::actor::SERVICE,
        ] {
            let a = Object::with_kind(t);
            assert!(a.is_actor(), "{t} should be an actor");
        }
    }

    #[test]
    fn is_public_detects_all_spellings() {
        let mut obj = Object::with_kind("Note");
        obj.to = OneOrMany::one(UrlOr::Url(Url::parse(Public::URI).unwrap()));
        assert!(obj.is_public());

        let mut obj2 = Object::with_kind("Note");
        let public_obj = Object::with_id(Object::new(), Url::parse(Public::URI).unwrap());
        obj2.cc = OneOrMany::one(UrlOr::Object(Box::new(public_obj)));
        assert!(obj2.is_public());
    }

    #[test]
    fn mastodon_note_roundtrips() {
        let raw = json!({
            "id": "https://mastodon.social/users/alice/statuses/1",
            "type": "Note",
            "attributedTo": "https://mastodon.social/users/alice",
            "content": "<p>Hello, Fediverse</p>",
            "published": "2026-04-20T10:00:00+00:00",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": ["https://mastodon.social/users/alice/followers"],
            "sensitive": false,
            "inReplyTo": null
        });

        let obj: Object = serde_json::from_value(raw).unwrap();
        assert!(obj.is_kind("Note"));
        assert_eq!(obj.content.as_deref(), Some("<p>Hello, Fediverse</p>"));
        assert!(obj.is_public());
        assert_eq!(obj.attributed_to.len(), 1);
        assert!(obj.extra.contains_key("sensitive"));
        // `inReplyTo: null` should be absorbed without failure
    }

    #[test]
    fn extension_fields_roundtrip() {
        let raw = json!({
            "type": "Note",
            "_misskey_quote": "https://misskey.example/note/abc",
            "blurhash": "LEHV6nWB2yk8pyo0adR*.7kCMdnj"
        });
        let obj: Object = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(obj.extra.len(), 2);
        let back = serde_json::to_value(&obj).unwrap();
        assert_eq!(back, raw);
    }
}
