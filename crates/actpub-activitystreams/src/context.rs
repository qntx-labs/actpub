//! The JSON-LD `@context` property.
//!
//! `ActivityPub` is technically a JSON-LD protocol, but in practice the
//! Fediverse consumes documents as plain JSON using a small set of well-known
//! context URIs. This module provides a lightweight, tolerant representation
//! of `@context` that round-trips all shapes encountered in production
//! without any full JSON-LD processing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::value::OneOrMany;

/// A single entry in the `@context` array.
///
/// Most entries are URI references to well-known AS 2.0 / security contexts;
/// the remainder are inline maps that define additional terms (such as
/// Mastodon's `toot:` namespace).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextEntry {
    /// A bare context URI.
    Uri(Url),
    /// An inline JSON-LD context object.
    ///
    /// Values are preserved verbatim as [`serde_json::Value`] since Rust-side
    /// processing does not inspect them.
    Object(BTreeMap<String, serde_json::Value>),
}

impl From<Url> for ContextEntry {
    fn from(url: Url) -> Self {
        Self::Uri(url)
    }
}

/// The value of a JSON-LD `@context` property.
///
/// May be a single entry (emitted as a bare value) or multiple entries
/// (emitted as an array). The wire format is driven by [`OneOrMany`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Context(pub OneOrMany<ContextEntry>);

impl Context {
    /// The canonical Activity Streams 2.0 context URI.
    pub const AS2: &'static str = "https://www.w3.org/ns/activitystreams";
    /// The Controlled Identifiers v1 context, required by FEP-521a.
    pub const CID_V1: &'static str = "https://www.w3.org/ns/cid/v1";
    /// The Data Integrity v2 context, required by FEP-8b32 proofs.
    pub const DATA_INTEGRITY_V2: &'static str = "https://w3id.org/security/data-integrity/v2";
    /// The legacy Security v1 context used by older Mastodon actors.
    pub const SECURITY_V1: &'static str = "https://w3id.org/security/v1";

    /// Creates a [`Context`] containing only the canonical AS 2.0 URI.
    ///
    /// # Panics
    ///
    /// Never panics; [`Self::AS2`] is a compile-time valid URL.
    #[must_use]
    pub fn activitystreams() -> Self {
        Self(OneOrMany::one(ContextEntry::Uri(
            Url::parse(Self::AS2).expect("AS2 URI is valid"),
        )))
    }

    /// Creates a [`Context`] containing the AS 2.0 URI plus the Security v1
    /// URI — the combination emitted by most current Fediverse actors.
    #[must_use]
    pub fn activitystreams_security() -> Self {
        Self(OneOrMany::many(vec![
            ContextEntry::Uri(Url::parse(Self::AS2).expect("AS2 URI is valid")),
            ContextEntry::Uri(Url::parse(Self::SECURITY_V1).expect("security/v1 URI is valid")),
        ]))
    }

    /// Creates a [`Context`] containing AS 2.0 plus the Data Integrity
    /// context — the combination required when emitting FEP-8b32 proofs.
    #[must_use]
    pub fn activitystreams_integrity() -> Self {
        Self(OneOrMany::many(vec![
            ContextEntry::Uri(Url::parse(Self::AS2).expect("AS2 URI is valid")),
            ContextEntry::Uri(
                Url::parse(Self::DATA_INTEGRITY_V2).expect("data-integrity/v2 URI is valid"),
            ),
        ]))
    }

    /// Returns the entries of this context.
    #[must_use]
    pub fn entries(&self) -> &[ContextEntry] {
        self.0.as_slice()
    }

    /// Appends an entry to this context.
    pub fn push(&mut self, entry: ContextEntry) {
        self.0.push(entry);
    }

    /// Returns `true` if the context contains the given URI.
    #[must_use]
    pub fn contains(&self, uri: &str) -> bool {
        self.0.iter().any(|e| match e {
            ContextEntry::Uri(u) => u.as_str() == uri,
            ContextEntry::Object(_) => false,
        })
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::activitystreams()
    }
}

impl From<Url> for Context {
    fn from(url: Url) -> Self {
        Self(OneOrMany::one(ContextEntry::Uri(url)))
    }
}

/// Wraps any Activity Streams payload with a JSON-LD `@context`.
///
/// Use this on outbound values to ensure conformant serialization; inbound
/// values typically carry their own `@context` and can be deserialized
/// directly into this type.
///
/// # Examples
///
/// ```
/// # use actpub_activitystreams::{Context, WithContext, Object};
/// let obj = Object::with_kind("Note");
/// let wrapped = WithContext::new(obj);
/// let json = serde_json::to_string(&wrapped).unwrap();
/// assert!(json.contains("@context"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithContext<T> {
    /// The JSON-LD context of the payload.
    #[serde(rename = "@context")]
    pub context: Context,
    /// The wrapped payload. Flattened in the wire format.
    #[serde(flatten)]
    pub inner: T,
}

impl<T> WithContext<T> {
    /// Wraps `inner` with the default AS 2.0 context.
    pub fn new(inner: T) -> Self {
        Self {
            context: Context::default(),
            inner,
        }
    }

    /// Wraps `inner` with an explicit context.
    pub const fn with_context(context: Context, inner: T) -> Self {
        Self { context, inner }
    }

    /// Unwraps the inner payload.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn default_context_is_as2() {
        let ctx = Context::default();
        assert_eq!(ctx.entries().len(), 1);
        assert!(ctx.contains(Context::AS2));
    }

    #[test]
    fn single_uri_serializes_as_bare_value() {
        let ctx = Context::activitystreams();
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(v, json!("https://www.w3.org/ns/activitystreams"));
    }

    #[test]
    fn multi_uri_serializes_as_array() {
        let ctx = Context::activitystreams_security();
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(
            v,
            json!([
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1"
            ])
        );
    }

    #[test]
    fn context_accepts_inline_object() {
        let json = json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                { "toot": "http://joinmastodon.org/ns#" }
            ]
        });
        let parsed: serde_json::Value = serde_json::from_value(json).expect("valid json fixture");
        let ctx: Context = serde_json::from_value(parsed["@context"].clone()).unwrap();
        assert_eq!(ctx.entries().len(), 2);
        assert!(matches!(ctx.entries()[1], ContextEntry::Object(_)));
    }
}
