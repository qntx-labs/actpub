//! Polymorphic value wrappers used throughout Activity Streams 2.0.
//!
//! Activity Streams 2.0 is notoriously loose about the shape of its values:
//! most "array-typed" properties may appear as a bare single value in JSON,
//! and object-typed properties frequently appear as plain URL strings that
//! reference a remote resource. These wrappers preserve type safety on the
//! Rust side while accepting the full range of legal JSON shapes.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

/// A value that may serialize as either a single `T` or as an ordered array
/// of `T`.
///
/// On the wire an empty [`OneOrMany`] is emitted as an empty array, a single
/// entry as a bare value, and multiple entries as a JSON array.
///
/// # Examples
///
/// ```
/// # use actpub_activitystreams::OneOrMany;
/// let one: OneOrMany<String> =
///     serde_json::from_str(r#""Hello""#).unwrap();
/// assert_eq!(one.as_slice(), &["Hello".to_owned()]);
///
/// let many: OneOrMany<String> =
///     serde_json::from_str(r#"["A", "B"]"#).unwrap();
/// assert_eq!(many.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OneOrMany<T>(Vec<T>);

impl<T> OneOrMany<T> {
    /// Creates an empty [`OneOrMany`].
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a [`OneOrMany`] containing a single value.
    pub fn one(value: T) -> Self {
        Self(vec![value])
    }

    /// Creates a [`OneOrMany`] from a pre-existing [`Vec`].
    #[must_use]
    pub const fn many(values: Vec<T>) -> Self {
        Self(values)
    }

    /// Returns a slice view of the contained values.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Returns a mutable slice view of the contained values.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    /// Returns the underlying [`Vec`], consuming `self`.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    /// Appends a value.
    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of contained values.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the contained values.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Returns a mutable iterator over the contained values.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Returns a reference to the first value, if any.
    #[must_use]
    pub fn first(&self) -> Option<&T> {
        self.0.first()
    }

    /// Returns a reference to the last value, if any.
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.0.last()
    }
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a OneOrMany<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::one(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(values: Vec<T>) -> Self {
        Self::many(values)
    }
}

impl<T> FromIterator<T> for OneOrMany<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T: Serialize> Serialize for OneOrMany<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [only] => only.serialize(serializer),
            many => many.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either<T> {
            Many(Vec<T>),
            One(T),
        }

        // Accept JSON `null` and the two concrete shapes. Real Fediverse
        // traffic frequently sends `null` for absent array-typed properties
        // (e.g. Mastodon's `inReplyTo: null`); we treat those as empty.
        match Option::<Either<T>>::deserialize(deserializer)? {
            None => Ok(Self::new()),
            Some(Either::One(value)) => Ok(Self::one(value)),
            Some(Either::Many(values)) => Ok(Self::many(values)),
        }
    }
}

/// A value that may appear inlined as `T` or as a bare URL reference.
///
/// AS 2.0 object-valued properties frequently arrive either:
///
/// - embedded as a full object (`{ "id": "https://…", "type": "Note", … }`)
/// - or as just the URL string (`"https://example.com/note/1"`)
///
/// [`UrlOr`] captures both variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlOr<T> {
    /// A bare URL reference to the remote resource.
    Url(Url),
    /// An inlined object of the target type.
    Object(T),
}

impl<T> UrlOr<T> {
    /// Returns the referenced URL, regardless of whether it is inlined or
    /// bare, provided the inlined variant exposes an `id` via [`HasId`].
    pub fn url(&self) -> Option<&Url>
    where
        T: HasId,
    {
        match self {
            Self::Url(u) => Some(u),
            Self::Object(o) => o.id(),
        }
    }

    /// Returns the inlined object if it was inlined.
    #[must_use]
    pub const fn as_object(&self) -> Option<&T> {
        match self {
            Self::Object(o) => Some(o),
            Self::Url(_) => None,
        }
    }
}

/// Types with an optional `id` URL, enabling uniform reference resolution.
pub trait HasId {
    /// Returns the `id` of this object, if set.
    fn id(&self) -> Option<&Url>;
}

/// The `Public` pseudo-actor used for public audience targeting in
/// `ActivityPub`.
///
/// The specification defines a single URI, but real Fediverse traffic
/// contains three spellings. [`Public::is_public`] recognises all of them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Public;

impl Public {
    /// Full public URI per the `ActivityPub` specification.
    pub const URI: &'static str = "https://www.w3.org/ns/activitystreams#Public";
    /// CURIE form using the `as:` prefix defined by the AS 2.0 JSON-LD
    /// context document.
    pub const CURIE: &'static str = "as:Public";
    /// Bare form `Public`. Legal only inside a JSON-LD `@context` that
    /// defines the `as:` prefix. Accepted for interop but not emitted.
    pub const BARE: &'static str = "Public";

    /// Returns `true` if `value` is any of the three accepted spellings of
    /// the AS 2.0 Public pseudo-actor.
    #[must_use]
    pub fn is_public(value: &str) -> bool {
        matches!(value, Self::URI | Self::CURIE | Self::BARE)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn one_or_many_single_value_roundtrips() {
        let value = OneOrMany::one("hello".to_owned());
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json, json!("hello"));

        let back: OneOrMany<String> = serde_json::from_value(json).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn one_or_many_multi_value_roundtrips() {
        let value = OneOrMany::many(vec![1_i32, 2, 3]);
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json, json!([1, 2, 3]));

        let back: OneOrMany<i32> = serde_json::from_value(json).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn one_or_many_accepts_single_on_deserialize() {
        let back: OneOrMany<String> = serde_json::from_value(json!("only")).unwrap();
        assert_eq!(back.as_slice(), &["only".to_owned()]);
    }

    #[test]
    fn url_or_deserializes_bare_url() {
        #[derive(Deserialize, Serialize, Debug, PartialEq)]
        struct Dummy {
            id: String,
        }
        let value: UrlOr<Dummy> = serde_json::from_value(json!("https://example/1")).unwrap();
        assert!(matches!(value, UrlOr::Url(_)));
    }

    #[test]
    fn url_or_deserializes_object() {
        #[derive(Deserialize, Serialize, Debug, PartialEq)]
        struct Dummy {
            id: String,
        }
        let value: UrlOr<Dummy> = serde_json::from_value(json!({ "id": "abc" })).unwrap();
        assert!(matches!(value, UrlOr::Object(Dummy { .. })));
    }

    #[test]
    fn public_is_recognised_in_all_spellings() {
        assert!(Public::is_public(Public::URI));
        assert!(Public::is_public(Public::CURIE));
        assert!(Public::is_public(Public::BARE));
        assert!(!Public::is_public("https://example/actor"));
    }
}
