//! Type-safe URL wrappers for `ActivityPub` object references.
//!
//! Plain `Url` values lose track of *what* they identify. The wrappers
//! in this module recover that information at the type level so that
//! the federation runtime's fetch / cache / dispatch APIs are
//! statically protected against mixing up an actor URL with a
//! collection URL.
//!
//! Both wrappers serialise / deserialise transparently as the
//! underlying URL string, so they are wire-compatible with bare URLs
//! everywhere `ActivityPub` uses them (`actor`, `object`, `inbox`,
//! `following`, …).

use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::traits::Object;

/// Typed reference to an [`Object`] of type `T`, identified by its
/// URL.
///
/// Acts like a plain [`Url`] at the wire layer, but carries
/// compile-time information about the expected resource type so that
/// fetcher APIs can return `T` directly instead of forcing the caller
/// to downcast.
///
/// # Example
///
/// ```ignore
/// // From the federation crate (illustrative):
/// async fn handle_follow(follow: Follow, fetcher: &impl Fetcher) {
///     let target_id: ObjectId<Person> = follow.object().clone();
///     let target: Person = fetcher.dereference(&target_id).await?;
///     // ...
/// }
/// ```
pub struct ObjectId<T: Object> {
    url: Url,
    _phantom: PhantomData<fn() -> T>,
}

impl<T: Object> ObjectId<T> {
    /// Wraps `url` as a typed reference to `T`.
    #[must_use]
    pub const fn new(url: Url) -> Self {
        Self {
            url,
            _phantom: PhantomData,
        }
    }

    /// Borrows the underlying [`Url`].
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Consumes this reference, returning the underlying [`Url`].
    #[must_use]
    pub fn into_url(self) -> Url {
        self.url
    }

    /// Re-tags this reference as pointing at a different [`Object`]
    /// type. Useful when a single document fits two specialised types
    /// (e.g. a `Person` is also an `Actor`).
    #[must_use]
    pub fn cast<U: Object>(self) -> ObjectId<U> {
        ObjectId::new(self.url)
    }
}

impl<T: Object> Clone for ObjectId<T> {
    fn clone(&self) -> Self {
        Self::new(self.url.clone())
    }
}

impl<T: Object> PartialEq for ObjectId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl<T: Object> Eq for ObjectId<T> {}

impl<T: Object> Hash for ObjectId<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl<T: Object> fmt::Debug for ObjectId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.url)
    }
}

impl<T: Object> fmt::Display for ObjectId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.url.fmt(f)
    }
}

impl<T: Object> From<Url> for ObjectId<T> {
    fn from(url: Url) -> Self {
        Self::new(url)
    }
}

impl<T: Object> FromStr for ObjectId<T> {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s).map(Self::new)
    }
}

impl<T: Object> Serialize for ObjectId<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.url.serialize(serializer)
    }
}

impl<'de, T: Object> Deserialize<'de> for ObjectId<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Url::deserialize(deserializer).map(Self::new)
    }
}

/// Typed reference to a collection of [`Object`]s of type `T`.
///
/// Wire-format-identical to [`ObjectId`]; the distinct alias exists so
/// that fetch APIs can advertise "this returns a paged collection"
/// rather than "this returns a single object" without bringing in a
/// new generic type parameter.
pub type CollectionId<T> = ObjectId<T>;

#[cfg(test)]
#[allow(
    clippy::unnecessary_literal_bound,
    reason = "the phantom-type test impls return literal `&'static str` from a trait method whose signature returns `&str`; cf. the matching reasoning in `traits::tests`"
)]
mod tests {
    use std::collections::HashSet;

    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;
    use crate::traits::Object;

    struct Note;
    impl Object for Note {
        type Wire = serde_json::Value;
        fn id(&self) -> &Url {
            unreachable!("phantom marker only")
        }
        fn kind(&self) -> &str {
            "Note"
        }
        fn to_wire(&self) -> Self::Wire {
            unreachable!("phantom marker only")
        }
    }

    struct Person;
    impl Object for Person {
        type Wire = serde_json::Value;
        fn id(&self) -> &Url {
            unreachable!("phantom marker only")
        }
        fn kind(&self) -> &str {
            "Person"
        }
        fn to_wire(&self) -> Self::Wire {
            unreachable!("phantom marker only")
        }
    }

    #[test]
    fn serializes_as_bare_url_string() {
        let id: ObjectId<Note> = "https://example.com/n/1".parse().unwrap();
        let v = serde_json::to_value(&id).unwrap();
        assert_eq!(v, json!("https://example.com/n/1"));
    }

    #[test]
    fn deserializes_from_bare_url_string() {
        let v = json!("https://example.com/n/1");
        let id: ObjectId<Note> = serde_json::from_value(v).unwrap();
        assert_eq!(id.url().as_str(), "https://example.com/n/1");
    }

    #[test]
    fn equality_and_hashing_compare_by_underlying_url() {
        let a: ObjectId<Note> = "https://example.com/n/1".parse().unwrap();
        let b: ObjectId<Note> = "https://example.com/n/1".parse().unwrap();
        let c: ObjectId<Note> = "https://example.com/n/2".parse().unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set: HashSet<ObjectId<Note>> = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn cast_changes_marker_but_preserves_url() {
        let note_id: ObjectId<Note> = "https://example.com/u/1".parse().unwrap();
        let person_id: ObjectId<Person> = note_id.clone().cast();
        assert_eq!(note_id.url(), person_id.url());
    }

    #[test]
    fn collection_id_is_an_alias_of_object_id() {
        // Compile-time check: CollectionId<T> = ObjectId<T>.
        let inbox: CollectionId<Note> = "https://example.com/c/1".parse().unwrap();
        let same: ObjectId<Note> = inbox.clone();
        assert_eq!(inbox, same);
    }

    #[test]
    fn debug_and_display_render_underlying_url() {
        let id: ObjectId<Note> = "https://example.com/n/1".parse().unwrap();
        assert_eq!(id.to_string(), "https://example.com/n/1");
        assert_eq!(format!("{id:?}"), "ObjectId(https://example.com/n/1)");
    }
}
