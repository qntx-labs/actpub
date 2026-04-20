//! Activity Streams 2.0 data model and vocabulary.
//!
//! This crate provides pure data types (no I/O, no networking) for the W3C
//! [Activity Streams 2.0 Core] and [Activity Vocabulary] specifications, as
//! used by the [ActivityPub] protocol.
//!
//! # Design
//!
//! The types are designed for idiomatic `serde` (de)serialization with
//! tolerant handling of the JSON-LD variants emitted by real-world Fediverse
//! implementations such as Mastodon, Pleroma, Lemmy and Misskey.
//!
//! Core AS 2.0 types ([`Object`], [`Link`], [`Activity`], [`Collection`]) are
//! concrete structs with every specification-defined property represented as
//! `Option<T>` or [`OneOrMany<T>`]. Concrete vocabulary types that add no new
//! properties (`Note`, `Article`, `Create`, …) share the core structs and are
//! discriminated by string type constants ([`kind`]), while types that add
//! new properties (`Question`, `Place`, `Tombstone`) are provided as
//! dedicated structs that flatten the core object.
//!
//! # Interoperability
//!
//! Real Fediverse JSON-LD is inconsistent and requires tolerance:
//!
//! - Array-typed properties may appear as a single value (handled by
//!   [`OneOrMany<T>`])
//! - Object properties may be inlined or appear as plain URL strings (handled
//!   by [`OrLink<T>`])
//! - The [`Public`] audience appears in multiple equivalent forms
//! - Unknown properties are preserved via flattened extension maps
//!
//! [Activity Streams 2.0 Core]: https://www.w3.org/TR/activitystreams-core/
//! [Activity Vocabulary]: https://www.w3.org/TR/activitystreams-vocabulary/
//! [ActivityPub]: https://www.w3.org/TR/activitypub/
#![cfg_attr(docsrs, feature(doc_cfg))]

mod context;
mod error;
mod link;
mod object;
mod value;

pub mod kind;

pub use self::context::{Context, ContextEntry, WithContext};
pub use self::error::Error;
pub use self::link::Link;
pub use self::object::{LanguageMap, Object, ObjectRef};
pub use self::value::{HasId, OneOrMany, Public, UrlOr};

/// Crate [`Result`] alias with the default error type set to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
