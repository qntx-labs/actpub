//! Activity Streams 2.0 data model and vocabulary.
//!
//! This crate provides pure data types (no I/O, no networking) for the W3C
//! [Activity Streams 2.0 Core] and [Activity Vocabulary] specifications, as
//! used by the [ActivityPub] protocol.
//!
//! The types are designed for idiomatic `serde` (de)serialization with
//! tolerant handling of the JSON-LD variants emitted by real-world Fediverse
//! implementations such as Mastodon, Pleroma, Lemmy and Misskey.
//!
//! [Activity Streams 2.0 Core]: https://www.w3.org/TR/activitystreams-core/
//! [Activity Vocabulary]: https://www.w3.org/TR/activitystreams-vocabulary/
//! [ActivityPub]: https://www.w3.org/TR/activitypub/
#![cfg_attr(docsrs, feature(doc_cfg))]
