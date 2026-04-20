//! # actpub — `ActivityPub` protocol SDK for Rust
//!
//! A production-ready, enterprise-grade toolkit for building `ActivityPub`
//! services that interoperate with the real Fediverse (Mastodon, Lemmy,
//! Pleroma, Misskey, `PeerTube`, …).
//!
//! This crate is a thin **meta-crate** that re-exports a family of focused
//! sub-crates. Pick the pieces you need via Cargo features:
//!
//! | Sub-crate | Feature | Purpose |
//! | --- | --- | --- |
//! | [`actpub-activitystreams`] | (always) | Activity Streams 2.0 data model |
//! | [`actpub-webfinger`]       | (always) | RFC 7033 `WebFinger` |
//! | [`actpub-nodeinfo`]        | (always) | `NodeInfo` 2.x + FEP-0151 |
//! | [`actpub-httpsig`]         | (always) | Cavage + RFC 9421 signatures |
//! | [`actpub-core`]            | (always) | Core protocol traits |
//! | [`actpub-federation`]      | `federation` | Full federation runtime |
//! | [`actpub-axum`]            | `axum` | axum 0.8 integration layer |
//!
//! Enable `default = ["federation", "axum", "client"]` for a batteries-included
//! server; disable default features to use just the data model and types.
//!
//! ## Conformance
//!
//! - W3C [ActivityPub](https://www.w3.org/TR/activitypub/) Server-to-Server
//! - W3C [Activity Streams 2.0](https://www.w3.org/TR/activitystreams-core/)
//! - IETF [RFC 7033](https://datatracker.ietf.org/doc/html/rfc7033) `WebFinger`
//! - IETF [Cavage draft-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12) (sending)
//! - IETF [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) (receiving)
//! - `NodeInfo` 2.0 / 2.1
//! - FEP-521a, FEP-8b32, FEP-8fcf, FEP-67ff, FEP-f1d5, FEP-0151
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use actpub_activitystreams as activitystreams;
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub use actpub_axum as axum;
pub use actpub_core as core;
#[cfg(feature = "federation")]
#[cfg_attr(docsrs, doc(cfg(feature = "federation")))]
pub use actpub_federation as federation;
pub use actpub_httpsig as httpsig;
pub use actpub_nodeinfo as nodeinfo;
pub use actpub_webfinger as webfinger;
