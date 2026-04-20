//! Federation runtime for `ActivityPub` server-to-server (S2S) protocol.
//!
//! Ties together [`actpub-activitystreams`], [`actpub-core`],
//! [`actpub-http-signatures`] and [`actpub-webfinger`] into a complete
//! federation stack:
//!
//! - `FederationConfig` / `Context` — shared runtime state and request scope
//! - `ObjectId<T>` / `CollectionId<T>` — typed URL wrappers with automatic
//!   dereferencing, caching and `DoS` protection
//! - Outgoing delivery queue with exponential backoff (1 min → 1 h → 60 h)
//! - Incoming inbox pipeline with Cavage + RFC 9421 signature verification,
//!   Digest validation, URL allow-listing and inbox-forwarding
#![cfg_attr(docsrs, feature(doc_cfg))]
