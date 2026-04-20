//! [axum] integration for `actpub-federation`.
//!
//! Provides extractors, responders and router helpers that let applications
//! drop `ActivityPub` federation into an existing axum 0.8 service:
//!
//! - `ActivityData` extractor — verifies HTTP signature + Digest, hands the
//!   raw JSON body to your activity dispatcher
//! - `WebfingerQuery` extractor — parses and validates `acct:` resource
//!   parameters
//! - `FederationJson<T>` responder — emits `application/activity+json`
//!   responses with the correct MIME type
//!
//! [axum]: https://docs.rs/axum
#![cfg_attr(docsrs, feature(doc_cfg))]
