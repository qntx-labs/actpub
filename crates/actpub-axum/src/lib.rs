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
#![allow(
    unused_crate_dependencies,
    dead_code,
    unused_imports,
    missing_docs,
    reason = "crate is a scaffold; dependencies are declared up-front so that implementation work in later phases does not churn the manifest. Remove this allow once the crate has concrete items."
)]
