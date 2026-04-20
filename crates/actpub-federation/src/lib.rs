//! Federation runtime for `ActivityPub` server-to-server delivery.
//!
//! Builds on the wire-format crates ([`actpub_activitystreams`],
//! [`actpub_httpsig`], [`actpub_webfinger`]) and the protocol layer
//! ([`actpub_core`]) to deliver the IO-shaped pieces that real
//! Fediverse servers need:
//!
//! - [`FederationConfig`] — a single immutable record bundling every
//!   policy knob (signing key, URL admission, cache, timeouts).
//! - [`UrlPolicy`] — SSRF-safe URL admission gate enforced at every
//!   IO boundary.
//! - [`Error`] — top-level error type carrying provenance for every
//!   failure path.
//!
//! Higher-level pieces (typed [`Fetcher`], retrying [`Deliverer`],
//! signature-verifying inbox pipeline) plug into this configuration
//! and are introduced in subsequent steps.
//!
//! [`Fetcher`]: https://docs.rs/actpub-federation/latest/actpub_federation/trait.Fetcher.html
//! [`Deliverer`]: https://docs.rs/actpub-federation/latest/actpub_federation/trait.Deliverer.html
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic name for the crate's top-level error enum, matching the `thiserror` convention used pervasively in the Rust ecosystem"
)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used,
        reason = "JSON / byte indexing is ergonomic in tests, and `panic!` / `unwrap()` are the idiomatic way to assert expectations"
    )
)]

mod config;
mod deliver;
mod error;
mod fetcher;
mod inbox;
mod outbox;
mod policy;
mod retry;

use actpub_activitystreams as _;
use actpub_core as _;
use actpub_webfinger as _;
use bytes as _;
use chrono as _;
use futures as _;
use http as _;
use httpdate as _;
use moka as _;
use reqwest as _;
use serde as _;
use serde_json as _;
use tokio as _;
use tracing as _;
#[cfg(test)]
use wiremock as _;

pub use self::config::{
    DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_REQUEST_TIMEOUT, FederationConfig, default_user_agent,
};
pub use self::deliver::{Deliverer, ReqwestDeliverer};
pub use self::error::Error;
pub use self::fetcher::{
    AP_ACCEPT_HEADER, AP_CONTENT_TYPE, Fetcher, LD_CONTENT_TYPE_PREFIX, ReqwestFetcher,
    signed_fetch_signature_header,
};
pub use self::inbox::{ActivityHandler, InboxOutcome, InboxPipeline};
pub use self::outbox::Outbox;
pub use self::policy::UrlPolicy;
pub use self::retry::RetryPolicy;

/// Crate [`Result`] alias defaulting to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
