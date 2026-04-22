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
//! # Conformance scope
//!
//! This crate targets the **`ActivityPub` server-to-server (S2S)**
//! surface, with the interop profile the mainstream Fediverse
//! (Mastodon, Pleroma, Lemmy, Misskey, `GoToSocial`, Akkoma) has
//! actually converged on. Concretely:
//!
//! - **In scope.** The `POST` delivery + inbox chain, HTTP
//!   signatures (Cavage draft-12 + RFC 9421), `Digest` and RFC 9530
//!   `Content-Digest`, `WebFinger`-based actor discovery, the
//!   mandatory subset of the replay / freshness gates Fediverse
//!   peers expect by default (12 h past / 5 min future skew), and
//!   the key-ownership chains FEP-521a / FEP-8b32 demand.
//! - **Out of scope.** The `ActivityPub` client-to-server (C2S)
//!   API described in W3C §6 — including auto-wrapping bare
//!   `Object`s in a `Create` on `POST` to the outbox, and the C2S
//!   authorisation / collection semantics. C2S is a different
//!   HTTP shape (OAuth, not signed requests) and serves a
//!   different population (end-user clients, not peer servers);
//!   conflating the two in one runtime was the mistake we
//!   explicitly chose not to make. Consumers that need C2S build
//!   it on top of this crate.
//! - **Partial / advisory.** RFC 9421's full covered-component
//!   vocabulary (`@status`, `@query-param`, structured-field
//!   parameters) is intentionally NOT enforced — Fediverse peers
//!   sign the minimum set (`@method @target-uri host date
//!   content-digest`) and nothing else, so requiring more would
//!   reject every real peer. `InboxPipeline` enforces exactly that
//!   minimum via [`FederationConfig::verify_policy`]; a deployment
//!   that needs the wider RFC 9421 surface can override the
//!   policy, but it is not on by default because no peer produces
//!   it. §7.1.2 Inbox Forwarding (`SHOULD` in the spec) is also
//!   not implemented by this crate yet; embedding it requires an
//!   application-specific definition of "local recipient" the
//!   runtime cannot guess, so it is a candidate for a dedicated
//!   trait in a future release.
//!
//! [`Fetcher`]: https://docs.rs/actpub-federation/latest/actpub_federation/trait.Fetcher.html
//! [`Deliverer`]: https://docs.rs/actpub-federation/latest/actpub_federation/trait.Deliverer.html
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic name for the crate's top-level error enum, matching the `thiserror` convention used pervasively in the Rust ecosystem"
)]
#![allow(
    clippy::result_large_err,
    reason = "Every error variant is rich with context (Url, String, transport cause) required for Fediverse operator triage; boxing the whole enum would complicate the happy path for no measurable benefit on the always-cold error path"
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
mod fetch_ctx;
mod fetcher;
mod http_util;
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
    DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, DEFAULT_DEDUP_CAPACITY, DEFAULT_DEDUP_TTL,
    DEFAULT_DELIVERY_CONCURRENCY, DEFAULT_DELIVERY_QUEUE_CAPACITY, DEFAULT_HTTP_FETCH_LIMIT,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RESOLVE_CONCURRENCY,
    FederationConfig, default_user_agent,
};
pub use self::deliver::{Deliverer, ReqwestDeliverer};
pub use self::error::Error;
pub use self::fetch_ctx::FetchContext;
pub use self::fetcher::{
    AP_ACCEPT_HEADER, AP_CONTENT_TYPE, Fetcher, LD_CONTENT_TYPE_PREFIX, ReqwestFetcher,
    signed_fetch_signature_header,
};
pub use self::inbox::{ActivityHandler, InboxOutcome, InboxPipeline};
pub use self::outbox::{DispatchReport, InboxResolution, Outbox};
pub use self::policy::UrlPolicy;
pub use self::retry::RetryPolicy;

/// Crate [`Result`] alias defaulting to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
