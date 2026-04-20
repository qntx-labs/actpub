//! [axum] 0.8 integration for `actpub-federation`.
//!
//! Drop-in router builders that wire the federation runtime into an
//! existing axum service:
//!
//! - [`inbox_router`] — POST endpoint dispatching to a configured
//!   [`InboxPipeline`](actpub_federation::InboxPipeline).
//! - [`webfinger_router`] — `/.well-known/webfinger` endpoint resolving
//!   `acct:` URIs via a user-supplied callback.
//! - [`nodeinfo_router`] — `/.well-known/nodeinfo` discovery + per-version
//!   schema endpoints.
//! - [`FederationJson<T>`] responder — serialises `T` with the
//!   `application/activity+json` media type required by every Fediverse
//!   peer.
//!
//! Each router is a standalone [`Router`](axum::Router) that mounts at
//! its conventional path; compose them via
//! [`Router::merge`](axum::Router::merge) to build a complete service.
//!
//! [axum]: https://docs.rs/axum
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::module_name_repetitions,
    reason = "router builder names like `inbox_router` mirror the conventional naming pattern axum users expect"
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

mod inbox;
mod json;
mod nodeinfo;
mod webfinger;

use bytes as _;
use http as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tower as _;
use tower_http as _;
use tracing as _;
use url as _;
#[cfg(test)]
use {actpub_httpsig as _, http_body_util as _, httpdate as _, pretty_assertions as _};

pub use self::inbox::{DEFAULT_MAX_INBOX_BYTES, InboxState, inbox_router};
pub use self::json::{ACTIVITY_PUB_CONTENT_TYPE, FederationJson};
pub use self::nodeinfo::{NODEINFO_CONTENT_TYPE, NodeInfoState, nodeinfo_router};
pub use self::webfinger::{JRD_CONTENT_TYPE, WebFingerResolver, webfinger_router};
