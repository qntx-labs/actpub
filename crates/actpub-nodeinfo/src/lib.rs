//! `NodeInfo` server metadata protocol for the Fediverse.
//!
//! Implements `NodeInfo` [2.0] / [2.1] and [FEP-0151] (`NodeInfo` 2025 edition),
//! providing both discovery (`/.well-known/nodeinfo`) and schema documents.
//!
//! # Example (server)
//!
//! ```
//! use actpub_nodeinfo::{NodeInfo, Software, Usage, UserCount, Protocol, Version};
//!
//! let info = NodeInfo::builder(Version::V2_1, Software::new("my-server", "1.0.0"))
//!     .protocol(Protocol::ActivityPub)
//!     .open_registrations(true)
//!     .usage(Usage::new(UserCount::default().with_total(42)))
//!     .build();
//!
//! let json = serde_json::to_string(&info).unwrap();
//! assert!(json.contains(r#""version":"2.1""#));
//! ```
//!
//! [2.0]: http://nodeinfo.diaspora.software/ns/schema/2.0
//! [2.1]: http://nodeinfo.diaspora.software/ns/schema/2.1
//! [FEP-0151]: https://codeberg.org/fediverse/fep/src/branch/main/fep/0151/fep-0151.md
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic name for the crate's top-level error enum, matching the `thiserror` convention used pervasively in the Rust ecosystem"
)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        reason = "JSON field indexing via `Value[\"key\"]` is ergonomic inside tests and its panic-on-missing behaviour is the desired failure mode when fixtures are wrong"
    )
)]

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
mod client;
mod discovery;
mod error;
mod schema;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use self::client::{
    DEFAULT_MAX_BODY_BYTES, fetch, fetch_discovery, fetch_discovery_with_limit, fetch_with_limit,
    recommended_client,
};
pub use self::discovery::{Discovery, DiscoveryLink, SCHEMA_REL_PREFIX};
pub use self::error::Error;
pub use self::schema::{
    InboundService, NodeInfo, NodeInfoBuilder, OutboundService, Protocol, Services, Software,
    Usage, UserCount, Version,
};

/// Crate [`Result`] alias with the default error type set to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The well-known URI path for the `NodeInfo` discovery document.
pub const WELL_KNOWN_PATH: &str = "/.well-known/nodeinfo";
