//! `WebFinger` (RFC 7033) primitives for `ActivityPub` account discovery.
//!
//! `WebFinger` is the discovery mechanism used across the Fediverse to map
//! `acct:user@host` identifiers to `ActivityPub` actor URLs via a
//! [`/.well-known/webfinger`][endpoint] endpoint returning a JSON Resource
//! Descriptor (JRD).
//!
//! # Example (client)
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use actpub_webfinger::{Account, resolve};
//!
//! let client = reqwest::Client::new();
//! let account = Account::parse("acct:gargron@mastodon.social")?;
//! let jrd = resolve(&account, &client).await?;
//!
//! if let Some(link) = jrd.activitypub_actor() {
//!     println!("Actor URL: {}", link.href.as_ref().unwrap());
//! }
//! # Ok(()) }
//! ```
//!
//! # Example (server)
//!
//! ```
//! use actpub_webfinger::{Jrd, JrdLink, rels};
//!
//! let jrd = Jrd::builder("acct:alice@example.com")
//!     .alias("https://example.com/@alice")
//!     .link(
//!         JrdLink::builder(rels::ACTIVITYPUB_ACTOR)
//!             .href("https://example.com/users/alice".parse().unwrap())
//!             .media_type("application/activity+json")
//!             .build(),
//!     )
//!     .build();
//!
//! let json = serde_json::to_string(&jrd).unwrap();
//! assert!(json.contains(r#""subject":"acct:alice@example.com""#));
//! ```
//!
//! [endpoint]: https://datatracker.ietf.org/doc/html/rfc7033#section-4
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

mod account;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
mod client;
mod error;
mod jrd;

pub mod rels;

pub use self::account::Account;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use self::client::resolve;
pub use self::error::Error;
pub use self::jrd::{Jrd, JrdBuilder, JrdLink, JrdLinkBuilder};

/// Crate [`Result`] alias with the default error type set to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The IANA-registered media type for a `WebFinger` JRD response.
pub const MEDIA_TYPE: &str = "application/jrd+json";

/// The well-known URI path for the `WebFinger` endpoint (RFC 7033 §4).
pub const WELL_KNOWN_PATH: &str = "/.well-known/webfinger";
