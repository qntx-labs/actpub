//! Core `ActivityPub` protocol layer.
//!
//! Sits one rung above the wire-format crates (`actpub-activitystreams`,
//! `actpub-httpsig`) and one rung below the `actpub-federation` runtime.
//! Its job is to bind cryptographic primitives to the on-the-wire data
//! model so that higher layers can speak in the language of "signed
//! `ActivityPub` objects" rather than "JSON blobs and detached signatures".
//!
//! # What this crate provides
//!
//! - [`eddsa_jcs`] — the [FEP-8b32] / [W3C VC-DI EdDSA] `eddsa-jcs-2022`
//!   cryptosuite (object-level signing for Mitra / Takahē / Mastodon
//!   4.5+).
//! - [`jcs`] — RFC 8785 JSON Canonicalisation Scheme helper.
//! - [`Object`] / [`Actor`] / [`Activity`] — the three traits user
//!   code implements to plug their own database row types into the
//!   federation runtime.
//! - [`ObjectId<T>`] — typed URL wrapper preserving the expected
//!   resource type at compile time.
//! - [`multikey_bridge`] — helpers to move between the wire-format
//!   and crypto-layer FEP-521a Multikey representations.
//!
//! Higher-level federation runtime concerns (typed URL fetching,
//! delivery queue, inbox pipeline) live in `actpub-federation`.
//!
//! [FEP-8b32]: https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md
//! [W3C VC-DI EdDSA]: https://www.w3.org/TR/vc-di-eddsa/
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
        reason = "JSON / byte field indexing via `[\"key\"]` or `[0]` is ergonomic inside tests, and `panic!` / `unwrap()` are the idiomatic way to assert expectations with a failure message when a fixture is wrong"
    )
)]

pub mod eddsa_jcs;
mod error;
pub mod jcs;
pub mod multikey_bridge;
mod traits;
mod typed_url;

use serde as _;
use tracing as _;

pub use self::error::Error;
pub use self::traits::{Activity, Actor, Object};
pub use self::typed_url::{CollectionId, ObjectId};

/// Crate [`Result`] alias with the default error type set to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
