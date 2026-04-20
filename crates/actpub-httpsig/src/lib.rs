//! Dual-stack HTTP message signatures for `ActivityPub`.
//!
//! Provides signing and verification for both:
//!
//! - [Cavage draft-12][cavage] — the de-facto Fediverse standard (Mastodon,
//!   Pleroma, Lemmy, Misskey, …)
//! - [RFC 9421][rfc9421] — the finalized IETF HTTP Message Signatures standard
//!   (Mastodon 4.5+ accepts both)
//!
//! Algorithms supported out of the box:
//!
//! - `rsa-sha256` (2048–8192-bit modulus) — legacy main-key format,
//!   required for interop with current Mastodon; [`RsaBits`] exposes
//!   the conventional 2048 and 4096 presets for generation, and
//!   [`RsaSigningKey::from_pkcs8_der`] accepts any byte-aligned width
//!   in the full range
//! - `ed25519` — FEP-521a Multikey, recommended for new deployments
//!
//! All cryptographic primitives are backed by [aws-lc-rs], a memory-safe,
//! constant-time, FIPS 140-3 validated library maintained by AWS. This crate
//! is therefore **not** affected by [RUSTSEC-2023-0071] (Marvin Attack) that
//! impacts the pure-Rust `rsa` crate.
//!
//! The crate is HTTP-framework agnostic: it operates on [`http::Request`]
//! values and leaves transport to the caller.
//!
//! # Example — Cavage signing
//!
//! ```
//! # use actpub_httpsig::{SigningKey, CavageSigner, sha256_digest_header};
//! # use http::{Request, Method};
//! let key = SigningKey::generate_ed25519();
//! let body: Vec<u8> = br#"{"type":"Follow"}"#.to_vec();
//! let mut req = Request::builder()
//!     .method(Method::POST)
//!     .uri("https://example.com/inbox")
//!     .header("host", "example.com")
//!     .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
//!     .header("digest", sha256_digest_header(&body))
//!     .header("content-type", "application/activity+json")
//!     .body(body)
//!     .unwrap();
//!
//! let signer = CavageSigner::new(&key, "https://example.com/users/alice#main-key");
//! signer.sign(&mut req).unwrap();
//! assert!(req.headers().contains_key("signature"));
//! ```
//!
//! [cavage]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
//! [rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
//! [aws-lc-rs]: https://docs.rs/aws-lc-rs
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
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

mod cavage;
mod content_digest;
mod digest;
mod error;
mod http_shared;
mod key;
mod policy;
mod rfc9421;
mod verify;

use bytes as _;
use pkcs8 as _;
#[cfg(test)]
use tokio as _;
use tracing as _;
use url as _;

pub use self::cavage::{
    CavageHeaderParams, CavageHeaderSet, CavageSigner, CavageVerified, DEFAULT_HEADER_SET,
    SIGNATURE_HEADER, cavage_verify, cavage_verify_with_policy,
};
pub use self::content_digest::{
    CONTENT_DIGEST_HEADER, DigestAlgorithm, content_digest_header, content_digest_header_with,
    verify_any_content_digest_header, verify_content_digest_header,
};
pub use self::digest::{SHA256_DIGEST_PREFIX, sha256_digest_header, verify_digest_header};
pub use self::error::Error;
pub use self::key::{
    Algorithm, Ed25519PublicKey, Ed25519SigningKey, Multikey, RsaBits, RsaPublicKey, RsaSigningKey,
    SigningKey, VerifyingKey,
};
pub use self::policy::{CAVAGE_REQUIRED_HEADERS, VerifyPolicy};
pub use self::rfc9421::{
    Component, DEFAULT_COMPONENTS as RFC9421_DEFAULT_COMPONENTS, Rfc9421Signer, Rfc9421Verified,
    SIGNATURE_INPUT_HEADER, SignatureInput, parse_signature_dict, parse_signature_input_dict,
    rfc9421_verify, rfc9421_verify_with_policy, serialise_signature_dict,
    serialise_signature_input_dict,
};
pub use self::verify::{REDACTED_HEADERS_DEFAULT, Verified, verify, verify_with_policy};

/// Crate [`Result`] alias with the default error type set to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;
