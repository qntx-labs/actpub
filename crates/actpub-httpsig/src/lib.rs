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
//! - `rsa-sha256` (2048/4096-bit) — legacy main-key format, required for
//!   interop with current Mastodon
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
//! [cavage]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
//! [rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
//! [aws-lc-rs]: https://docs.rs/aws-lc-rs
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    unused_crate_dependencies,
    dead_code,
    unused_imports,
    missing_docs,
    reason = "crate is a scaffold; dependencies are declared up-front so that implementation work in later phases does not churn the manifest. Remove this allow once the crate has concrete items."
)]
