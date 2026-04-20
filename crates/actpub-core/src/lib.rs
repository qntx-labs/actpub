//! Core `ActivityPub` protocol layer.
//!
//! Defines the three fundamental traits that drive federation:
//!
//! - [`Object`] — anything addressable by an `ActivityPub` `id` URI, with
//!   database <-> wire conversion
//! - [`Actor`] — an `Object` that owns cryptographic keys and mailboxes
//! - [`Activity`] — a verb applied to an object, with verification and
//!   side-effect semantics
//!
//! Additionally, this crate implements the two core security-related FEPs:
//!
//! - [FEP-521a] — Multikey representation of actor public keys
//! - [FEP-8b32] — Data Integrity Proofs (`eddsa-jcs-2022`)
//!
//! [FEP-521a]: https://codeberg.org/fediverse/fep/src/branch/main/fep/521a/fep-521a.md
//! [FEP-8b32]: https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    unused_crate_dependencies,
    dead_code,
    unused_imports,
    missing_docs,
    reason = "crate is a scaffold; dependencies are declared up-front so that implementation work in later phases does not churn the manifest. Remove this allow once the crate has concrete items."
)]
