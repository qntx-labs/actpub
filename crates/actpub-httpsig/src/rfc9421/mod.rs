//! [RFC 9421][rfc9421] HTTP Message Signatures — the finalised IETF
//! standard that supersedes the Cavage draft.
//!
//! RFC 9421 differs from Cavage in several visible ways:
//!
//! - Header names are **quoted** in the signature base (`"host": example.com`).
//! - Derived components are spelled `"@method"`, `"@target-uri"`,
//!   `"@authority"`, `"@path"`, `"@query"`, `"@scheme"`, `"@status"` —
//!   distinct from Cavage's `(request-target)` pseudo-header.
//! - Parameters live in the `Signature-Input:` header (a Structured Field
//!   dictionary of inner lists), and the signature itself goes into a
//!   separate `Signature:` dictionary keyed by a caller-chosen label.
//! - A trailing `"@signature-params"` line appears in the signature base
//!   and binds the chosen parameter set to the signature.
//!
//! Mastodon 4.5+ accepts both Cavage and RFC 9421 on the receiving side.
//! This crate emits either flavour at the caller's request and verifies
//! both transparently (see [`crate::cavage::cavage_verify`] and
//! [`rfc9421_verify`]).
//!
//! [rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
#![allow(
    unreachable_pub,
    reason = "submodule items are re-exported by this module's `pub use` declarations, but rustc's reachability analysis doesn't follow re-exports across private module boundaries"
)]

mod components;
mod sign;
mod signature;
mod signature_input;
mod verify;

pub use self::components::Component;
pub use self::sign::{DEFAULT_COMPONENTS, Rfc9421Signer};
pub use self::signature::{parse_signature_dict, serialise_signature_dict};
pub use self::signature_input::{
    SIGNATURE_INPUT_HEADER, SignatureInput, parse_signature_input_dict,
    serialise_signature_input_dict,
};
pub use self::verify::{Rfc9421Verified, rfc9421_verify};
