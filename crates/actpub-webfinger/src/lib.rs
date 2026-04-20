//! WebFinger (RFC 7033) primitives for ActivityPub account discovery.
//!
//! WebFinger is the discovery mechanism used across the Fediverse to map
//! `acct:user@host` identifiers to ActivityPub actor URLs via a
//! [`/.well-known/webfinger`][endpoint] endpoint returning a JSON Resource
//! Descriptor (JRD).
//!
//! [endpoint]: https://datatracker.ietf.org/doc/html/rfc7033#section-4
#![cfg_attr(docsrs, feature(doc_cfg))]
