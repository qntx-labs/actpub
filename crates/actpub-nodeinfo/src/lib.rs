//! `NodeInfo` server metadata protocol for the Fediverse.
//!
//! Implements `NodeInfo` [2.0] / [2.1] and [FEP-0151] (`NodeInfo` 2025 edition),
//! providing both discovery (`/.well-known/nodeinfo`) and schema documents.
//!
//! [2.0]: http://nodeinfo.diaspora.software/ns/schema/2.0
//! [2.1]: http://nodeinfo.diaspora.software/ns/schema/2.1
//! [FEP-0151]: https://codeberg.org/fediverse/fep/src/branch/main/fep/0151/fep-0151.md
#![cfg_attr(docsrs, feature(doc_cfg))]
