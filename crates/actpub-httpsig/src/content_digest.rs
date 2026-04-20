//! [RFC 9530] `Content-Digest:` header.
//!
//! The modern successor to the legacy `Digest:` header implemented in
//! [`crate::digest`]. Its value is a Structured Field dictionary whose
//! keys are hash-algorithm names and whose values are byte sequences
//! (`:<base64>:`) per RFC 8941.
//!
//! Example wire value:
//!
//! ```text
//! Content-Digest: sha-256=:X48E9qOok=:
//! ```
//!
//! Mastodon 4.5+ accepts both `Digest:` and `Content-Digest:`; we emit
//! the legacy form for maximum compatibility and verify either on
//! incoming requests.
//!
//! [RFC 9530]: https://www.rfc-editor.org/rfc/rfc9530.html

use aws_lc_rs::digest::{self, SHA256};
use sfv::{BareItem, Dictionary, Item, ListEntry, Parser, SerializeValue};

use crate::error::Error;

/// Name of the `Content-Digest:` HTTP header.
pub const CONTENT_DIGEST_HEADER: &str = "content-digest";

/// Computes the RFC 9530 `Content-Digest:` header value carrying only a
/// `sha-256` entry.
///
/// # Panics
///
/// Panics only if `sfv` fails to serialise a single-entry `sha-256`
/// dictionary; this is unreachable for any well-formed byte sequence.
#[must_use]
pub fn content_digest_header(body: &[u8]) -> String {
    let hash = digest::digest(&SHA256, body);
    let mut dict = Dictionary::new();
    dict.insert(
        "sha-256".into(),
        ListEntry::Item(Item::new(BareItem::ByteSeq(hash.as_ref().to_vec()))),
    );
    #[allow(
        clippy::expect_used,
        reason = "serialising a single-entry ByteSeq dictionary cannot fail"
    )]
    dict.serialize_value()
        .expect("ByteSeq dictionary is always serialisable")
}

/// Verifies that the `Content-Digest:` header value matches the computed
/// digest of `body`.
///
/// Accepts dictionaries containing at least one `sha-256` entry; other
/// algorithms, if present, are ignored.
///
/// # Errors
///
/// Returns [`Error::UnsupportedDigestAlgorithm`] if no supported entry is
/// present, [`Error::InvalidHeader`] on structured-field parse failure,
/// and [`Error::DigestMismatch`] if the hash does not match.
pub fn verify_content_digest_header(header: &str, body: &[u8]) -> Result<(), Error> {
    let dict = Parser::parse_dictionary(header.as_bytes()).map_err(|e| Error::InvalidHeader {
        name: "content-digest",
        reason: e.to_owned(),
    })?;

    let Some(entry) = dict.get("sha-256") else {
        return Err(Error::UnsupportedDigestAlgorithm(
            "Content-Digest does not contain an sha-256 entry".to_owned(),
        ));
    };

    let item = match entry {
        ListEntry::Item(item) => item,
        ListEntry::InnerList(_) => {
            return Err(Error::InvalidHeader {
                name: "content-digest",
                reason: "sha-256 entry must be an item, not an inner list".into(),
            });
        }
    };

    let BareItem::ByteSeq(bytes) = &item.bare_item else {
        return Err(Error::InvalidHeader {
            name: "content-digest",
            reason: "sha-256 value must be a byte sequence".into(),
        });
    };

    let expected = digest::digest(&SHA256, body);
    if !constant_time_eq(bytes, expected.as_ref()) {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}

/// Constant-time byte comparison; see the notes in [`crate::digest`].
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn emits_rfc9530_value_for_empty_body() {
        let header = content_digest_header(b"");
        assert_eq!(
            header,
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    #[test]
    fn roundtrips_sign_then_verify() {
        let body = b"Hello, Fediverse";
        let header = content_digest_header(body);
        verify_content_digest_header(&header, body).expect("matching body must verify");
    }

    #[test]
    fn tampered_body_fails_verify() {
        let header = content_digest_header(b"original");
        let err = verify_content_digest_header(&header, b"tampered")
            .expect_err("tampered body must not verify");
        assert!(matches!(err, Error::DigestMismatch));
    }

    #[test]
    fn missing_sha256_entry_returns_unsupported_algorithm() {
        let header = "sha-512=:AAAA:";
        let err =
            verify_content_digest_header(header, b"").expect_err("sha-512 only must be rejected");
        assert!(matches!(err, Error::UnsupportedDigestAlgorithm(_)));
    }

    #[test]
    fn malformed_structured_field_is_rejected() {
        // An unclosed inner list is a genuine sf-dictionary parse failure.
        let err = verify_content_digest_header("sha-256=(unclosed", b"").expect_err("malformed");
        assert!(
            matches!(err, Error::InvalidHeader { .. }),
            "expected InvalidHeader, got {err:?}",
        );
    }

    #[test]
    fn mixed_algorithm_dictionary_accepts_on_sha256_match() {
        let body = b"payload";
        let sha256 = content_digest_header(body)
            .strip_prefix("sha-256=")
            .expect("has prefix")
            .to_owned();
        let mixed = format!("sha-512=:AAAA:, sha-256={sha256}");
        verify_content_digest_header(&mixed, body)
            .expect("dictionaries with extra algorithms are fine");
    }
}
