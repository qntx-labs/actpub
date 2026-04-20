//! [RFC 9530] `Content-Digest:` header with multi-algorithm support.
//!
//! The modern successor to the legacy `Digest:` header implemented in
//! [`crate::digest`]. Its value is a Structured Field dictionary whose
//! keys are hash-algorithm names and whose values are byte sequences
//! (`:<base64>:`) per RFC 8941, allowing one header to carry several
//! digest algorithms simultaneously:
//!
//! ```text
//! Content-Digest: sha-256=:X48…=:, sha-512=:9KQ…=:
//! ```
//!
//! Mastodon today emits only `sha-256`; Mitra and Takahē are migrating
//! to multi-algorithm `sha-256`+`sha-512` headers. This module supports
//! both the legacy single-algorithm and the modern multi-algorithm
//! shapes on read and write paths.
//!
//! # Wire-up at a glance
//!
//! - **Outgoing**: [`content_digest_header`] for the conventional
//!   single-algorithm SHA-256 case, or
//!   [`content_digest_header_with`] for arbitrary algorithm sets.
//! - **Incoming**: [`verify_content_digest_header`] requires SHA-256 to
//!   match (matches Mastodon today); [`verify_any_content_digest_header`]
//!   succeeds if **any** algorithm in the supplied accepted list
//!   verifies, suitable for liberal interoperability.
//!
//! [RFC 9530]: https://www.rfc-editor.org/rfc/rfc9530.html

use aws_lc_rs::digest::{self, SHA256, SHA512};
use sfv::{BareItem, Dictionary, Item, ListEntry, Parser, SerializeValue};

use crate::error::Error;

/// Name of the `Content-Digest:` HTTP header.
pub const CONTENT_DIGEST_HEADER: &str = "content-digest";

/// A hash algorithm registered with the IANA Hash Algorithm Names
/// registry and accepted by RFC 9530 `Content-Digest`.
///
/// Only the algorithms the Fediverse actually uses today are
/// enumerated; future algorithms can be added without breaking the wire
/// format because the variant set is `#[non_exhaustive]`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 — universally supported by today's Fediverse.
    Sha256,
    /// SHA-512 — emitted by Mitra and Takahē, accepted by
    /// Mastodon 4.5+.
    Sha512,
}

impl DigestAlgorithm {
    /// IANA-registered token used as the dictionary key in the wire
    /// header.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
        }
    }

    /// Computes the digest bytes of `body` under this algorithm.
    #[must_use]
    pub fn hash(self, body: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => digest::digest(&SHA256, body).as_ref().to_vec(),
            Self::Sha512 => digest::digest(&SHA512, body).as_ref().to_vec(),
        }
    }

    /// Parses the IANA token into an algorithm variant. Returns `None`
    /// for tokens this crate does not recognise.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "sha-256" => Some(Self::Sha256),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Computes the conventional Mastodon-compatible single-algorithm
/// `Content-Digest:` value carrying only a `sha-256` entry.
///
/// Equivalent to
/// `content_digest_header_with(body, &[DigestAlgorithm::Sha256])` but
/// kept as a stable convenience entry point.
#[must_use]
pub fn content_digest_header(body: &[u8]) -> String {
    content_digest_header_with(body, &[DigestAlgorithm::Sha256])
}

/// Computes a multi-algorithm `Content-Digest:` value carrying one
/// dictionary entry per requested algorithm, in the order they are
/// supplied.
///
/// # Panics
///
/// Panics only if `sfv` fails to serialise a `ByteSeq`-only dictionary;
/// this is unreachable for any well-formed input.
#[must_use]
pub fn content_digest_header_with(body: &[u8], algorithms: &[DigestAlgorithm]) -> String {
    let mut dict = Dictionary::new();
    for algo in algorithms {
        dict.insert(
            algo.token().into(),
            ListEntry::Item(Item::new(BareItem::ByteSeq(algo.hash(body)))),
        );
    }
    #[allow(
        clippy::expect_used,
        reason = "serialising a ByteSeq-only dictionary cannot fail"
    )]
    dict.serialize_value()
        .expect("ByteSeq dictionary is always serialisable")
}

/// Verifies that the `Content-Digest:` header carries a `sha-256`
/// entry matching `body`.
///
/// This is the strict Mastodon-compatible verifier: it requires SHA-256
/// specifically. To accept any of several algorithms, use
/// [`verify_any_content_digest_header`].
///
/// # Errors
///
/// Returns [`Error::UnsupportedDigestAlgorithm`] if no `sha-256` entry
/// is present, [`Error::InvalidHeader`] on structured-field parse
/// failure, and [`Error::DigestMismatch`] if the hash does not match.
pub fn verify_content_digest_header(header: &str, body: &[u8]) -> Result<(), Error> {
    verify_specific_digest(header, body, DigestAlgorithm::Sha256)
}

/// Verifies that the `Content-Digest:` header carries **at least one**
/// matching entry across the supplied accepted algorithms.
///
/// Iterates `accepted` in caller-supplied priority order; the first
/// algorithm whose dictionary entry matches the body's hash is taken
/// as proof. Algorithms in the header that are not in `accepted` are
/// ignored. If no entry verifies (because none of the accepted
/// algorithms are present, or every matching entry mismatches), the
/// last error encountered is propagated.
///
/// # Errors
///
/// Returns [`Error::UnsupportedDigestAlgorithm`] when none of the
/// accepted algorithms appear in the header, [`Error::InvalidHeader`]
/// on parse failure, and [`Error::DigestMismatch`] when an accepted
/// algorithm appears but its byte sequence does not match the body.
pub fn verify_any_content_digest_header(
    header: &str,
    body: &[u8],
    accepted: &[DigestAlgorithm],
) -> Result<DigestAlgorithm, Error> {
    let dict = parse_content_digest_dict(header)?;

    let mut last_err: Option<Error> = None;
    let mut saw_any = false;
    for algo in accepted {
        let Some(entry) = dict.get(algo.token()) else {
            continue;
        };
        saw_any = true;
        let bytes = match extract_byte_seq(entry, algo.token()) {
            Ok(b) => b,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let expected = algo.hash(body);
        if constant_time_eq(bytes, &expected) {
            return Ok(*algo);
        }
        last_err = Some(Error::DigestMismatch);
    }

    if !saw_any {
        return Err(Error::UnsupportedDigestAlgorithm(format!(
            "Content-Digest carries no entry for any of the accepted algorithms: {}",
            accepted
                .iter()
                .map(|a| a.token())
                .collect::<Vec<_>>()
                .join(", "),
        )));
    }
    Err(last_err.unwrap_or(Error::DigestMismatch))
}

fn verify_specific_digest(header: &str, body: &[u8], algo: DigestAlgorithm) -> Result<(), Error> {
    let dict = parse_content_digest_dict(header)?;

    let Some(entry) = dict.get(algo.token()) else {
        return Err(Error::UnsupportedDigestAlgorithm(format!(
            "Content-Digest does not contain a {} entry",
            algo.token()
        )));
    };

    let bytes = extract_byte_seq(entry, algo.token())?;
    let expected = algo.hash(body);
    if !constant_time_eq(bytes, &expected) {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}

fn parse_content_digest_dict(header: &str) -> Result<Dictionary, Error> {
    Parser::parse_dictionary(header.as_bytes()).map_err(|e| Error::InvalidHeader {
        name: "content-digest",
        reason: e.to_owned(),
    })
}

fn extract_byte_seq<'a>(entry: &'a ListEntry, algo_token: &str) -> Result<&'a [u8], Error> {
    let item = match entry {
        ListEntry::Item(item) => item,
        ListEntry::InnerList(_) => {
            return Err(Error::InvalidHeader {
                name: "content-digest",
                reason: format!("{algo_token} entry must be an item, not an inner list"),
            });
        }
    };
    let BareItem::ByteSeq(bytes) = &item.bare_item else {
        return Err(Error::InvalidHeader {
            name: "content-digest",
            reason: format!("{algo_token} value must be a byte sequence"),
        });
    };
    Ok(bytes)
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

    #[test]
    fn multi_algorithm_header_carries_both_entries_in_order() {
        let body = b"payload";
        let header =
            content_digest_header_with(body, &[DigestAlgorithm::Sha256, DigestAlgorithm::Sha512]);
        assert!(header.starts_with("sha-256=:"), "sha-256 first: {header}");
        assert!(header.contains("sha-512=:"), "sha-512 present: {header}");
    }

    #[test]
    fn verify_any_picks_first_accepted_match() {
        let body = b"payload";
        let header =
            content_digest_header_with(body, &[DigestAlgorithm::Sha256, DigestAlgorithm::Sha512]);
        // Caller prefers SHA-512: it must be picked because both verify.
        let chosen = verify_any_content_digest_header(
            &header,
            body,
            &[DigestAlgorithm::Sha512, DigestAlgorithm::Sha256],
        )
        .expect("any-of must verify");
        assert_eq!(chosen, DigestAlgorithm::Sha512);
    }

    #[test]
    fn verify_any_falls_back_to_second_when_first_absent() {
        let body = b"payload";
        let sha256_only = content_digest_header_with(body, &[DigestAlgorithm::Sha256]);
        let chosen = verify_any_content_digest_header(
            &sha256_only,
            body,
            &[DigestAlgorithm::Sha512, DigestAlgorithm::Sha256],
        )
        .expect("sha-256 fallback must verify");
        assert_eq!(chosen, DigestAlgorithm::Sha256);
    }

    #[test]
    fn verify_any_returns_unsupported_when_no_accepted_algorithm_present() {
        let body = b"payload";
        let sha256_only = content_digest_header_with(body, &[DigestAlgorithm::Sha256]);
        let err = verify_any_content_digest_header(&sha256_only, body, &[DigestAlgorithm::Sha512])
            .expect_err("sha-512 only acceptance must fail when only sha-256 is present");
        assert!(matches!(err, Error::UnsupportedDigestAlgorithm(_)));
    }

    #[test]
    fn verify_any_returns_mismatch_when_only_present_algorithm_disagrees() {
        // SHA-512 entry whose value is a 64-byte zero blob; will not match
        // the actual hash of any non-empty body.
        let header = "sha-512=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:";
        let err = verify_any_content_digest_header(header, b"payload", &[DigestAlgorithm::Sha512])
            .expect_err("mismatched bytes must not verify");
        assert!(matches!(err, Error::DigestMismatch));
    }

    #[test]
    fn algorithm_round_trips_through_token() {
        for algo in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
            let token = algo.token();
            assert_eq!(DigestAlgorithm::from_token(token), Some(algo));
        }
        assert_eq!(DigestAlgorithm::from_token("sha-1"), None);
    }
}
