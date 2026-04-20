//! Legacy `Digest:` header (Cavage-style), RFC 3230 / RFC 5843.
//!
//! Fediverse servers add a `Digest: SHA-256=<base64>` header to signed
//! `POST` requests so that the signature can bind the body without
//! actually hashing it into the signature base itself. The modern
//! replacement is RFC 9530 `Content-Digest` (see [`crate::content_digest`]),
//! but Mastodon and its siblings still mandate the legacy form today.

use aws_lc_rs::digest::{self, SHA256};
use base64ct::{Base64, Encoding};

use crate::error::Error;

/// Prefix emitted in the legacy `Digest:` header for SHA-256.
///
/// RFC 5843 defines the token case-insensitively as `SHA-256`; this crate
/// emits it in the exact casing used by every major Fediverse
/// implementation.
pub const SHA256_DIGEST_PREFIX: &str = "SHA-256=";

/// Computes the legacy `Digest:` header value for `body`.
///
/// Returns a string of the form `SHA-256=<base64>`, ready to insert as an
/// HTTP header value.
#[must_use]
pub fn sha256_digest_header(body: &[u8]) -> String {
    let hash = digest::digest(&SHA256, body);
    let encoded = Base64::encode_string(hash.as_ref());
    format!("{SHA256_DIGEST_PREFIX}{encoded}")
}

/// Verifies that the `Digest:` header value matches the computed digest of
/// `body`.
///
/// Accepts only the `SHA-256` algorithm; other algorithms result in
/// [`Error::UnsupportedDigestAlgorithm`], matching Fediverse practice.
///
/// # Errors
///
/// Returns [`Error::UnsupportedDigestAlgorithm`] if the header prefix is
/// not `SHA-256=`, [`Error::InvalidBase64`] if the base64 body is
/// malformed, and [`Error::DigestMismatch`] if the hash does not match.
pub fn verify_digest_header(header: &str, body: &[u8]) -> Result<(), Error> {
    let encoded = header
        .strip_prefix(SHA256_DIGEST_PREFIX)
        .or_else(|| header.strip_prefix("sha-256="))
        .or_else(|| header.strip_prefix("Sha-256="))
        .ok_or_else(|| {
            let algo = header
                .split_once('=')
                .map_or_else(|| header.to_owned(), |(a, _)| a.to_owned());
            Error::UnsupportedDigestAlgorithm(algo)
        })?;

    let expected = digest::digest(&SHA256, body);

    let mut buf = [0u8; 32];
    let actual = Base64::decode(encoded, &mut buf)?;
    if actual.len() != 32 {
        return Err(Error::DigestMismatch);
    }
    if !constant_time_eq(actual, expected.as_ref()) {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}

/// Constant-time byte comparison.
///
/// Using a variable-time `==` here would leak timing information about
/// where a mismatch occurs, which in turn would let an attacker forge
/// partial digests byte-by-byte.
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

    /// SHA-256 of the empty string, pre-computed and base64-encoded.
    const EMPTY_SHA256_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    #[test]
    fn sha256_digest_of_empty_body_matches_vector() {
        let header = sha256_digest_header(b"");
        assert_eq!(header, format!("{SHA256_DIGEST_PREFIX}{EMPTY_SHA256_B64}"));
    }

    #[test]
    fn digest_roundtrips_through_verify() {
        let body = b"Hello, Fediverse!";
        let header = sha256_digest_header(body);
        verify_digest_header(&header, body).expect("digest must verify");
    }

    #[test]
    fn tampered_body_fails_verify() {
        let header = sha256_digest_header(b"original body");
        let err = verify_digest_header(&header, b"tampered body")
            .expect_err("tampered body must not verify");
        assert!(matches!(err, Error::DigestMismatch));
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let err =
            verify_digest_header("SHA-512=abcdef", b"").expect_err("SHA-512 must be rejected");
        match err {
            Error::UnsupportedDigestAlgorithm(algo) => assert_eq!(algo, "SHA-512"),
            other => panic!("expected UnsupportedDigestAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn lowercase_algorithm_token_is_accepted() {
        // Some client libraries emit the token lowercased.
        let body = b"interop tolerance";
        let upper = sha256_digest_header(body);
        let encoded = upper
            .strip_prefix(SHA256_DIGEST_PREFIX)
            .expect("has prefix");
        let lower = format!("sha-256={encoded}");
        verify_digest_header(&lower, body).expect("lowercase prefix must be accepted");
    }
}
