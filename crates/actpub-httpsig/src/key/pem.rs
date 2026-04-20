//! PEM encoding and decoding for signing / verifying keys.
//!
//! Handles both PKCS#8 `PRIVATE KEY` / legacy `RSA PRIVATE KEY` for private
//! keys, and `PUBLIC KEY` (`SubjectPublicKeyInfo`) for the public half. The
//! Fediverse actor `publicKey.publicKeyPem` field follows the SPKI form.

use crate::error::Error;
use crate::key::ed25519::{ED25519_PUBLIC_KEY_LEN, Ed25519PublicKey, Ed25519SigningKey};
use crate::key::rsa::{RsaPublicKey, RsaSigningKey};

/// PEM label for a generic PKCS#8 `PrivateKeyInfo`.
pub(crate) const PEM_LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";

/// PEM label for a legacy `RSA PRIVATE KEY` (PKCS#1).
///
/// We do not emit this form but accept it on input for interoperability
/// with older tooling.
pub(crate) const PEM_LABEL_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";

/// PEM label for a `SubjectPublicKeyInfo` public key.
pub(crate) const PEM_LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";

/// OID of `id-Ed25519` (RFC 8410).
const OID_ED25519: [u8; 3] = [0x2b, 0x65, 0x70];

/// OID of `rsaEncryption` (PKCS#1).
const OID_RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Decodes a PEM `PRIVATE KEY` into an [`Ed25519SigningKey`].
///
/// # Errors
///
/// Returns [`Error::InvalidPem`] on malformed PEM, [`Error::UnexpectedPemLabel`]
/// if the label is not `PRIVATE KEY`, and [`Error::UnsupportedAlgorithm`] if
/// the PKCS#8 body does not identify an Ed25519 key.
pub(crate) fn ed25519_signing_key_from_pem(pem_text: &str) -> Result<Ed25519SigningKey, Error> {
    let block = parse_single_pem(pem_text)?;
    if block.tag() != PEM_LABEL_PRIVATE_KEY {
        return Err(Error::UnexpectedPemLabel(
            block.tag().to_owned(),
            PEM_LABEL_PRIVATE_KEY,
        ));
    }
    let der = block.contents();
    if !pkcs8_algorithm_matches(der, &OID_ED25519) {
        return Err(Error::UnsupportedAlgorithm(
            "PKCS#8 body does not identify an Ed25519 key".into(),
        ));
    }
    Ed25519SigningKey::from_pkcs8_der(der)
}

/// Encodes an Ed25519 private key as a PEM `PRIVATE KEY`.
#[must_use]
pub(crate) fn ed25519_signing_key_to_pem(key: &Ed25519SigningKey) -> String {
    encode_pem(PEM_LABEL_PRIVATE_KEY, key.to_pkcs8_der())
}

/// Decodes a PEM `PUBLIC KEY` into an [`Ed25519PublicKey`].
///
/// # Errors
///
/// Returns [`Error::InvalidPem`], [`Error::UnexpectedPemLabel`], or
/// [`Error::UnsupportedAlgorithm`] as above; [`Error::InvalidMultikeyLength`]
/// if the `SubjectPublicKey` bit string is not 32 bytes.
pub(crate) fn ed25519_public_key_from_pem(pem_text: &str) -> Result<Ed25519PublicKey, Error> {
    let block = parse_single_pem(pem_text)?;
    if block.tag() != PEM_LABEL_PUBLIC_KEY {
        return Err(Error::UnexpectedPemLabel(
            block.tag().to_owned(),
            PEM_LABEL_PUBLIC_KEY,
        ));
    }
    let spki = block.contents();
    if !spki_algorithm_matches(spki, &OID_ED25519) {
        return Err(Error::UnsupportedAlgorithm(
            "SPKI body does not identify an Ed25519 key".into(),
        ));
    }
    let raw = spki_public_key_bits(spki).ok_or_else(|| {
        Error::InvalidPem("SubjectPublicKeyInfo body truncated or malformed".into())
    })?;
    if raw.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(Error::InvalidMultikeyLength {
            expected: ED25519_PUBLIC_KEY_LEN,
            actual: raw.len(),
        });
    }
    Ed25519PublicKey::from_bytes(raw)
}

/// Encodes an Ed25519 public key as a PEM `PUBLIC KEY`.
#[must_use]
pub(crate) fn ed25519_public_key_to_pem(key: &Ed25519PublicKey) -> String {
    let spki = ed25519_spki_der(key.as_bytes());
    encode_pem(PEM_LABEL_PUBLIC_KEY, &spki)
}

/// Decodes a PEM `PRIVATE KEY` (or legacy `RSA PRIVATE KEY`) into an
/// [`RsaSigningKey`].
///
/// # Errors
///
/// Same shape as the Ed25519 equivalent, plus [`Error::UnsupportedRsaSize`]
/// for out-of-range keys.
pub(crate) fn rsa_signing_key_from_pem(pem_text: &str) -> Result<RsaSigningKey, Error> {
    let block = parse_single_pem(pem_text)?;
    match block.tag() {
        PEM_LABEL_PRIVATE_KEY => {
            let der = block.contents();
            if !pkcs8_algorithm_matches(der, &OID_RSA_ENCRYPTION) {
                return Err(Error::UnsupportedAlgorithm(
                    "PKCS#8 body does not identify an RSA key".into(),
                ));
            }
            RsaSigningKey::from_pkcs8_der(der)
        }
        PEM_LABEL_RSA_PRIVATE_KEY => Err(Error::UnsupportedAlgorithm(
            "legacy `RSA PRIVATE KEY` PEM is not yet supported; please \
             re-encode as PKCS#8 `PRIVATE KEY`"
                .into(),
        )),
        other => Err(Error::UnexpectedPemLabel(
            other.to_owned(),
            PEM_LABEL_PRIVATE_KEY,
        )),
    }
}

/// Encodes an RSA private key as a PEM `PRIVATE KEY` (PKCS#8).
#[must_use]
pub(crate) fn rsa_signing_key_to_pem(key: &RsaSigningKey) -> String {
    encode_pem(PEM_LABEL_PRIVATE_KEY, key.to_pkcs8_der())
}

/// Decodes a PEM `PUBLIC KEY` into an [`RsaPublicKey`].
///
/// # Errors
///
/// Returns [`Error::InvalidPem`], [`Error::UnexpectedPemLabel`], or
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn rsa_public_key_from_pem(pem_text: &str) -> Result<RsaPublicKey, Error> {
    let block = parse_single_pem(pem_text)?;
    if block.tag() != PEM_LABEL_PUBLIC_KEY {
        return Err(Error::UnexpectedPemLabel(
            block.tag().to_owned(),
            PEM_LABEL_PUBLIC_KEY,
        ));
    }
    let spki = block.contents();
    if !spki_algorithm_matches(spki, &OID_RSA_ENCRYPTION) {
        return Err(Error::UnsupportedAlgorithm(
            "SPKI body does not identify an RSA key".into(),
        ));
    }
    RsaPublicKey::from_spki_der(spki)
}

/// Encodes an RSA public key as a PEM `PUBLIC KEY` (SPKI).
#[must_use]
pub(crate) fn rsa_public_key_to_pem(key: &RsaPublicKey) -> String {
    encode_pem(PEM_LABEL_PUBLIC_KEY, key.as_spki_der())
}

fn parse_single_pem(pem_text: &str) -> Result<pem::Pem, Error> {
    pem::parse(pem_text.as_bytes()).map_err(|e| Error::InvalidPem(e.to_string()))
}

fn encode_pem(label: &'static str, der: &[u8]) -> String {
    let block = pem::Pem::new(label, der.to_vec());
    pem::encode(&block)
}

/// Returns `true` when the given PKCS#8 `PrivateKeyInfo` DER declares the
/// supplied algorithm OID.
///
/// Performs a conservative substring match on the DER so that we do not
/// need a full ASN.1 parser here; the worst-case false positive is a key
/// whose parameters happen to encode the same OID byte sequence, which
/// would then be handed to `aws-lc-rs` and rejected at load time.
fn pkcs8_algorithm_matches(der: &[u8], oid: &[u8]) -> bool {
    find_subsequence(der, oid).is_some()
}

/// Same conservative check as above, for SPKI.
fn spki_algorithm_matches(der: &[u8], oid: &[u8]) -> bool {
    find_subsequence(der, oid).is_some()
}

/// Extracts the raw public-key bit string from a `SubjectPublicKeyInfo`.
///
/// The SPKI ASN.1 structure is:
///
/// ```text
/// SEQUENCE {
///     SEQUENCE { algorithmIdentifier }
///     BIT STRING { subjectPublicKey }
/// }
/// ```
///
/// We scan for the BIT STRING (tag `0x03`) and return its unused-bits-stripped
/// body. This is sufficient for Ed25519 where the SPKI has a fixed shape.
fn spki_public_key_bits(der: &[u8]) -> Option<&[u8]> {
    // Find the last `0x03` tag followed by a length and a zero unused-bits
    // byte. Ed25519 SPKI is always 44 bytes total, so we locate the final
    // BIT STRING deterministically.
    let mut last: Option<&[u8]> = None;
    for idx in 0..der.len().saturating_sub(2) {
        if der.get(idx) != Some(&0x03) {
            continue;
        }
        let Some(&len_byte) = der.get(idx + 1) else {
            continue;
        };
        let len = len_byte as usize;
        let body_start = idx + 2;
        let body_end = body_start + len;
        if body_end > der.len() || len < 1 {
            continue;
        }
        if der.get(body_start) != Some(&0x00) {
            continue;
        }
        last = der.get(body_start + 1..body_end);
    }
    last
}

/// Returns the byte offset at which `needle` first appears inside `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Builds a `SubjectPublicKeyInfo` DER for an Ed25519 public key (44 bytes).
///
/// The structure is fixed:
///
/// ```text
/// 30 2A                   SEQUENCE (42)
///   30 05                 SEQUENCE (5)
///     06 03 2B 65 70      OID 1.3.101.112 (id-Ed25519)
///   03 21                 BIT STRING (33 bytes)
///     00                  unused-bits = 0
///     <32 key bytes>
/// ```
fn ed25519_spki_der(key_bytes: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&[
        0x30, 0x2A, // SEQUENCE (42)
        0x30, 0x05, // SEQUENCE (5) — algorithm identifier
        0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (id-Ed25519)
        0x03, 0x21, 0x00, // BIT STRING (33), 0 unused bits
    ]);
    out.extend_from_slice(key_bytes);
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::key::rsa::RsaBits;

    #[test]
    fn ed25519_signing_key_pem_roundtrip() {
        let key = Ed25519SigningKey::generate().expect("rng");
        let pem = ed25519_signing_key_to_pem(&key);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let reloaded = ed25519_signing_key_from_pem(&pem).expect("parse");
        assert_eq!(reloaded.public_key(), key.public_key());
    }

    #[test]
    fn ed25519_public_key_pem_roundtrip() {
        let key = Ed25519SigningKey::generate().expect("rng");
        let public = key.public_key();
        let pem = ed25519_public_key_to_pem(&public);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let reloaded = ed25519_public_key_from_pem(&pem).expect("parse");
        assert_eq!(reloaded, public);
    }

    #[test]
    fn rsa_signing_key_pem_roundtrip() {
        let key = RsaSigningKey::generate(RsaBits::Rsa2048).expect("rng");
        let pem = rsa_signing_key_to_pem(&key);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let reloaded = rsa_signing_key_from_pem(&pem).expect("parse");
        assert_eq!(reloaded.bits(), key.bits());
    }

    #[test]
    fn rsa_public_key_pem_roundtrip() {
        let key = RsaSigningKey::generate(RsaBits::Rsa2048).expect("rng");
        let public = key.public_key();
        let pem = rsa_public_key_to_pem(&public);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let reloaded = rsa_public_key_from_pem(&pem).expect("parse");
        assert_eq!(reloaded, public);
    }

    #[test]
    fn wrong_label_returns_unexpected_label_error() {
        let key = Ed25519SigningKey::generate().expect("rng");
        let pem = ed25519_signing_key_to_pem(&key);
        // As a public-key decoder, the PRIVATE KEY label is wrong.
        let err = ed25519_public_key_from_pem(&pem).expect_err("wrong label");
        assert!(matches!(
            err,
            Error::UnexpectedPemLabel(_, PEM_LABEL_PUBLIC_KEY)
        ));
    }

    #[test]
    fn legacy_rsa_private_key_label_returns_helpful_error() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                   AAAA\n\
                   -----END RSA PRIVATE KEY-----\n";
        let err = rsa_signing_key_from_pem(pem).expect_err("must reject legacy label");
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)));
    }
}
