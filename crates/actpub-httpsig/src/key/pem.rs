//! PEM encoding and decoding for signing / verifying keys.
//!
//! Handles both PKCS#8 `PRIVATE KEY` / legacy `RSA PRIVATE KEY` for private
//! keys, and `PUBLIC KEY` (`SubjectPublicKeyInfo`) for the public half. The
//! Fediverse actor `publicKey.publicKeyPem` field follows the SPKI form.

use pkcs8::der::asn1::AnyRef;
use pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfoRef,
    der::{Decode, Encode},
};

use crate::error::Error;
use crate::key::ed25519::{ED25519_PUBLIC_KEY_LEN, Ed25519PublicKey, Ed25519SigningKey};
use crate::key::rsa::{RsaPublicKey, RsaSigningKey};

/// PEM label for a generic PKCS#8 `PrivateKeyInfo`.
pub(crate) const PEM_LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";

/// PEM label for a legacy `RSA PRIVATE KEY` (PKCS#1).
///
/// Accepted on input for interoperability with OpenSSL-generated keys
/// and Fediverse implementations that still emit PKCS#1. We re-encode
/// such keys to PKCS#8 before handing them to the cryptographic backend.
pub(crate) const PEM_LABEL_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";

/// PEM label for a `SubjectPublicKeyInfo` public key.
pub(crate) const PEM_LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";

/// `id-Ed25519` (RFC 8410).
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `rsaEncryption` (RFC 8017, PKCS#1).
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

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
    let oid = parse_pkcs8_algorithm_oid(der)?;
    if oid != OID_ED25519 {
        return Err(Error::UnsupportedAlgorithm(format!(
            "PKCS#8 body identifies algorithm {oid}, expected id-Ed25519 (1.3.101.112)"
        )));
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
    let (oid, bits) = parse_spki(block.contents())?;
    if oid != OID_ED25519 {
        return Err(Error::UnsupportedAlgorithm(format!(
            "SPKI body identifies algorithm {oid}, expected id-Ed25519 (1.3.101.112)"
        )));
    }
    if bits.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(Error::InvalidMultikeyLength {
            expected: ED25519_PUBLIC_KEY_LEN,
            actual: bits.len(),
        });
    }
    Ed25519PublicKey::from_bytes(bits)
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
/// Both PKCS#8 `PrivateKeyInfo` and the legacy PKCS#1 `RSAPrivateKey`
/// envelopes are accepted on input; the latter is wrapped into PKCS#8
/// on the fly before being handed to the cryptographic backend, so
/// callers never need to shell out to OpenSSL just to re-encode.
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
            let oid = parse_pkcs8_algorithm_oid(der)?;
            if oid != OID_RSA_ENCRYPTION {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "PKCS#8 body identifies algorithm {oid}, expected rsaEncryption \
                     (1.2.840.113549.1.1.1)"
                )));
            }
            RsaSigningKey::from_pkcs8_der(der)
        }
        PEM_LABEL_RSA_PRIVATE_KEY => {
            let pkcs8 = wrap_pkcs1_rsa_as_pkcs8(block.contents())?;
            RsaSigningKey::from_pkcs8_der(&pkcs8)
        }
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
    let (oid, _bits) = parse_spki(block.contents())?;
    if oid != OID_RSA_ENCRYPTION {
        return Err(Error::UnsupportedAlgorithm(format!(
            "SPKI body identifies algorithm {oid}, expected rsaEncryption \
             (1.2.840.113549.1.1.1)"
        )));
    }
    RsaPublicKey::from_spki_der(block.contents())
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

/// Extracts the `algorithm.oid` field from a PKCS#8 `PrivateKeyInfo`
/// DER blob via a full ASN.1 parse. Replaces the old substring heuristic
/// so that we never misclassify a key whose parameters happen to contain
/// a byte sequence overlapping an unrelated OID.
fn parse_pkcs8_algorithm_oid(der: &[u8]) -> Result<ObjectIdentifier, Error> {
    let info = PrivateKeyInfo::from_der(der).map_err(|e| Error::InvalidPkcs8(e.to_string()))?;
    Ok(info.algorithm.oid)
}

/// Parses a `SubjectPublicKeyInfo` DER blob into its algorithm OID and
/// the raw `subjectPublicKey` bit string bytes.
fn parse_spki(der: &[u8]) -> Result<(ObjectIdentifier, &[u8]), Error> {
    let spki =
        SubjectPublicKeyInfoRef::from_der(der).map_err(|e| Error::InvalidPem(e.to_string()))?;
    let bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
        Error::InvalidPem(
            "SubjectPublicKeyInfo.subjectPublicKey is not a well-formed BIT STRING".into(),
        )
    })?;
    Ok((spki.algorithm.oid, bits))
}

/// Wraps a PKCS#1 `RSAPrivateKey` DER blob in the PKCS#8 envelope
/// expected by `aws-lc-rs`, attaching the `rsaEncryption` algorithm
/// identifier with the mandatory NULL parameters.
fn wrap_pkcs1_rsa_as_pkcs8(pkcs1_der: &[u8]) -> Result<Vec<u8>, Error> {
    let info = PrivateKeyInfo::new(
        AlgorithmIdentifierRef {
            oid: OID_RSA_ENCRYPTION,
            parameters: Some(AnyRef::NULL),
        },
        pkcs1_der,
    );
    info.to_der().map_err(|e| Error::InvalidPem(e.to_string()))
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
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
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
    fn malformed_rsa_private_key_pem_is_rejected() {
        // Valid PEM framing but the body is not a well-formed PKCS#1
        // RSAPrivateKey, so the PKCS#8 wrapper produces junk DER that
        // the backend refuses. The observable error kind is not
        // specified here — we only care that it fails cleanly.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                   AAAA\n\
                   -----END RSA PRIVATE KEY-----\n";
        rsa_signing_key_from_pem(pem).expect_err("malformed PKCS#1 body must fail");
    }

    #[test]
    fn legacy_pkcs1_rsa_private_key_pem_is_accepted() {
        // Round-trip a freshly generated RSA key through the PKCS#1
        // envelope to verify the on-the-fly wrapper produces a PKCS#8
        // blob the backend accepts.
        let key = RsaSigningKey::generate(RsaBits::Rsa2048).expect("rng");
        let pkcs8_pem = rsa_signing_key_to_pem(&key);
        // Convert the PKCS#8 `PRIVATE KEY` PEM to a `RSA PRIVATE KEY`
        // PEM by unwrapping the PKCS#8 OCTET STRING back to the
        // PKCS#1 body. The test below does this the cheap way by
        // asking `pkcs8` to parse and then re-emitting just the
        // `private_key` field.
        let pkcs8_der = {
            let block = parse_single_pem(&pkcs8_pem).expect("re-parse");
            block.contents().to_vec()
        };
        let pkcs1_body = {
            let info = PrivateKeyInfo::from_der(&pkcs8_der).expect("pkcs8 decode");
            info.private_key.to_vec()
        };
        let pkcs1_pem = encode_pem(PEM_LABEL_RSA_PRIVATE_KEY, &pkcs1_body);
        let reloaded = rsa_signing_key_from_pem(&pkcs1_pem).expect("accept PKCS#1");
        assert_eq!(reloaded.bits(), key.bits());
    }

    #[test]
    fn pkcs8_with_non_rsa_oid_reports_algorithm_mismatch() {
        // An Ed25519 PKCS#8 fed into the RSA loader must surface a
        // precise algorithm-mismatch error rather than a low-level
        // backend message.
        let ed = Ed25519SigningKey::generate().expect("rng");
        let pem = ed25519_signing_key_to_pem(&ed);
        let err = rsa_signing_key_from_pem(&pem).expect_err("Ed25519 key must not load as RSA");
        assert!(matches!(err, Error::UnsupportedAlgorithm(msg) if msg.contains("rsaEncryption")));
    }
}
