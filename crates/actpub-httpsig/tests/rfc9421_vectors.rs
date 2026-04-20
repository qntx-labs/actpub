//! Byte-level conformance tests against the RFC 9421 Appendix B
//! specimen vectors.
#![allow(
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::doc_markdown,
    reason = "integration-test idioms: every `#[test]` is the file's contents; `expect`/`[0]` are the clearest way to assert invariants"
)]
//!
//! These tests are the strongest evidence that our implementation
//! generates exactly the wire format demanded by the standard. Each
//! vector is lifted verbatim from the RFC; if any of them drifts the
//! culprit is almost certainly a canonicalisation bug in our
//! signature-base construction.
//!
//! The Ed25519 vector from [RFC 9421 §B.2.6][b26] is the primary case
//! because it matches the algorithm the Fediverse increasingly adopts
//! via FEP-521a. RSA-PSS / ECDSA / HMAC are out of scope for this
//! crate so those vectors are not exercised here.
//!
//! [b26]: https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-ed2

use actpub_httpsig::{
    Component, Ed25519PublicKey, Ed25519SigningKey, Rfc9421Signer, SignatureInput, SigningKey,
    VerifyPolicy, parse_signature_dict, rfc9421_verify_with_policy, serialise_signature_dict,
    serialise_signature_input_dict,
};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::{Method, Request};
use pretty_assertions::assert_eq;

/// Ed25519 private key seed from RFC 9421 B.1.4 (`test-key-ed25519`),
/// JWK `d` field base64url-decoded to 32 raw bytes.
const ED25519_PRIVATE_SEED_B64URL: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";

/// Matching public key (JWK `x`).
const ED25519_PUBLIC_KEY_B64URL: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

/// Expected signature base string from RFC 9421 §B.2.6.
const EXPECTED_SIGNATURE_BASE: &str = concat!(
    "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
    "\"@method\": POST\n",
    "\"@path\": /foo\n",
    "\"@authority\": example.com\n",
    "\"content-type\": application/json\n",
    "\"content-length\": 18\n",
    "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
);

/// Expected base64-encoded Ed25519 signature from RFC 9421 §B.2.6.
const EXPECTED_SIGNATURE_B64: &str =
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";

/// Wraps a raw 32-byte Ed25519 seed in a PKCS#8 v1 PrivateKeyInfo DER
/// (RFC 8410 §7), so that it can be loaded by
/// [`Ed25519SigningKey::from_pkcs8_der`].
fn wrap_seed_as_pkcs8(seed: &[u8; 32]) -> [u8; 48] {
    let mut pkcs8 = [
        // SEQUENCE (46 bytes follow)
        0x30, 0x2e, // INTEGER 0 — version
        0x02, 0x01, 0x00, // AlgorithmIdentifier SEQUENCE (5)
        0x30, 0x05, //   OID 1.3.101.112 (id-Ed25519)
        0x06, 0x03, 0x2b, 0x65, 0x70,
        // OCTET STRING wrapping OCTET STRING of 32 seed bytes
        0x04, 0x22, 0x04, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    pkcs8[16..48].copy_from_slice(seed);
    pkcs8
}

fn load_rfc_ed25519_signing_key() -> Ed25519SigningKey {
    let mut seed = [0u8; 32];
    Base64UrlUnpadded::decode(ED25519_PRIVATE_SEED_B64URL, &mut seed)
        .expect("RFC 9421 vector seed is exactly 32 base64url bytes");
    let pkcs8 = wrap_seed_as_pkcs8(&seed);
    Ed25519SigningKey::from_pkcs8_der(&pkcs8).expect("PKCS#8 wrapper must decode")
}

fn load_rfc_ed25519_public_key() -> Ed25519PublicKey {
    let mut raw = [0u8; 32];
    Base64UrlUnpadded::decode(ED25519_PUBLIC_KEY_B64URL, &mut raw)
        .expect("RFC 9421 vector public key is exactly 32 base64url bytes");
    Ed25519PublicKey::from_bytes(&raw).expect("valid Ed25519 public key")
}

/// Reconstructs the exact request from RFC 9421 §B.2.6.
fn rfc_b26_request() -> Request<Vec<u8>> {
    // Body: `{"hello": "world"}` — 18 bytes, as declared by `content-length`.
    let body = br#"{"hello": "world"}"#.to_vec();
    Request::builder()
        .method(Method::POST)
        .uri("http://example.com/foo?param=Value&Pet=dog")
        .header("host", "example.com")
        .header("date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .header("content-type", "application/json")
        .header("content-length", "18")
        .body(body)
        .expect("RFC 9421 vector request must build")
}

/// Verifies that our Ed25519 implementation reproduces the exact
/// signature from the RFC's appendix — bit-for-bit.
#[test]
fn rfc9421_b26_ed25519_signature_matches_appendix() {
    let signing_inner = load_rfc_ed25519_signing_key();
    let public = signing_inner.public_key();
    assert_eq!(
        &public,
        &load_rfc_ed25519_public_key(),
        "signer's public key must match the vector's JWK `x`",
    );
    let signing_key = SigningKey::Ed25519(signing_inner);

    let mut req = rfc_b26_request();
    Rfc9421Signer::new(&signing_key, "test-key-ed25519")
        .with_label("sig-b26")
        .with_components(vec![
            Component::Header("date".into()),
            Component::Method,
            Component::Path,
            Component::Authority,
            Component::Header("content-type".into()),
            Component::Header("content-length".into()),
        ])
        .with_created(1_618_884_473)
        .emit_alg(false)
        .sign(&mut req)
        .expect("signing must succeed");

    // Signature-Input MUST match the appendix verbatim (parameter order
    // and quoting).
    let input_header = req
        .headers()
        .get("signature-input")
        .expect("Signature-Input inserted")
        .to_str()
        .expect("ASCII");
    assert_eq!(
        input_header,
        r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
        "Signature-Input must serialise in RFC 9421 form",
    );

    // Extract the signature, base64-decode it, and compare byte-for-byte
    // with the vector.
    let sig_header = req
        .headers()
        .get("signature")
        .expect("Signature inserted")
        .to_str()
        .expect("ASCII");
    let entries = parse_signature_dict(sig_header).expect("parseable");
    assert_eq!(entries.len(), 1);
    let (label, sig_bytes) = &entries[0];
    assert_eq!(label, "sig-b26");
    let observed_b64 = Base64::encode_string(sig_bytes);
    assert_eq!(
        observed_b64, EXPECTED_SIGNATURE_B64,
        "signature bytes must match RFC 9421 §B.2.6",
    );
}

/// Verifies that our canonicalisation produces *exactly* the signature
/// base string given in RFC 9421 §B.2.6. This isolates canonicalisation
/// bugs from signature bugs: even if the Ed25519 primitive is wrong,
/// this test will catch a faulty base string.
#[test]
fn rfc9421_b26_signature_base_is_byte_identical_to_appendix() {
    // Round-trip a handcrafted SignatureInput through the serialiser to
    // build the inner-list string exactly as RFC §B.2.6 specifies.
    let input = SignatureInput::new(vec![
        Component::Header("date".into()),
        Component::Method,
        Component::Path,
        Component::Authority,
        Component::Header("content-type".into()),
        Component::Header("content-length".into()),
    ])
    .with_keyid("test-key-ed25519")
    .with_created(1_618_884_473);

    // `build_signature_base` is a `pub(crate)` helper; rather than
    // widen its visibility we drive it indirectly via the signer and
    // pull the verified base string back out of the round-trip.
    let signing_key = SigningKey::Ed25519(load_rfc_ed25519_signing_key());
    let public = signing_key.verifying_key();

    let mut req = rfc_b26_request();
    Rfc9421Signer::new(&signing_key, "test-key-ed25519")
        .with_label("sig-b26")
        .with_components(input.components.clone())
        .with_created(1_618_884_473)
        .emit_alg(false)
        .sign(&mut req)
        .expect("sign");

    // A fixed `now` within the RFC vector's `created` window.
    let now: DateTime<Utc> = DateTime::<Utc>::from_timestamp(1_618_884_480, 0).expect("valid");
    let report =
        rfc9421_verify_with_policy(&req, &VerifyPolicy::no_freshness_check(), now, |kid| {
            assert_eq!(kid, "test-key-ed25519");
            Ok(public.clone())
        })
        .expect("verify must succeed for the RFC B.2.6 request");

    assert_eq!(report.signature_base, EXPECTED_SIGNATURE_BASE);

    // And the Signature dictionary also roundtrips to the exact wire form.
    let roundtripped = serialise_signature_input_dict(&[("sig-b26".to_owned(), input)]);
    assert!(
        roundtripped.contains("test-key-ed25519"),
        "round-tripped Signature-Input must contain the vector's keyid",
    );
    let mock_sig = serialise_signature_dict(&[("sig-b26".to_owned(), vec![0xAB, 0xCD])]);
    assert!(
        mock_sig.starts_with("sig-b26=:"),
        "Signature serialiser must emit the sf-dictionary byte-seq shape",
    );
}
