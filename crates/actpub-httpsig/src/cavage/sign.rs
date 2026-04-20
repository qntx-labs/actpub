//! Cavage draft-12 request signer.

use base64ct::{Base64, Encoding};
use http::Request;
use http::header::HeaderValue;

use crate::cavage::canonical::{CavageHeaderSet, Timestamps, build_signature_base};
use crate::cavage::header::{CavageHeaderParams, SIGNATURE_HEADER};
use crate::error::Error;
use crate::key::{Algorithm, SigningKey};

/// The default header set used by Mastodon and Lemmy for outbound
/// requests: `(request-target)`, `host`, `date`, `digest`.
///
/// Callers typically construct a [`CavageSigner`] without specifying the
/// header set, in which case this default applies.
pub const DEFAULT_HEADER_SET: &[&str] = &["(request-target)", "host", "date", "digest"];

/// A request signer that attaches a Cavage `Signature:` header to an
/// `http::Request`.
///
/// Borrows the signing key so that multiple requests can share the same
/// key without reallocating it.
#[derive(Debug)]
pub struct CavageSigner<'a> {
    key: &'a SigningKey,
    key_id: &'a str,
    headers: CavageHeaderSet,
    created: Option<i64>,
    expires: Option<i64>,
    emit_algorithm: bool,
}

impl<'a> CavageSigner<'a> {
    /// Creates a signer using the [`DEFAULT_HEADER_SET`] and emitting the
    /// `algorithm="…"` parameter for maximum compatibility with older
    /// Fediverse implementations.
    #[must_use]
    pub fn new(key: &'a SigningKey, key_id: &'a str) -> Self {
        Self {
            key,
            key_id,
            headers: CavageHeaderSet::new(DEFAULT_HEADER_SET.iter().copied()),
            created: None,
            expires: None,
            emit_algorithm: true,
        }
    }

    /// Replaces the header set to sign.
    #[must_use]
    pub fn with_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.headers = CavageHeaderSet::new(headers);
        self
    }

    /// Replaces the header set directly.
    #[must_use]
    pub fn with_header_set(mut self, headers: CavageHeaderSet) -> Self {
        self.headers = headers;
        self
    }

    /// Attaches a `(created)` timestamp. Required if the header set
    /// includes `(created)`.
    #[must_use]
    pub const fn with_created(mut self, seconds: i64) -> Self {
        self.created = Some(seconds);
        self
    }

    /// Attaches an `(expires)` timestamp.
    #[must_use]
    pub const fn with_expires(mut self, seconds: i64) -> Self {
        self.expires = Some(seconds);
        self
    }

    /// Controls whether the `algorithm="…"` parameter is emitted.
    ///
    /// Cavage draft-12 §2.1.1 recommends against emitting the algorithm,
    /// but every Fediverse implementation today expects to see it, so
    /// this defaults to `true`.
    #[must_use]
    pub const fn emit_algorithm(mut self, emit: bool) -> Self {
        self.emit_algorithm = emit;
        self
    }

    /// Computes the signature over `req` and inserts the resulting
    /// `Signature:` header in place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequiredHeaderAbsent`] if the request does not
    /// carry every header listed in the signer's header set, and any
    /// error from [`SigningKey::sign`].
    pub fn sign<B>(&self, req: &mut Request<B>) -> Result<(), Error> {
        let base = build_signature_base(
            req,
            &self.headers,
            Timestamps {
                created: self.created,
                expires: self.expires,
            },
        )?;
        let sig_bytes = self.key.sign(base.as_bytes())?;
        let sig_b64 = Base64::encode_string(&sig_bytes);

        let params = CavageHeaderParams {
            key_id: self.key_id.to_owned(),
            algorithm: self.emit_algorithm.then(|| algorithm_name(self.key)),
            headers: self.headers.clone(),
            signature: sig_b64,
            created: self.created,
            expires: self.expires,
        };

        let value =
            HeaderValue::from_str(&params.to_header_value()).map_err(|e| Error::InvalidHeader {
                name: "signature",
                reason: e.to_string(),
            })?;
        req.headers_mut().insert(SIGNATURE_HEADER, value);
        Ok(())
    }
}

fn algorithm_name(key: &SigningKey) -> String {
    match key.algorithm() {
        Algorithm::RsaSha256 => "rsa-sha256".to_owned(),
        Algorithm::Ed25519 => "ed25519".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::cavage::header::CavageHeaderParams;
    use crate::digest::sha256_digest_header;
    use crate::key::RsaBits;

    fn sample_post(body: &[u8]) -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", sha256_digest_header(body))
            .body(body.to_vec())
            .expect("valid request")
    }

    #[test]
    fn ed25519_sign_inserts_signature_header_with_correct_shape() {
        let key = SigningKey::generate_ed25519();
        let mut req = sample_post(b"{}");
        let signer = CavageSigner::new(&key, "https://example.com/actors/alice#main-key");
        signer.sign(&mut req).expect("sign must succeed");

        let raw = req
            .headers()
            .get(SIGNATURE_HEADER)
            .expect("Signature header was inserted")
            .to_str()
            .expect("ASCII");

        let params = CavageHeaderParams::parse(raw).expect("parseable");
        assert_eq!(params.key_id, "https://example.com/actors/alice#main-key");
        assert_eq!(params.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(params.headers.len(), DEFAULT_HEADER_SET.len());
        assert!(!params.signature.is_empty());
    }

    #[test]
    fn rsa_sha256_sign_emits_rsa_sha256_algorithm_name() {
        let key = SigningKey::generate_rsa(RsaBits::Rsa2048).expect("rng");
        let mut req = sample_post(b"{}");
        let signer = CavageSigner::new(&key, "kid");
        signer.sign(&mut req).expect("sign");
        let params = CavageHeaderParams::parse(
            req.headers()
                .get(SIGNATURE_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(params.algorithm.as_deref(), Some("rsa-sha256"));
    }

    #[test]
    fn emit_algorithm_false_suppresses_algorithm_parameter() {
        let key = SigningKey::generate_ed25519();
        let mut req = sample_post(b"{}");
        let signer = CavageSigner::new(&key, "kid").emit_algorithm(false);
        signer.sign(&mut req).expect("sign");
        let params = CavageHeaderParams::parse(
            req.headers()
                .get(SIGNATURE_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(params.algorithm, None);
    }

    #[test]
    fn missing_required_header_returns_required_header_absent() {
        let key = SigningKey::generate_ed25519();
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .body(Vec::<u8>::new())
            .unwrap();
        let signer = CavageSigner::new(&key, "kid");
        let err = signer.sign(&mut req).expect_err("missing host/date/digest");
        assert!(matches!(err, Error::RequiredHeaderAbsent(_)));
    }
}
