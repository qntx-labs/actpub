//! RFC 9421 request signer.

use http::Request;
use http::header::HeaderValue;

use crate::error::Error;
use crate::key::{Algorithm, SigningKey};
use crate::rfc9421::components::{Component, build_signature_base};
use crate::rfc9421::signature::{SIGNATURE_HEADER, serialise_signature_dict};
use crate::rfc9421::signature_input::{
    SIGNATURE_INPUT_HEADER, SignatureInput, serialise_signature_input_dict,
};

/// Default component sequence emitted by [`Rfc9421Signer::new`].
///
/// Mirrors the Cavage default in every respect except the body digest,
/// which follows the modern RFC 9530 `Content-Digest:` form that RFC
/// 9421 implementations expect (Mastodon 4.5+, Mitra, Takahē). Callers
/// running in dual-stack deployments attach the legacy `Digest:` header
/// for their Cavage signer and the modern `Content-Digest:` header for
/// this one; both names can be emitted side by side, since receivers
/// simply ignore headers they do not recognise.
pub const DEFAULT_COMPONENTS: &[&str] =
    &["@method", "@target-uri", "host", "date", "content-digest"];

/// A request signer that produces RFC 9421 `Signature-Input:` and
/// `Signature:` headers.
#[derive(Debug)]
pub struct Rfc9421Signer<'a> {
    key: &'a SigningKey,
    key_id: &'a str,
    label: String,
    components: Vec<Component>,
    created: Option<i64>,
    expires: Option<i64>,
    emit_alg: bool,
    nonce: Option<String>,
    tag: Option<String>,
}

impl<'a> Rfc9421Signer<'a> {
    /// Creates a signer with the [`DEFAULT_COMPONENTS`] layout, label
    /// `"sig1"`, and `alg=` emitted for compatibility.
    ///
    /// # Panics
    ///
    /// Panics if any entry in [`DEFAULT_COMPONENTS`] fails to parse as
    /// a valid identifier. The default list is a compile-time constant,
    /// so this is unreachable at runtime.
    #[must_use]
    pub fn new(key: &'a SigningKey, key_id: &'a str) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "the DEFAULT_COMPONENTS constant contains only valid identifiers"
        )]
        let components = DEFAULT_COMPONENTS
            .iter()
            .map(|ident| Component::parse(ident).expect("valid default component"))
            .collect();
        Self {
            key,
            key_id,
            label: "sig1".into(),
            components,
            created: None,
            expires: None,
            emit_alg: true,
            nonce: None,
            tag: None,
        }
    }

    /// Replaces the full component list.
    #[must_use]
    pub fn with_components(mut self, components: Vec<Component>) -> Self {
        self.components = components;
        self
    }

    /// Replaces the `Signature-Input:` label (default `"sig1"`).
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Sets the `created=` parameter.
    #[must_use]
    pub const fn with_created(mut self, seconds: i64) -> Self {
        self.created = Some(seconds);
        self
    }

    /// Sets the `expires=` parameter.
    #[must_use]
    pub const fn with_expires(mut self, seconds: i64) -> Self {
        self.expires = Some(seconds);
        self
    }

    /// Sets the `nonce=` parameter.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the `tag=` parameter.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Controls whether the `alg=` parameter is emitted. Defaults to
    /// `true`; set to `false` to match RFC 9421 §3.3.7's stated
    /// preference for relying on out-of-band key agreement instead.
    #[must_use]
    pub const fn emit_alg(mut self, emit: bool) -> Self {
        self.emit_alg = emit;
        self
    }

    /// Signs `req` and inserts `Signature-Input:` and `Signature:` headers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequiredHeaderAbsent`] if the request is missing
    /// any referenced header, [`Error::Crypto`] if the signing primitive
    /// fails, and [`Error::InvalidHeader`] if the resulting header value
    /// cannot be converted to an [`http::HeaderValue`] (extremely rare,
    /// only if the key id contains non-ASCII bytes).
    pub fn sign<B>(&self, req: &mut Request<B>) -> Result<(), Error> {
        let input = SignatureInput {
            components: self.components.clone(),
            keyid: Some(self.key_id.to_owned()),
            algorithm: self.emit_alg.then(|| algorithm_name(self.key).to_owned()),
            created: self.created,
            expires: self.expires,
            nonce: self.nonce.clone(),
            tag: self.tag.clone(),
        };
        let inner_list = input.serialise_inner_list();
        let base = build_signature_base(req, &self.components, &inner_list)?;
        let sig_bytes = self.key.sign(base.as_bytes())?;

        let input_value = serialise_signature_input_dict(&[(self.label.clone(), input)]);
        let sig_value = serialise_signature_dict(&[(self.label.clone(), sig_bytes)]);

        insert_header(req, SIGNATURE_INPUT_HEADER, &input_value)?;
        insert_header(req, SIGNATURE_HEADER, &sig_value)?;
        Ok(())
    }
}

const fn algorithm_name(key: &SigningKey) -> &'static str {
    match key.algorithm() {
        Algorithm::RsaSha256 => "rsa-v1_5-sha256",
        Algorithm::Ed25519 => "ed25519",
    }
}

fn insert_header<B>(req: &mut Request<B>, name: &'static str, value: &str) -> Result<(), Error> {
    let value = HeaderValue::from_str(value).map_err(|e| Error::InvalidHeader {
        name,
        reason: e.to_string(),
    })?;
    req.headers_mut().insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::content_digest::content_digest_header;
    use crate::rfc9421::signature::parse_signature_dict;
    use crate::rfc9421::signature_input::parse_signature_input_dict;

    fn sample_request() -> Request<Vec<u8>> {
        let body = b"{}";
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("content-digest", content_digest_header(body))
            .body(body.to_vec())
            .expect("valid")
    }

    #[test]
    fn sign_inserts_both_headers_with_matching_label() {
        let key = SigningKey::generate_ed25519();
        let mut req = sample_request();
        Rfc9421Signer::new(&key, "https://example.com/actor#sig")
            .with_label("sig1")
            .with_created(1_700_000_000)
            .sign(&mut req)
            .expect("sign");

        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .expect("Signature-Input present")
            .to_str()
            .expect("ASCII");
        let sig_raw = req
            .headers()
            .get(SIGNATURE_HEADER)
            .expect("Signature present")
            .to_str()
            .expect("ASCII");

        let input = parse_signature_input_dict(input_raw).expect("parse input");
        let sig = parse_signature_dict(sig_raw).expect("parse sig");
        assert_eq!(input[0].0, "sig1");
        assert_eq!(sig[0].0, "sig1");
        assert_eq!(
            input[0].1.keyid.as_deref(),
            Some("https://example.com/actor#sig")
        );
        assert_eq!(input[0].1.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(input[0].1.created, Some(1_700_000_000));
    }

    #[test]
    fn rsa_signer_uses_rfc9421_algorithm_name() {
        let key = SigningKey::generate_rsa(crate::key::RsaBits::Rsa2048).expect("rng");
        let mut req = sample_request();
        Rfc9421Signer::new(&key, "kid")
            .sign(&mut req)
            .expect("sign");
        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        let input = parse_signature_input_dict(input_raw).unwrap();
        assert_eq!(input[0].1.algorithm.as_deref(), Some("rsa-v1_5-sha256"));
    }

    #[test]
    fn emit_alg_false_suppresses_alg_parameter() {
        let key = SigningKey::generate_ed25519();
        let mut req = sample_request();
        Rfc9421Signer::new(&key, "kid")
            .emit_alg(false)
            .sign(&mut req)
            .expect("sign");
        let input_raw = req
            .headers()
            .get(SIGNATURE_INPUT_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        let input = parse_signature_input_dict(input_raw).unwrap();
        assert_eq!(input[0].1.algorithm, None);
    }
}
