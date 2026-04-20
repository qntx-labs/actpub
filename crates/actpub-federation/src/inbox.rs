//! Inbound activity processing pipeline.
//!
//! [`InboxPipeline`] is the centerpiece of receive-side federation:
//! it takes the raw `(http::request::Parts, body)` of an inbox POST,
//! verifies every layer of authenticity the Fediverse demands, and
//! dispatches the resulting activity to a user-supplied
//! [`ActivityHandler`] implementation.
//!
//! # Verification chain
//!
//! Run in order; any failure aborts the pipeline before the activity
//! reaches the user handler:
//!
//! 1. **Body integrity.** Either the legacy `Digest:` header
//!    (Mastodon-style `SHA-256=<base64>`) or the modern RFC 9530
//!    `Content-Digest:` (sha-256 / sha-512) MUST match the body
//!    bytes.
//! 2. **Signature parsing.** The pipeline supports both the
//!    Cavage draft-12 `Signature:` header (Mastodon, Pleroma, Lemmy,
//!    Misskey) and the IETF RFC 9421 `Signature-Input:` /
//!    `Signature:` pair (Mastodon 4.5+). The first present header
//!    wins; both flavours yield the signing `keyId`.
//! 3. **Actor resolution.** The keyId is dereferenced (with
//!    fragment stripped) via the supplied [`Fetcher`]. The fetched
//!    JSON is the signing actor.
//! 4. **Key resolution.** A [`VerifyingKey`] is reconstructed from
//!    the actor's `publicKey.publicKeyPem` (legacy RSA / Mastodon
//!    main key) or from one of its FEP-521a `assertionMethod`
//!    Multikey blocks (modern Ed25519).
//! 5. **Signature verification.** The reconstructed key is fed to
//!    [`actpub_httpsig::verify`], which re-derives the canonical
//!    signature base from `parts` + `body` and re-runs the
//!    cryptographic check.
//! 6. **Replay protection.** The activity's `id` is checked against
//!    an in-memory LRU cache; previously-seen activities are dropped
//!    silently with [`InboxOutcome::Duplicate`] (the wire response
//!    is still 2xx so the sender does not retry).
//!
//! # FEP-8b32 object integrity
//!
//! Object-level Data Integrity proofs (FEP-8b32) are **not** verified
//! by this pipeline; they live in
//! [`actpub_core::eddsa_jcs::verify`](actpub_core::eddsa_jcs::verify) and
//! the user handler can call it on the activity it receives, using
//! the now-trusted signing actor's `assertionMethod` to look up the
//! relevant Multikey. We deliberately separate the two so that
//! handlers can choose between "trust hop-by-hop signature" and
//! "trust embedded proof" semantics.

use std::sync::Arc;

use actpub_httpsig::{
    CavageHeaderParams, Multikey as HsMultikey, SIGNATURE_HEADER, VerifyingKey,
    parse_signature_input_dict, sha256_digest_header, verify as verify_signature,
    verify_any_content_digest_header,
};
use bytes::Bytes;
use http::Method;
use moka::future::Cache;
use serde_json::Value;
use url::Url;

use crate::config::FederationConfig;
use crate::error::Error;
use crate::fetcher::Fetcher;

/// User-supplied callback invoked once per verified activity.
///
/// The pipeline guarantees that by the time `handle` is called:
///
/// - the body matched its `Digest` / `Content-Digest`;
/// - the HTTP signature was verified against `signing_actor`'s
///   public key;
/// - the activity has not been seen by this pipeline instance before.
pub trait ActivityHandler: Send + Sync {
    /// User-defined error type. Constrained to `'static + Display`
    /// so the pipeline can surface it through `tracing` without
    /// boxing.
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Processes one verified activity.
    ///
    /// Returns `Ok(())` to acknowledge delivery (the pipeline will
    /// reply 202 Accepted to the sender). Returns `Err(e)` to abort
    /// processing — the pipeline surfaces this as
    /// [`Error::HandlerFailed`] and the inbox HTTP layer above will
    /// translate it into a 5xx so the sender retries.
    fn handle(
        &self,
        activity: Value,
        signing_actor: Value,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Outcome of [`InboxPipeline::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxOutcome {
    /// The activity was verified, dispatched to the handler, and
    /// recorded as seen. The HTTP layer above SHOULD reply 202.
    Accepted {
        /// The verified activity's `id` URL. `None` for the rare
        /// activities that do not carry an `id`.
        activity_id: Option<String>,
    },
    /// The activity ID matched a previously-processed entry. The
    /// handler was NOT invoked. The HTTP layer above SHOULD still
    /// reply 2xx so the sender does not retry.
    Duplicate {
        /// The duplicated activity's `id`.
        activity_id: String,
    },
}

/// In-memory inbox pipeline.
///
/// Owns the dedup cache; cheap to clone (cache and config are
/// `Arc`-shared).
pub struct InboxPipeline<F: Fetcher, H: ActivityHandler> {
    inner: Arc<Inner<F, H>>,
}

impl<F, H> Clone for InboxPipeline<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<F, H> std::fmt::Debug for InboxPipeline<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxPipeline")
            .field("dedup_capacity", &self.inner.config.cache_capacity)
            .finish()
    }
}

struct Inner<F: Fetcher, H: ActivityHandler> {
    fetcher: F,
    handler: H,
    config: Arc<FederationConfig>,
    seen: Cache<String, ()>,
}

impl<F, H> InboxPipeline<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    /// Constructs a pipeline that uses `fetcher` to dereference
    /// signing actors, `handler` to receive verified activities, and
    /// shares `config` for caching and policy.
    #[must_use]
    pub fn new(fetcher: F, handler: H, config: Arc<FederationConfig>) -> Self {
        let seen = Cache::builder()
            .max_capacity(config.cache_capacity.max(1))
            .time_to_live(config.cache_ttl)
            .build();
        Self {
            inner: Arc::new(Inner {
                fetcher,
                handler,
                config,
                seen,
            }),
        }
    }

    /// Runs the full verification chain on the inbox POST described
    /// by `parts` + `body` and dispatches the activity to the
    /// configured [`ActivityHandler`] on success.
    ///
    /// # Errors
    ///
    /// Returns one of the [`Error`] variants produced by any stage:
    /// [`Error::DigestMismatch`] / [`Error::HttpSig`] for body
    /// integrity and signature failures; transport / status errors
    /// from the fetcher when resolving the signing actor;
    /// [`Error::ActorWithoutKey`] when the resolved actor exposes no
    /// usable public key; [`Error::HandlerFailed`] when the user
    /// handler returns `Err`.
    pub async fn process(
        &self,
        parts: &http::request::Parts,
        body: Bytes,
    ) -> Result<InboxOutcome, Error> {
        verify_body_integrity(parts, &body)?;
        let key_id = extract_key_id(parts)?;
        let actor_url = strip_fragment(&key_id)?;
        let signing_actor = self.inner.fetcher.fetch_raw(&actor_url).await?;
        let verifying_key = pick_verifying_key(&signing_actor, &key_id)?;

        let req = rebuild_request(parts, body.clone())?;
        verify_signature(&req, |_| Ok(verifying_key.clone())).map_err(Error::from)?;

        let activity: Value = serde_json::from_slice(&body)?;
        let activity_id = activity
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned);

        if let Some(id) = &activity_id
            && self.inner.seen.contains_key(id)
        {
            return Ok(InboxOutcome::Duplicate {
                activity_id: id.clone(),
            });
        }

        self.inner
            .handler
            .handle(activity, signing_actor)
            .await
            .map_err(|e| Error::HandlerFailed(e.to_string()))?;

        if let Some(id) = &activity_id {
            self.inner.seen.insert(id.clone(), ()).await;
        }
        Ok(InboxOutcome::Accepted { activity_id })
    }
}

fn verify_body_integrity(parts: &http::request::Parts, body: &[u8]) -> Result<(), Error> {
    let digest_header = parts
        .headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_digest_header = parts
        .headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    match (content_digest_header, digest_header) {
        (Some(cd), _) => {
            verify_any_content_digest_header(
                &cd,
                body,
                &[
                    actpub_httpsig::DigestAlgorithm::Sha256,
                    actpub_httpsig::DigestAlgorithm::Sha512,
                ],
            )?;
            Ok(())
        }
        (None, Some(d)) => {
            // Compare against our own SHA-256 digest of the body. The
            // legacy header has the shape `SHA-256=<base64>`.
            let expected = sha256_digest_header(body);
            if d.eq_ignore_ascii_case(&expected) {
                Ok(())
            } else {
                Err(Error::HttpSig(actpub_httpsig::Error::DigestMismatch))
            }
        }
        (None, None) => Err(Error::HttpSig(actpub_httpsig::Error::RequiredHeaderAbsent(
            "digest".to_owned(),
        ))),
    }
}

fn extract_key_id(parts: &http::request::Parts) -> Result<String, Error> {
    if let Some(input) = parts
        .headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
    {
        let entries = parse_signature_input_dict(input)?;
        if let Some((_, sig)) = entries.first()
            && let Some(keyid) = &sig.keyid
        {
            return Ok(keyid.clone());
        }
    }
    let raw = parts
        .headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Error::HttpSig(actpub_httpsig::Error::RequiredHeaderAbsent(
                SIGNATURE_HEADER.to_owned(),
            ))
        })?;
    let params = CavageHeaderParams::parse(raw)?;
    Ok(params.key_id)
}

fn strip_fragment(key_id: &str) -> Result<Url, Error> {
    let mut url: Url = key_id.parse()?;
    url.set_fragment(None);
    Ok(url)
}

fn pick_verifying_key(actor: &Value, key_id: &str) -> Result<VerifyingKey, Error> {
    // 1. FEP-521a Multikey (modern Ed25519): match by `id`.
    if let Some(methods) = actor.get("assertionMethod").and_then(Value::as_array) {
        for entry in methods {
            let Some(obj) = entry.as_object() else {
                continue;
            };
            let id = obj.get("id").and_then(Value::as_str).unwrap_or("");
            if id != key_id {
                continue;
            }
            let multibase = obj
                .get("publicKeyMultibase")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::ActorWithoutKey(format!(
                        "assertionMethod entry `{id}` is missing publicKeyMultibase"
                    ))
                })?;
            let decoded = HsMultikey::decode(multibase)?;
            return Ok(VerifyingKey::Ed25519(decoded.key));
        }
    }
    // 2. Legacy Cavage `publicKey.publicKeyPem` (RSA, sometimes Ed25519).
    if let Some(pk) = actor.get("publicKey")
        && let Some(pem) = pk.get("publicKeyPem").and_then(Value::as_str)
    {
        // VerifyingKey::from_pem auto-discriminates Ed25519 vs RSA by
        // SPKI OID — the same backend used to load Mitra and Mastodon
        // actor keys.
        if let Ok(key) = VerifyingKey::from_pem(pem) {
            return Ok(key);
        }
    }
    Err(Error::ActorWithoutKey(format!(
        "actor exposes no key matching keyId `{key_id}`"
    )))
}

fn rebuild_request(
    parts: &http::request::Parts,
    body: Bytes,
) -> Result<http::Request<Bytes>, Error> {
    let mut req = http::Request::new(body);
    *req.method_mut() = parts.method.clone();
    *req.uri_mut() = parts.uri.clone();
    *req.version_mut() = parts.version;
    *req.headers_mut() = parts.headers.clone();
    *req.extensions_mut() = parts.extensions.clone();
    if req.method() != Method::POST {
        // The URI may be in `*` / `path-only` / `authority-form`
        // depending on how the upstream framework handed us the
        // request, so a parse failure is recoverable: fall back to
        // the literal `*` Url that always parses.
        let url = parts.uri.to_string().parse().unwrap_or_else(|_| {
            #[allow(
                clippy::unwrap_used,
                reason = "the literal `https://unknown/` is well-formed by construction"
            )]
            Url::parse("https://unknown/").unwrap()
        });
        return Err(Error::PolicyViolation {
            url,
            reason: format!("inbox accepts POST only, got {}", req.method()),
        });
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use actpub_httpsig::{
        CavageSigner, SigningKey, content_digest_header_with, sha256_digest_header,
    };
    use http::Request;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;
    use crate::config::FederationConfig;
    use crate::policy::UrlPolicy;

    /// Test [`Fetcher`] returning a single hard-coded actor JSON.
    struct FakeFetcher(Value);

    impl Fetcher for FakeFetcher {
        async fn fetch_raw(&self, _url: &Url) -> Result<Value, Error> {
            Ok(self.0.clone())
        }
    }

    /// Counting handler used by tests to assert dispatch / dedup.
    #[derive(Default)]
    struct CountHandler {
        count: AtomicUsize,
    }

    impl ActivityHandler for CountHandler {
        type Error = std::convert::Infallible;
        async fn handle(&self, _activity: Value, _actor: Value) -> Result<(), Self::Error> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_config() -> Arc<FederationConfig> {
        FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://test/sender#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .cache_capacity(64)
            .build()
            .shared()
    }

    /// Build a signed inbox POST: returns (parts, body) plus the
    /// public key the receiver MUST resolve to verify.
    fn signed_inbox_request(activity: &Value) -> (http::request::Parts, Bytes, VerifyingKey) {
        let body = serde_json::to_vec(activity).unwrap();
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://recv.example.com/users/bob/inbox")
            .header("host", "recv.example.com")
            .header(
                "date",
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            )
            .header("content-type", crate::AP_CONTENT_TYPE)
            .header("digest", sha256_digest_header(&body))
            .header(
                "content-digest",
                content_digest_header_with(&body, &[actpub_httpsig::DigestAlgorithm::Sha256]),
            )
            .body(body.clone())
            .unwrap();
        CavageSigner::new(&key, "https://send.example.com/users/alice#key")
            .sign(&mut req)
            .unwrap();
        let (parts, _body_vec) = req.into_parts();
        (parts, Bytes::from(body), public)
    }

    fn actor_json_with_pem(key_id: &str, pem_or_multibase: &str, is_multikey: bool) -> Value {
        if is_multikey {
            json!({
                "id": "https://send.example.com/users/alice",
                "type": "Person",
                "assertionMethod": [{
                    "id": key_id,
                    "type": "Multikey",
                    "controller": "https://send.example.com/users/alice",
                    "publicKeyMultibase": pem_or_multibase,
                }]
            })
        } else {
            json!({
                "id": "https://send.example.com/users/alice",
                "type": "Person",
                "publicKey": {
                    "id": key_id,
                    "owner": "https://send.example.com/users/alice",
                    "publicKeyPem": pem_or_multibase,
                }
            })
        }
    }

    #[tokio::test]
    async fn process_accepts_a_well_signed_activity_via_multikey() {
        let activity = json!({
            "id": "https://send.example.com/activities/01",
            "type": "Create",
            "actor": "https://send.example.com/users/alice"
        });
        let (parts, body, public) = signed_inbox_request(&activity);
        let multibase = match &public {
            VerifyingKey::Ed25519(k) => HsMultikey::encode_ed25519(k),
            other => unreachable!("test signs with Ed25519, got {other:?}"),
        };
        let actor =
            actor_json_with_pem("https://send.example.com/users/alice#key", &multibase, true);
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let outcome = pipeline.process(&parts, body).await.unwrap();
        assert!(matches!(outcome, InboxOutcome::Accepted { .. }));
    }

    #[tokio::test]
    async fn process_dedups_a_repeated_activity() {
        let activity = json!({
            "id": "https://send.example.com/activities/dup",
            "type": "Create",
            "actor": "https://send.example.com/users/alice"
        });
        let (parts, body, public) = signed_inbox_request(&activity);
        let multibase = match &public {
            VerifyingKey::Ed25519(k) => HsMultikey::encode_ed25519(k),
            other => unreachable!("test signs with Ed25519, got {other:?}"),
        };
        let actor =
            actor_json_with_pem("https://send.example.com/users/alice#key", &multibase, true);
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());

        let first = pipeline.process(&parts, body.clone()).await.unwrap();
        assert!(matches!(first, InboxOutcome::Accepted { .. }));
        let second = pipeline.process(&parts, body).await.unwrap();
        assert!(matches!(second, InboxOutcome::Duplicate { .. }));
    }

    #[tokio::test]
    async fn process_rejects_a_tampered_body() {
        let activity = json!({
            "id": "https://send.example.com/activities/02",
            "type": "Create"
        });
        let (parts, _body, public) = signed_inbox_request(&activity);
        let multibase = match &public {
            VerifyingKey::Ed25519(k) => HsMultikey::encode_ed25519(k),
            other => unreachable!("test signs with Ed25519, got {other:?}"),
        };
        let actor =
            actor_json_with_pem("https://send.example.com/users/alice#key", &multibase, true);
        // Tamper with the body after signing.
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let tampered = Bytes::from_static(b"{\"id\":\"x\",\"type\":\"Tampered\"}");
        let err = pipeline
            .process(&parts, tampered)
            .await
            .expect_err("digest mismatch must be detected");
        // Either Digest or Content-Digest fails first; both produce
        // an HttpSig error variant via verify_body_integrity.
        assert!(matches!(err, Error::HttpSig(_)), "unexpected: {err:?}");
    }

    #[tokio::test]
    async fn process_rejects_an_actor_without_a_usable_key() {
        let activity = json!({
            "id": "https://send.example.com/activities/03",
            "type": "Create"
        });
        let (parts, body, _public) = signed_inbox_request(&activity);
        // Actor exposes neither assertionMethod nor publicKey.
        let actor = json!({
            "id": "https://send.example.com/users/alice",
            "type": "Person"
        });
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let err = pipeline
            .process(&parts, body)
            .await
            .expect_err("missing key must surface");
        assert!(
            matches!(err, Error::ActorWithoutKey(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn strip_fragment_drops_anchor_and_preserves_path() {
        let stripped = strip_fragment("https://example.com/users/alice#key").unwrap();
        assert_eq!(stripped.as_str(), "https://example.com/users/alice");
    }

    #[test]
    fn strip_fragment_idempotent_when_no_fragment_present() {
        let stripped = strip_fragment("https://example.com/users/alice").unwrap();
        assert_eq!(stripped.as_str(), "https://example.com/users/alice");
    }
}
