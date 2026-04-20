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
//! 1. **Method gate.** The pipeline accepts `POST` only. Other
//!    methods produce [`Error::PolicyViolation`] before any
//!    cryptography runs.
//! 2. **Body integrity.** Either the legacy `Digest:` header
//!    (Mastodon-style `SHA-256=<base64>`) or the modern RFC 9530
//!    `Content-Digest:` (sha-256 / sha-512) MUST match the body
//!    bytes.
//! 3. **Signature parsing.** The pipeline supports both the
//!    Cavage draft-12 `Signature:` header (Mastodon, Pleroma, Lemmy,
//!    Misskey) and the IETF RFC 9421 `Signature-Input:` /
//!    `Signature:` pair (Mastodon 4.5+). The first present header
//!    wins; both flavours yield the signing `keyId`.
//! 4. **Actor resolution.** The keyId is dereferenced (with
//!    fragment stripped) via the supplied [`Fetcher`]. The fetched
//!    JSON is the signing actor.
//! 5. **Identity binding.** The fetched actor's `id` host MUST
//!    match the `keyId` host; otherwise the request is rejected as
//!    a cross-domain impersonation attempt. When the actor uses a
//!    legacy `publicKey`, its `publicKey.id` MUST equal the signing
//!    `keyId`.
//! 6. **Key resolution.** A [`VerifyingKey`] is reconstructed from
//!    the actor's `publicKey.publicKeyPem` (legacy RSA / Mastodon
//!    main key) or from one of its FEP-521a `assertionMethod`
//!    Multikey blocks (modern Ed25519).
//! 7. **Signature verification.** The reconstructed key is fed to
//!    [`actpub_httpsig::verify`], which re-derives the canonical
//!    signature base from `parts` + `body` and re-runs the
//!    cryptographic check.
//! 8. **Replay protection.** The activity's `id` is checked against
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
use crate::fetch_ctx::FetchContext;
use crate::fetcher::Fetcher;

/// User-supplied callback invoked once per verified activity.
///
/// The pipeline guarantees that by the time `handle` is called:
///
/// - the body matched its `Digest` / `Content-Digest`;
/// - the HTTP signature was verified against `signing_actor`'s
///   public key;
/// - the activity has not been seen by this pipeline instance before.
///
/// The [`FetchContext`] passed to `handle` represents the **same**
/// per-request budget the pipeline used to resolve the signing
/// actor, so recursive dereferencing the handler performs (walking
/// `object.inReplyTo`, dereferencing mentioned actors, …) is
/// tracked against a single
/// [`FederationConfig::http_fetch_limit`](crate::FederationConfig::http_fetch_limit)
/// ceiling. Handlers that do not perform further fetches can
/// simply ignore the parameter.
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
        ctx: FetchContext,
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
        enforce_post(parts)?;
        verify_body_integrity(parts, &body)?;
        let key_id = extract_key_id(parts)?;
        let actor_url = strip_fragment(&key_id)?;
        // Budget every HTTP fetch the pipeline (and the user
        // handler) will perform for this one inbox POST against a
        // single counter. Actor resolution counts as one; the
        // handler inherits the remainder of the budget.
        let ctx = FetchContext::new(self.inner.config.http_fetch_limit);
        let signing_actor = self.inner.fetcher.fetch_raw(&actor_url, &ctx).await?;
        enforce_actor_domain_matches_key_id(&signing_actor, &key_id)?;
        let verifying_key = pick_verifying_key(&signing_actor, &key_id)?;

        let req = rebuild_request(parts, body.clone());
        verify_signature(&req, |_| Ok(verifying_key.clone())).map_err(Error::from)?;

        let activity: Value = serde_json::from_slice(&body)?;
        let activity_id = activity
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Dedup key is normalised so that `https://Example.COM/a/1`
        // and `https://example.com/a/1/` are recognised as the same
        // activity; otherwise the cheapest replay attack is a
        // capitalisation flip.
        let dedup_key = activity_id.as_deref().map(normalise_activity_id);

        if let Some(key) = &dedup_key
            && self.inner.seen.contains_key(key)
        {
            return Ok(InboxOutcome::Duplicate {
                activity_id: activity_id.clone().unwrap_or_else(|| key.clone()),
            });
        }

        self.inner
            .handler
            .handle(activity, signing_actor, ctx)
            .await
            .map_err(|e| Error::HandlerFailed(e.to_string()))?;

        if let Some(key) = dedup_key {
            self.inner.seen.insert(key, ()).await;
        }
        Ok(InboxOutcome::Accepted { activity_id })
    }
}

/// Canonicalises an activity `id` so that cosmetic URL variations
/// (case-folded host, trailing slash, etc.) do not sneak past the
/// dedup cache. For non-URL identifiers (URNs, tag URIs, bare
/// strings) the original value is returned unchanged.
fn normalise_activity_id(id: &str) -> String {
    let Ok(mut url) = Url::parse(id) else {
        return id.to_owned();
    };
    url.set_fragment(None);
    // The `url` crate already lower-cases the host; explicitly
    // trim a lone trailing slash from the path so that
    // `https://h/a/` and `https://h/a` hash the same.
    if url.path().len() > 1 && url.path().ends_with('/') && url.query().is_none() {
        let trimmed = url.path().trim_end_matches('/').to_owned();
        url.set_path(&trimmed);
    }
    url.into()
}

/// Rejects any request whose method is not POST before any
/// cryptographic work is performed.
fn enforce_post(parts: &http::request::Parts) -> Result<(), Error> {
    if parts.method == Method::POST {
        return Ok(());
    }
    // The URI may be in authority-only / asterisk form; fall back
    // to a placeholder URL if it cannot be parsed as an absolute
    // `Url`, so the error is still usable by downstream logging.
    let url = parts.uri.to_string().parse().unwrap_or_else(|_| {
        #[allow(
            clippy::unwrap_used,
            reason = "the literal `https://unknown/` is well-formed by construction"
        )]
        Url::parse("https://unknown/").unwrap()
    });
    Err(Error::PolicyViolation {
        url,
        reason: format!("inbox accepts POST only, got {}", parts.method),
    })
}

/// Enforces that the fetched `signing_actor.id` and the signing
/// `key_id` live on the same host.
///
/// This is the defence against cross-domain actor impersonation: an
/// attacker that controls `attacker.example` cannot produce a
/// signed request whose fetched actor claims
/// `"id": "https://victim.example/users/alice"` and have that
/// identity survive this gate.
fn enforce_actor_domain_matches_key_id(actor: &Value, key_id: &str) -> Result<(), Error> {
    let key_id_url: Url = key_id
        .parse()
        .map_err(|_| Error::SignerKeyMismatch(format!("keyId `{key_id}` is not a valid URL")))?;
    let actor_id = actor
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::SignerKeyMismatch("fetched actor has no `id`".to_owned()))?;
    let actor_id_url: Url = actor_id.parse().map_err(|_| {
        Error::SignerKeyMismatch(format!("actor.id `{actor_id}` is not a valid URL"))
    })?;
    match (key_id_url.host_str(), actor_id_url.host_str()) {
        (Some(k), Some(a)) if k.eq_ignore_ascii_case(a) => Ok(()),
        (k, a) => Err(Error::SignerKeyMismatch(format!(
            "keyId host `{k:?}` does not match actor.id host `{a:?}`",
        ))),
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

/// Extracts the signing `keyId` from whichever HTTP-Signature
/// flavour the request carries.
///
/// The selection logic mirrors [`actpub_httpsig::verify`] exactly,
/// so the actor fetched from this `keyId` is guaranteed to be the
/// one that `verify` will check the signature against:
///
/// - A `Signature-Input:` header switches the request into the
///   RFC 9421 stack; the `keyid=` parameter of the first inner
///   list is the signer. Anything malformed here is surfaced
///   rather than silently falling through to Cavage (which would
///   let a malformed RFC 9421 header "downgrade" to a Cavage
///   signature potentially using a different `keyId`).
/// - Without `Signature-Input:`, the Cavage `Signature:` header's
///   `keyId=` parameter is used.
fn extract_key_id(parts: &http::request::Parts) -> Result<String, Error> {
    if let Some(input) = parts
        .headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
    {
        let entries = parse_signature_input_dict(input)?;
        let (_, sig) = entries.first().ok_or_else(|| {
            Error::HttpSig(actpub_httpsig::Error::MalformedSignatureHeader(
                "Signature-Input header has no entries".to_owned(),
            ))
        })?;
        return sig.keyid.clone().ok_or_else(|| {
            Error::HttpSig(actpub_httpsig::Error::MalformedSignatureHeader(
                "Signature-Input entry has no `keyid` parameter".to_owned(),
            ))
        });
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
    //
    // The `publicKey.id` MUST equal the `keyId` used to sign the
    // request; otherwise an actor with two rotated keys could see
    // verification fall back to the wrong one.
    if let Some(pk) = actor.get("publicKey") {
        let pk_id = pk.get("id").and_then(Value::as_str).unwrap_or("");
        if pk_id != key_id {
            return Err(Error::SignerKeyMismatch(format!(
                "actor.publicKey.id `{pk_id}` does not equal signing keyId `{key_id}`",
            )));
        }
        if let Some(pem) = pk.get("publicKeyPem").and_then(Value::as_str) {
            // VerifyingKey::from_pem auto-discriminates Ed25519 vs
            // RSA by SPKI OID -- the same backend used to load
            // Mitra and Mastodon actor keys.
            if let Ok(key) = VerifyingKey::from_pem(pem) {
                return Ok(key);
            }
        }
    }
    Err(Error::ActorWithoutKey(format!(
        "actor exposes no key matching keyId `{key_id}`"
    )))
}

/// Re-assembles a full [`http::Request`] from the already-split
/// `parts` + `body`. The method-guard runs in [`enforce_post`] before
/// we reach this helper, so failure here is structurally impossible.
fn rebuild_request(parts: &http::request::Parts, body: Bytes) -> http::Request<Bytes> {
    let mut req = http::Request::new(body);
    *req.method_mut() = parts.method.clone();
    *req.uri_mut() = parts.uri.clone();
    *req.version_mut() = parts.version;
    *req.headers_mut() = parts.headers.clone();
    *req.extensions_mut() = parts.extensions.clone();
    req
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
        async fn fetch_raw(&self, _url: &Url, _ctx: &FetchContext) -> Result<Value, Error> {
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
        async fn handle(
            &self,
            _activity: Value,
            _actor: Value,
            _ctx: FetchContext,
        ) -> Result<(), Self::Error> {
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

    #[tokio::test]
    async fn process_rejects_get_requests_before_verification() {
        // The verification chain MUST short-circuit on non-POST methods
        // so that no cryptographic work (and no fetcher call) runs.
        let (mut parts, body, _) = signed_inbox_request(&json!({"id": "x", "type": "Create"}));
        parts.method = Method::GET;
        let actor = json!({ "id": "https://send.example.com/users/alice", "type": "Person" });
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let err = pipeline
            .process(&parts, body)
            .await
            .expect_err("GET must be rejected by the method gate");
        assert!(
            matches!(err, Error::PolicyViolation { ref reason, .. } if reason.contains("POST")),
            "unexpected: {err:?}",
        );
    }

    #[tokio::test]
    async fn process_rejects_cross_domain_actor_impersonation() {
        // Attacker signs with keyId hosted on attacker.example, but
        // the fetched actor JSON claims `id` on victim.example.
        // Without the domain binding, the handler would see a
        // victim-authored activity signed by a stranger.
        let activity = json!({ "id": "https://attacker.example/acts/1", "type": "Create" });
        let body = serde_json::to_vec(&activity).unwrap();
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let multibase = match &public {
            VerifyingKey::Ed25519(k) => HsMultikey::encode_ed25519(k),
            other => unreachable!("test signs with Ed25519, got {other:?}"),
        };
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://recv.example.com/users/bob/inbox")
            .header("host", "recv.example.com")
            .header(
                "date",
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            )
            .header("content-type", crate::AP_CONTENT_TYPE)
            .header(
                "content-digest",
                content_digest_header_with(&body, &[actpub_httpsig::DigestAlgorithm::Sha256]),
            )
            .header("digest", sha256_digest_header(&body))
            .body(body.clone())
            .unwrap();
        // keyId on attacker.example...
        CavageSigner::new(&key, "https://attacker.example/users/alice#key")
            .sign(&mut req)
            .unwrap();
        let (parts, _) = req.into_parts();

        // ...but the fetched actor pretends to live on victim.example.
        let fraudulent_actor = json!({
            "id": "https://victim.example/users/alice",
            "type": "Person",
            "assertionMethod": [{
                "id": "https://attacker.example/users/alice#key",
                "type": "Multikey",
                "publicKeyMultibase": multibase,
            }],
        });
        let pipeline = InboxPipeline::new(
            FakeFetcher(fraudulent_actor),
            CountHandler::default(),
            test_config(),
        );
        let err = pipeline
            .process(&parts, Bytes::from(body))
            .await
            .expect_err("cross-domain impersonation must be rejected");
        assert!(
            matches!(err, Error::SignerKeyMismatch(_)),
            "unexpected: {err:?}",
        );
    }

    #[tokio::test]
    async fn process_rejects_legacy_public_key_with_mismatched_id() {
        // Legacy publicKey path: actor has a public key whose `id`
        // does not match the signing `keyId`. This is the rotation
        // ambiguity mitigated by F-FED-H05.
        let activity = json!({ "id": "https://send.example.com/acts/1", "type": "Create" });
        let (parts, body, _) = signed_inbox_request(&activity);
        let other_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAXAm6N+kyXkCSdMVqkCD8GLYRXlkxAaJIpA8Yk0g3x4c=\n-----END PUBLIC KEY-----";
        let actor = json!({
            "id": "https://send.example.com/users/alice",
            "type": "Person",
            "publicKey": {
                "id": "https://send.example.com/users/alice#rotation-key",
                "owner": "https://send.example.com/users/alice",
                "publicKeyPem": other_pem,
            }
        });
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let err = pipeline
            .process(&parts, body)
            .await
            .expect_err("mismatched publicKey.id must be rejected");
        assert!(
            matches!(err, Error::SignerKeyMismatch(_)),
            "unexpected: {err:?}",
        );
    }

    #[test]
    fn enforce_actor_domain_matches_key_id_ok_for_same_host() {
        let actor = json!({ "id": "https://example.com/users/alice" });
        enforce_actor_domain_matches_key_id(&actor, "https://example.com/users/alice#k")
            .expect("same host must pass");
    }

    #[test]
    fn enforce_actor_domain_matches_key_id_is_ascii_case_insensitive() {
        // Hosts are compared case-insensitively to match DNS semantics.
        let actor = json!({ "id": "https://Example.COM/users/alice" });
        enforce_actor_domain_matches_key_id(&actor, "https://example.com/users/alice#k")
            .expect("case-insensitive host match");
    }

    #[test]
    fn enforce_actor_domain_matches_key_id_rejects_missing_actor_id() {
        let actor = json!({ "type": "Person" });
        let err = enforce_actor_domain_matches_key_id(&actor, "https://example.com/u/a#k")
            .expect_err("missing actor.id must fail");
        assert!(matches!(err, Error::SignerKeyMismatch(_)));
    }

    #[test]
    fn normalise_activity_id_lowercases_host() {
        assert_eq!(
            normalise_activity_id("https://Example.COM/activities/1"),
            "https://example.com/activities/1",
        );
    }

    #[test]
    fn normalise_activity_id_strips_trailing_slash() {
        assert_eq!(
            normalise_activity_id("https://example.com/activities/1/"),
            "https://example.com/activities/1",
        );
    }

    #[test]
    fn normalise_activity_id_drops_fragment() {
        assert_eq!(
            normalise_activity_id("https://example.com/activities/1#part"),
            "https://example.com/activities/1",
        );
    }

    #[test]
    fn normalise_activity_id_preserves_non_url_identifiers() {
        // URNs and plain strings are passed through untouched.
        assert_eq!(
            normalise_activity_id("urn:uuid:deadbeef"),
            "urn:uuid:deadbeef",
        );
        assert_eq!(normalise_activity_id("not-a-url"), "not-a-url");
    }
}
