//! axum router that funnels inbox POSTs into an
//! [`InboxPipeline`](actpub_federation::InboxPipeline).
//!
//! Designed as a pre-built drop-in: the user constructs an
//! [`InboxPipeline`] (with their fetcher, handler, and federation
//! config) and hands it to [`inbox_router`]; the result is a fully
//! wired axum [`Router`] mountable at any prefix.
//!
//! # Wire contract
//!
//! - `POST <prefix>/inbox` accepts the activity body up to
//!   [`InboxState::max_body_bytes`] (default 1 MiB) and feeds it,
//!   together with the request headers, into
//!   [`InboxPipeline::process`].
//! - `202 Accepted` is returned on successful verification or on a
//!   detected duplicate (the latter still 2xx so the sender does not
//!   retry, matching what every Mastodon-compatible peer expects).
//! - `400 Bad Request` for body parse / size / signature issues;
//!   `502 Bad Gateway` when actor resolution fails;
//!   `500 Internal Server Error` for unexpected server-side errors
//!   (e.g. a panicking handler).

use std::sync::Arc;

use actpub_federation::{ActivityHandler, Error, Fetcher, InboxPipeline};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Router, body};

/// Default inbox body cap (1 MiB) — large enough for any realistic
/// activity, small enough to bound memory under hostile load.
pub const DEFAULT_MAX_INBOX_BYTES: usize = 1 << 20;

/// Shared state handed to the inbox handler.
///
/// Cheap to clone (the pipeline is itself `Arc`-shared internally).
pub struct InboxState<F: Fetcher, H: ActivityHandler> {
    pipeline: Arc<InboxPipeline<F, H>>,
    max_body_bytes: usize,
}

impl<F, H> InboxState<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    /// Wraps `pipeline` in a state object using the
    /// [`DEFAULT_MAX_INBOX_BYTES`] body cap.
    #[must_use]
    pub fn new(pipeline: InboxPipeline<F, H>) -> Self {
        Self {
            pipeline: Arc::new(pipeline),
            max_body_bytes: DEFAULT_MAX_INBOX_BYTES,
        }
    }

    /// Overrides the maximum inbox body size.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

impl<F, H> Clone for InboxState<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    fn clone(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

impl<F, H> std::fmt::Debug for InboxState<F, H>
where
    F: Fetcher,
    H: ActivityHandler,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pipeline` does not implement Debug across arbitrary F/H,
        // so the formatter elides it and surfaces the configurable
        // body cap which is the only useful operator-facing field.
        f.debug_struct("InboxState")
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// Builds an axum [`Router`] mounted at `/inbox` that POSTs into
/// the supplied state's pipeline.
///
/// Wire example:
///
/// ```ignore
/// use actpub_axum::{inbox_router, InboxState};
///
/// let app = axum::Router::new().nest(
///     "/users/:name",
///     inbox_router(InboxState::new(my_pipeline)),
/// );
/// ```
pub fn inbox_router<F, H>(state: InboxState<F, H>) -> Router
where
    F: Fetcher + 'static,
    H: ActivityHandler + 'static,
{
    Router::new()
        .route("/inbox", post(handle::<F, H>))
        .with_state(state)
}

async fn handle<F, H>(State(state): State<InboxState<F, H>>, request: Request) -> impl IntoResponse
where
    F: Fetcher,
    H: ActivityHandler,
{
    let (parts, body) = request.into_parts();
    let bytes = match body::to_bytes(body, state.max_body_bytes).await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(target: "actpub::axum::inbox", %err, "inbox body read failed");
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };

    match state.pipeline.process(&parts, bytes).await {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(err) => {
            let status = status_for(&err);
            tracing::warn!(
                target: "actpub::axum::inbox",
                %err,
                status = status.as_u16(),
                "inbox processing failed",
            );
            (status, err.to_string()).into_response()
        }
    }
}

/// Maps a federation [`Error`] to the wire-appropriate HTTP status
/// code.
///
/// The mapping follows the Mastodon inbox contract as closely as
/// the federation error type permits:
///
/// - **400 Bad Request** for protocol-level defects in the inbound
///   document that the sender can fix (malformed JSON, bogus
///   content-type, body over size).
/// - **401 Unauthorized** when the HTTP signature verifies against
///   the wrong key or an actor impersonation is detected
///   ([`Error::SignerKeyMismatch`]). The sender has a key problem
///   and must re-sign with correct identity binding.
/// - **403 Forbidden** when [`UrlPolicy`](actpub_federation::UrlPolicy)
///   rejects a URL (a federation-level refusal, not a sender bug).
/// - **422 Unprocessable Entity** when the signing actor is missing
///   the key our verifier needs.
/// - **502 Bad Gateway** for upstream fetch failures that are not
///   the sender's fault.
const fn status_for(err: &Error) -> StatusCode {
    match err {
        Error::HttpSig(_)
        | Error::Json(_)
        | Error::Cryptosuite(_)
        | Error::ResponseTooLarge { .. }
        | Error::UnexpectedContentType { .. } => StatusCode::BAD_REQUEST,
        Error::SignerKeyMismatch(_) => StatusCode::UNAUTHORIZED,
        Error::PolicyViolation { .. } => StatusCode::FORBIDDEN,
        Error::ActorWithoutKey(_) | Error::ActorWithoutInbox(_) => StatusCode::UNPROCESSABLE_ENTITY,
        Error::Status { .. } | Error::Http(_) | Error::Timeout { .. } => StatusCode::BAD_GATEWAY,
        // `Error` is `#[non_exhaustive]`; HandlerFailed / InvalidUrl
        // and any future variants default to 500.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use actpub_federation::{
        ActivityHandler, Error, FederationConfig, Fetcher, InboxPipeline, UrlPolicy,
    };
    use actpub_httpsig::{
        CavageSigner, SigningKey, content_digest_header_with, sha256_digest_header,
    };
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    struct FakeFetcher(Value);

    impl Fetcher for FakeFetcher {
        async fn fetch_raw(&self, _url: &url::Url) -> Result<Value, Error> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct CountHandler(AtomicUsize);

    impl ActivityHandler for CountHandler {
        type Error = std::convert::Infallible;
        async fn handle(&self, _activity: Value, _actor: Value) -> Result<(), Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
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

    /// Build a signed inbox POST against the wiremock-style server URI
    /// `recv_uri` plus `path`.
    fn signed_inbox_post(
        activity: &Value,
        recv_uri: &str,
        path: &str,
    ) -> (Request<Body>, actpub_httpsig::VerifyingKey) {
        let body = serde_json::to_vec(activity).unwrap();
        let key = SigningKey::generate_ed25519();
        let public = key.verifying_key();
        let url = format!("{recv_uri}{path}");
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(
                "host",
                url::Url::parse(&url).unwrap().host_str().unwrap_or(""),
            )
            .header(
                "date",
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            )
            .header("content-type", "application/activity+json")
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
        let (parts, body_vec) = req.into_parts();
        let mut axum_req = Request::from_parts(parts, Body::from(body_vec));
        // Body is already set; ensure Content-Length matches.
        axum_req
            .headers_mut()
            .insert("content-length", body.len().to_string().parse().unwrap());
        (axum_req, public)
    }

    #[tokio::test]
    async fn router_returns_202_for_a_valid_signed_post() {
        let activity = json!({
            "id": "https://send.example.com/activities/01",
            "type": "Create",
            "actor": "https://send.example.com/users/alice"
        });
        let (req, public) = signed_inbox_post(&activity, "https://recv.example.com", "/inbox");
        let multibase = match &public {
            actpub_httpsig::VerifyingKey::Ed25519(k) => actpub_httpsig::Multikey::encode_ed25519(k),
            other => unreachable!("test signs Ed25519, got {other:?}"),
        };
        let actor = json!({
            "id": "https://send.example.com/users/alice",
            "type": "Person",
            "assertionMethod": [{
                "id": "https://send.example.com/users/alice#key",
                "type": "Multikey",
                "controller": "https://send.example.com/users/alice",
                "publicKeyMultibase": multibase,
            }]
        });
        let pipeline =
            InboxPipeline::new(FakeFetcher(actor), CountHandler::default(), test_config());
        let app = inbox_router(InboxState::new(pipeline));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn router_returns_400_for_a_missing_signature() {
        // Signed request, then strip the Signature header.
        let activity = json!({ "id": "https://send.example.com/a/2", "type": "Create" });
        let (mut req, _public) = signed_inbox_post(&activity, "https://recv.example.com", "/inbox");
        req.headers_mut().remove("signature");
        let pipeline = InboxPipeline::new(
            FakeFetcher(json!({"id": "https://send.example.com/users/alice", "type": "Person"})),
            CountHandler::default(),
            test_config(),
        );
        let app = inbox_router(InboxState::new(pipeline));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn router_returns_413_when_body_exceeds_cap() {
        // 16 KiB body, 1 KiB cap — the body parse must fail before the
        // pipeline ever runs.
        let activity_str = format!(
            "{{\"id\":\"x\",\"type\":\"Note\",\"content\":\"{}\"}}",
            "x".repeat(16_000),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://recv.example.com/inbox")
            .body(Body::from(activity_str))
            .unwrap();
        let pipeline = InboxPipeline::new(
            FakeFetcher(json!({"id": "x", "type": "Person"})),
            CountHandler::default(),
            test_config(),
        );
        let app = inbox_router(InboxState::new(pipeline).with_max_body_bytes(1024));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn router_returns_405_for_get_on_inbox() {
        let pipeline = InboxPipeline::new(
            FakeFetcher(json!({"id": "x", "type": "Person"})),
            CountHandler::default(),
            test_config(),
        );
        let app = inbox_router(InboxState::new(pipeline));
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://recv.example.com/inbox")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // axum 0.8 returns 405 with a list of allowed methods.
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
