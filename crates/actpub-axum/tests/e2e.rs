//! End-to-end integration tests composing every actpub-axum router.
//!
//! These tests build a full Fediverse-compatible service by merging
//! [`inbox_router`], [`webfinger_router`] and [`nodeinfo_router`] into
//! one axum [`Router`], then drive the resulting `tower::Service`
//! through `oneshot` requests covering each surface in turn. The
//! point is to catch regressions where the routers conflict — shared
//! state collisions, path collisions, content-type mix-ups — that
//! the per-module unit tests cannot see.

#![allow(
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "integration-test idioms: every `#[test]` is the file's contents; `expect`/`unwrap`/`panic!` are the clearest way to assert expectations"
)]

use std::sync::Arc;

use actpub_axum::{
    InboxState, NodeInfoState, WebFingerResolver, inbox_router, nodeinfo_router, webfinger_router,
};
use actpub_federation::{
    ActivityHandler, Error as FederationError, FederationConfig, Fetcher, InboxPipeline, UrlPolicy,
};
use actpub_httpsig::{
    CavageSigner, Multikey as HsMultikey, SigningKey, VerifyingKey, content_digest_header_with,
    sha256_digest_header,
};
use actpub_nodeinfo::{NodeInfo, Protocol, Software, Version};
use actpub_webfinger::{Jrd, JrdLink, rels};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;

/// Test fetcher returning a single canned actor JSON for any URL.
struct StaticFetcher(Value);

impl Fetcher for StaticFetcher {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait definition requires async but mock implementation has no await"
    )]
    async fn fetch_raw(
        &self,
        _url: &Url,
        _ctx: &actpub_federation::FetchContext,
    ) -> Result<Value, FederationError> {
        Ok(self.0.clone())
    }
}

/// Test handler that records every (activity, actor) pair.
#[derive(Default)]
struct CaptureHandler {
    captured: tokio::sync::Mutex<Vec<(Value, Value)>>,
}

impl ActivityHandler for CaptureHandler {
    type Error = std::convert::Infallible;
    async fn handle(
        &self,
        activity: Value,
        actor: Value,
        _ctx: actpub_federation::FetchContext,
    ) -> Result<(), Self::Error> {
        self.captured.lock().await.push((activity, actor));
        Ok(())
    }
}

/// `WebFinger` resolver returning a single hard-coded JRD for the
/// expected `acct:alice@example.com` resource.
struct AliceResolver(Jrd);

impl WebFingerResolver for AliceResolver {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait definition requires async but mock implementation has no await"
    )]
    async fn resolve(&self, resource: String) -> Result<Option<Jrd>, String> {
        if resource == "acct:alice@example.com" {
            Ok(Some(self.0.clone()))
        } else {
            Ok(None)
        }
    }
}

fn alice_jrd() -> Jrd {
    Jrd::builder("acct:alice@example.com")
        .alias("https://example.com/@alice")
        .link(
            JrdLink::builder(rels::ACTIVITYPUB_ACTOR)
                .href("https://example.com/users/alice".parse().unwrap())
                .media_type("application/activity+json")
                .build(),
        )
        .build()
}

fn nodeinfo_state() -> NodeInfoState {
    NodeInfoState::dual(
        "https://example.com".parse().unwrap(),
        NodeInfo::builder(Version::V2_0, Software::new("actpub-test", "0.1.0"))
            .protocol(Protocol::ActivityPub)
            .build(),
        NodeInfo::builder(Version::V2_1, Software::new("actpub-test", "0.1.0"))
            .protocol(Protocol::ActivityPub)
            .build(),
    )
}

fn federation_config() -> Arc<FederationConfig> {
    FederationConfig::builder()
        .signing_key(SigningKey::generate_ed25519())
        .key_id("https://example.com/users/server#key".parse().unwrap())
        .url_policy(UrlPolicy::permissive_for_tests())
        .cache_capacity(64)
        .build()
        .shared()
}

/// Builds the full federated service with every router merged in.
fn build_app(actor_for_signature: Value, handler: CaptureHandler) -> (Router, Arc<CaptureHandler>) {
    let pipeline = InboxPipeline::new(
        StaticFetcher(actor_for_signature),
        handler,
        federation_config(),
    );
    let captured: Arc<CaptureHandler> = Arc::new(CaptureHandler::default());
    let app = Router::new()
        .merge(inbox_router(InboxState::new(pipeline)))
        .merge(webfinger_router(AliceResolver(alice_jrd())))
        .merge(nodeinfo_router(nodeinfo_state()));
    (app, captured)
}

/// Builds a Cavage-signed inbox POST request (Mastodon-style headers
/// + signature) plus the matching public key the receiver MUST resolve.
fn signed_inbox_post(activity: &Value) -> (Request<Body>, VerifyingKey) {
    let body = serde_json::to_vec(activity).unwrap();
    let key = SigningKey::generate_ed25519();
    let public = key.verifying_key();
    let url = "https://recv.example.com/inbox";
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("host", "recv.example.com")
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
    axum_req
        .headers_mut()
        .insert("content-length", body.len().to_string().parse().unwrap());
    (axum_req, public)
}

fn actor_with_multikey(public: &VerifyingKey) -> Value {
    let multibase = match public {
        VerifyingKey::Ed25519(k) => HsMultikey::encode_ed25519(k),
        other => panic!("e2e signs Ed25519, got {other:?}"),
    };
    json!({
        "id": "https://send.example.com/users/alice",
        "type": "Person",
        "assertionMethod": [{
            "id": "https://send.example.com/users/alice#key",
            "type": "Multikey",
            "controller": "https://send.example.com/users/alice",
            "publicKeyMultibase": multibase,
        }]
    })
}

/// All three routers can co-exist in a single axum [`Router`] without
/// path collisions or shared-state interference.
#[tokio::test]
async fn merged_app_serves_inbox_webfinger_and_nodeinfo_in_one_service() {
    let activity = json!({
        "id": "https://send.example.com/activities/01",
        "type": "Create",
        "actor": "https://send.example.com/users/alice"
    });
    let (req, public) = signed_inbox_post(&activity);
    let (app, _captured) = build_app(actor_with_multikey(&public), CaptureHandler::default());

    // 1. Inbox — signed POST returns 202.
    let inbox_resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(inbox_resp.status(), StatusCode::ACCEPTED);

    // 2. WebFinger — known resource returns 200 with JRD.
    let wf_req = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/webfinger?resource=acct:alice@example.com")
        .body(Body::empty())
        .unwrap();
    let wf_resp = app.clone().oneshot(wf_req).await.unwrap();
    assert_eq!(wf_resp.status(), StatusCode::OK);
    let ct = wf_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "application/jrd+json");

    // 3. NodeInfo discovery — returns the discovery document with both
    //    schema versions.
    let nf_req = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/nodeinfo")
        .body(Body::empty())
        .unwrap();
    let nf_resp = app.clone().oneshot(nf_req).await.unwrap();
    assert_eq!(nf_resp.status(), StatusCode::OK);
    let bytes = nf_resp.into_body().collect().await.unwrap().to_bytes();
    let disco_doc: Value = serde_json::from_slice(&bytes).unwrap();
    let links = disco_doc["links"]
        .as_array()
        .expect("discovery links array");
    assert_eq!(links.len(), 2, "discovery exposes both 2.0 and 2.1");

    // 4. NodeInfo schema 2.1 — returns the per-version document with
    //    the schema profile parameter on the Content-Type.
    let nf21_req = Request::builder()
        .method(Method::GET)
        .uri("/nodeinfo/2.1")
        .body(Body::empty())
        .unwrap();
    let nf21_resp = app.oneshot(nf21_req).await.unwrap();
    assert_eq!(nf21_resp.status(), StatusCode::OK);
    let nf21_ct = nf21_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        nf21_ct.contains(r#"profile="http://nodeinfo.diaspora.software/ns/schema/2.1""#),
        "schema 2.1 carries its versioned profile parameter: {nf21_ct}",
    );
}

/// Inbox handler invocation flows the activity body through to the
/// user-supplied handler (this is the integration-level proof that
/// the verification chain calls `handle` with the correct payload).
#[tokio::test]
async fn inbox_post_flows_into_user_handler_with_verified_payload() {
    let activity = json!({
        "id": "https://send.example.com/activities/02",
        "type": "Create",
        "actor": "https://send.example.com/users/alice"
    });
    let (req, public) = signed_inbox_post(&activity);

    // Build a pipeline whose handler is shared with the test through
    // an Arc so we can post-hoc inspect the captured payload.
    let captured: Arc<CaptureHandler> = Arc::new(CaptureHandler::default());
    let captured_in_handler = Arc::clone(&captured);
    let pipeline = InboxPipeline::new(
        StaticFetcher(actor_with_multikey(&public)),
        SharedHandler(captured_in_handler),
        federation_config(),
    );
    let app = inbox_router(InboxState::new(pipeline));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Drop the lock guard before the assertions so it does not stay
    // held longer than necessary in this contention-free test path.
    let snapshot: Vec<(Value, Value)> = {
        let captured = captured.captured.lock().await;
        captured.clone()
    };
    assert_eq!(snapshot.len(), 1, "handler invoked exactly once");
    let (got_activity, got_actor) = &snapshot[0];
    assert_eq!(
        got_activity["id"],
        json!("https://send.example.com/activities/02")
    );
    assert_eq!(got_activity["type"], json!("Create"));
    assert_eq!(
        got_actor["id"],
        json!("https://send.example.com/users/alice")
    );
}

/// Test handler that delegates to a shared [`CaptureHandler`] so the
/// outer test body can inspect the captured payload after handling.
struct SharedHandler(Arc<CaptureHandler>);

impl ActivityHandler for SharedHandler {
    type Error = std::convert::Infallible;
    async fn handle(
        &self,
        activity: Value,
        actor: Value,
        _ctx: actpub_federation::FetchContext,
    ) -> Result<(), Self::Error> {
        self.0.captured.lock().await.push((activity, actor));
        Ok(())
    }
}

/// `WebFinger` router rejects unknown subjects with 404, the way every
/// real Fediverse client expects.
#[tokio::test]
async fn webfinger_returns_404_for_unknown_subject_when_merged_with_other_routers() {
    let (app, _) = build_app(json!({}), CaptureHandler::default());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/webfinger?resource=acct:ghost@example.com")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
