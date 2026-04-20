//! `application/activity+json` JSON responder.
//!
//! axum's built-in [`axum::Json`] responder hard-codes the
//! `application/json` media type. Federated peers expect the
//! ActivityPub-specific [`application/activity+json`] media type
//! instead — Mastodon will reject responses with the wrong
//! `Content-Type` outright. [`FederationJson<T>`] is the drop-in
//! replacement: it serialises `T` via `serde_json` and sets the
//! correct header.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Wire-mandated `Content-Type` for `ActivityPub` JSON responses.
///
/// Per [ActivityPub §3.2] every actor / activity / collection
/// document MUST be served with this exact media type.
///
/// [ActivityPub §3.2]: https://www.w3.org/TR/activitypub/#retrieving-objects
pub const ACTIVITY_PUB_CONTENT_TYPE: &str = "application/activity+json";

/// JSON responder that emits the federation-mandated `Content-Type`.
///
/// Behaves identically to [`axum::Json`] but with the right media
/// type. Use it for every actor / object / collection your server
/// publishes to the Fediverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederationJson<T>(pub T);

impl<T: Serialize> IntoResponse for FederationJson<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, ACTIVITY_PUB_CONTENT_TYPE)],
                body,
            )
                .into_response(),
            Err(err) => {
                tracing::error!(target: "actpub::axum", %err, "FederationJson serialisation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "JSON serialisation failed").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn responder_sets_activity_pub_content_type() {
        let resp = FederationJson(json!({ "id": "https://example.com/u/1", "type": "Person" }))
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, ACTIVITY_PUB_CONTENT_TYPE);
    }

    #[tokio::test]
    async fn responder_serialises_payload_as_canonical_json() {
        let payload = json!({ "name": "Alice", "age": 30 });
        let resp = FederationJson(payload.clone()).into_response();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, payload);
    }
}
