//! axum router serving the [RFC 7033] `/.well-known/webfinger`
//! endpoint.
//!
//! The router accepts the standard `?resource=<uri>` query and
//! delegates resolution to a user-supplied [`WebFingerResolver`]
//! callback. The callback returns a [`Jrd`] describing the resource,
//! which the router serialises with the RFC 7033 mandated
//! `application/jrd+json` media type.
//!
//! Every response carries `Access-Control-Allow-Origin: *` per
//! [RFC 7033 §8.4][cors] so that browser-based Fediverse clients
//! can query the endpoint cross-origin without requiring a
//! pre-flight (the `GET` request is a CORS "simple" request).
//!
//! [RFC 7033]: https://datatracker.ietf.org/doc/html/rfc7033
//! [cors]: https://datatracker.ietf.org/doc/html/rfc7033#section-8.4

use std::sync::Arc;

use actpub_webfinger::Jrd;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;

/// `Content-Type` mandated by RFC 7033 §10.2 for JRD responses.
pub const JRD_CONTENT_TYPE: &str = "application/jrd+json";

/// Wildcard CORS header value mandated by RFC 7033 §8.4.
const CORS_ALLOW_ANY_ORIGIN: &str = "*";

/// Asynchronous callback that resolves a `?resource=<uri>` query into
/// a [`Jrd`] describing it.
///
/// `Send + Sync + 'static` so an `Arc<dyn WebFingerResolver>` can be
/// shared across axum worker tasks.
pub trait WebFingerResolver: Send + Sync + 'static {
    /// Resolves `resource` to a [`Jrd`].
    ///
    /// Return `Ok(None)` when the resource is recognised as not
    /// belonging to this server (the router will reply 404).
    /// Return `Err(_)` for unexpected internal failures (the router
    /// will reply 500).
    fn resolve(&self, resource: String)
    -> impl Future<Output = Result<Option<Jrd>, String>> + Send;
}

/// Query parameters accepted at `/.well-known/webfinger`.
#[derive(Debug, Deserialize)]
struct WebFingerQuery {
    resource: String,
}

/// Builds the `/.well-known/webfinger` router.
///
/// Mount at the root of your service (NOT under a prefix) so that
/// the conventional well-known path resolves correctly:
///
/// ```ignore
/// let app = axum::Router::new().merge(webfinger_router(my_resolver));
/// ```
pub fn webfinger_router<R>(resolver: R) -> Router
where
    R: WebFingerResolver,
{
    Router::new()
        .route("/.well-known/webfinger", get(handle::<R>))
        .with_state(Arc::new(resolver))
}

async fn handle<R>(
    State(resolver): State<Arc<R>>,
    Query(q): Query<WebFingerQuery>,
) -> impl IntoResponse
where
    R: WebFingerResolver,
{
    let cors = (header::ACCESS_CONTROL_ALLOW_ORIGIN, CORS_ALLOW_ANY_ORIGIN);
    match resolver.resolve(q.resource).await {
        Ok(Some(jrd)) => match serde_json::to_vec(&jrd) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, JRD_CONTENT_TYPE), cors],
                body,
            )
                .into_response(),
            Err(err) => {
                tracing::error!(target: "actpub::axum::webfinger", %err, "JRD serialise failed");
                (StatusCode::INTERNAL_SERVER_ERROR, [cors]).into_response()
            }
        },
        Ok(None) => (StatusCode::NOT_FOUND, [cors]).into_response(),
        Err(err) => {
            tracing::warn!(target: "actpub::axum::webfinger", reason = %err, "resolver failed");
            (StatusCode::INTERNAL_SERVER_ERROR, [cors]).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use actpub_webfinger::{Jrd, JrdLink, rels};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    struct StaticResolver(Option<Jrd>);

    impl WebFingerResolver for StaticResolver {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "trait definition requires async but mock implementation has no await"
        )]
        async fn resolve(&self, _resource: String) -> Result<Option<Jrd>, String> {
            Ok(self.0.clone())
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

    #[tokio::test]
    async fn router_returns_jrd_for_known_resource() {
        let app = webfinger_router(StaticResolver(Some(alice_jrd())));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/webfinger?resource=acct:alice@example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            JRD_CONTENT_TYPE,
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["subject"], serde_json::json!("acct:alice@example.com"));
    }

    #[tokio::test]
    async fn router_returns_404_for_unknown_resource() {
        let app = webfinger_router(StaticResolver(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/webfinger?resource=acct:ghost@example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_returns_400_when_resource_query_param_is_missing() {
        let app = webfinger_router(StaticResolver(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/webfinger")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // axum's Query extractor rejects with 400 on missing fields.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn router_emits_cors_header_on_success() {
        // RFC 7033 §8.4 MUSTs `Access-Control-Allow-Origin: *` so
        // browser-based Fediverse UIs can query the endpoint.
        let app = webfinger_router(StaticResolver(Some(alice_jrd())));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/webfinger?resource=acct:alice@example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*"),
        );
    }

    #[tokio::test]
    async fn router_emits_cors_header_on_404() {
        let app = webfinger_router(StaticResolver(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/webfinger?resource=acct:ghost@example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*"),
        );
    }
}
