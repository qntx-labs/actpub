//! axum router serving the `/.well-known/nodeinfo` discovery
//! document plus per-version schema endpoints.
//!
//! [`nodeinfo_router`] builds a router that exposes:
//!
//! - `GET /.well-known/nodeinfo` returning the [`Discovery`] document
//!   pointing to one or more schema URLs (typically 2.0 and 2.1).
//! - `GET /nodeinfo/2.0` and `GET /nodeinfo/2.1` returning the
//!   [`NodeInfo`] documents the discovery references.
//!
//! The user supplies the per-version [`NodeInfo`] documents at
//! construction time; the discovery document is generated
//! automatically from the document set.

use std::sync::Arc;

use actpub_nodeinfo::{Discovery, NodeInfo, Version};
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use url::Url;

/// `Content-Type` Mastodon and most Fediverse peers send for
/// `NodeInfo` documents (matches what nodeinfo.diaspora.software
/// recommends).
pub const NODEINFO_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// Shared state for the `NodeInfo` router.
///
/// Holds the per-version documents and the public base URL the
/// discovery document points at.
#[derive(Debug, Clone)]
pub struct NodeInfoState {
    /// Public base URL of this server, used to build the discovery
    /// links (e.g. `https://example.com`).
    pub base_url: Url,
    /// Optional `NodeInfo` 2.0 document.
    pub v2_0: Option<NodeInfo>,
    /// Optional `NodeInfo` 2.1 document.
    pub v2_1: Option<NodeInfo>,
}

impl NodeInfoState {
    /// Constructs a state holding both 2.0 and 2.1 documents
    /// (the typical setup; both versions are spec-equivalent for the
    /// fields most consumers care about).
    #[must_use]
    pub const fn dual(base_url: Url, v2_0: NodeInfo, v2_1: NodeInfo) -> Self {
        Self {
            base_url,
            v2_0: Some(v2_0),
            v2_1: Some(v2_1),
        }
    }

    /// Constructs a state holding only a `NodeInfo` 2.1 document.
    #[must_use]
    pub const fn only_v2_1(base_url: Url, v2_1: NodeInfo) -> Self {
        Self {
            base_url,
            v2_0: None,
            v2_1: Some(v2_1),
        }
    }

    fn discovery(&self) -> Discovery {
        let mut disco = Discovery::default();
        if self.v2_0.is_some()
            && let Ok(href) = self.versioned_href(Version::V2_0)
        {
            disco = disco.with_version(Version::V2_0, href);
        }
        if self.v2_1.is_some()
            && let Ok(href) = self.versioned_href(Version::V2_1)
        {
            disco = disco.with_version(Version::V2_1, href);
        }
        disco
    }

    fn versioned_href(&self, version: Version) -> Result<Url, url::ParseError> {
        self.base_url
            .join(&format!("/nodeinfo/{}", version.as_str()))
    }
}

/// Builds the `NodeInfo` router.
///
/// Mount at the root of your service so the well-known path resolves
/// at the conventional location:
///
/// ```ignore
/// let app = axum::Router::new().merge(nodeinfo_router(state));
/// ```
pub fn nodeinfo_router(state: NodeInfoState) -> Router {
    Router::new()
        .route("/.well-known/nodeinfo", get(handle_discovery))
        .route("/nodeinfo/2.0", get(handle_v2_0))
        .route("/nodeinfo/2.1", get(handle_v2_1))
        .with_state(Arc::new(state))
}

async fn handle_discovery(State(state): State<Arc<NodeInfoState>>) -> impl IntoResponse {
    json_response(state.discovery())
}

async fn handle_v2_0(State(state): State<Arc<NodeInfoState>>) -> impl IntoResponse {
    state.v2_0.as_ref().map_or_else(
        || StatusCode::NOT_FOUND.into_response(),
        |info| json_response_with_schema(info, Version::V2_0).into_response(),
    )
}

async fn handle_v2_1(State(state): State<Arc<NodeInfoState>>) -> impl IntoResponse {
    state.v2_1.as_ref().map_or_else(
        || StatusCode::NOT_FOUND.into_response(),
        |info| json_response_with_schema(info, Version::V2_1).into_response(),
    )
}

fn json_response<T: serde::Serialize>(value: T) -> axum::response::Response {
    match serde_json::to_vec(&value) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, NODEINFO_CONTENT_TYPE)],
            bytes,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(target: "actpub::axum::nodeinfo", %err, "JSON serialise failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Per the `NodeInfo` schema, the body Content-Type SHOULD include the
/// schema URI as a `profile` parameter so clients can avoid
/// guessing the version from the response shape.
fn json_response_with_schema<T: serde::Serialize>(
    value: T,
    version: Version,
) -> axum::response::Response {
    let content_type = format!(
        r#"application/json; charset=utf-8; profile="{}""#,
        version.schema_uri(),
    );
    match serde_json::to_vec(&value) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type.as_str())],
            bytes,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(target: "actpub::axum::nodeinfo", %err, "JSON serialise failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use actpub_nodeinfo::{NodeInfo, Protocol, Software, Version};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn sample_node_info(version: Version) -> NodeInfo {
        NodeInfo::builder(version, Software::new("test-server", "0.1.0"))
            .protocol(Protocol::ActivityPub)
            .build()
    }

    fn dual_state() -> NodeInfoState {
        NodeInfoState::dual(
            "https://example.com".parse().unwrap(),
            sample_node_info(Version::V2_0),
            sample_node_info(Version::V2_1),
        )
    }

    #[tokio::test]
    async fn discovery_lists_both_versions() {
        let app = nodeinfo_router(dual_state());
        let req = Request::builder()
            .uri("/.well-known/nodeinfo")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let links = v["links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        assert!(
            links
                .iter()
                .any(|l| l["href"].as_str().unwrap_or("").ends_with("/nodeinfo/2.0"))
        );
        assert!(
            links
                .iter()
                .any(|l| l["href"].as_str().unwrap_or("").ends_with("/nodeinfo/2.1"))
        );
    }

    #[tokio::test]
    async fn schema_endpoint_returns_node_info_with_versioned_profile() {
        let app = nodeinfo_router(dual_state());
        let req = Request::builder()
            .uri("/nodeinfo/2.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains(r#"profile="http://nodeinfo.diaspora.software/ns/schema/2.0""#),
            "missing schema profile parameter: {ct}",
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["version"], serde_json::json!("2.0"));
        assert_eq!(v["software"]["name"], serde_json::json!("test-server"));
    }

    #[tokio::test]
    async fn schema_endpoint_returns_404_for_a_disabled_version() {
        let state = NodeInfoState::only_v2_1(
            "https://example.com".parse().unwrap(),
            sample_node_info(Version::V2_1),
        );
        let app = nodeinfo_router(state);
        let req = Request::builder()
            .uri("/nodeinfo/2.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
