//! Single-shot HTTP delivery of `ActivityPub` activities.
//!
//! [`Deliverer`] is the trait every higher-level outbox helper calls
//! when it needs to POST one (already-serialised) activity at one
//! inbox URL. [`ReqwestDeliverer`] is the production implementation:
//! it serialises the activity, attaches a `Date`, `Host`,
//! `Content-Type` and RFC 9530 `Content-Digest` header, signs the
//! request with the configured Cavage HTTP-Signature key, and POSTs
//! it via [`reqwest`].
//!
//! Retry logic, fan-out across recipients and shared-inbox grouping
//! are intentionally **not** part of this trait — they belong to the
//! [`outbox`](crate::outbox) module that composes a `Deliverer` with
//! a [`RetryPolicy`](crate::RetryPolicy).
//!
//! # IO contract
//!
//! - The inbox URL is checked against the configured
//!   [`UrlPolicy`](crate::UrlPolicy) **before** any network IO.
//! - The activity is serialised once via `serde_json` so the bytes
//!   that get hashed for `Content-Digest` and the bytes that get
//!   `POST`ed are by construction identical.
//! - A 2xx response is success; anything else surfaces as
//!   [`Error::Status`]; transport failures surface as
//!   [`Error::Http`].

use std::sync::Arc;

use actpub_httpsig::{
    CONTENT_DIGEST_HEADER, CavageSigner, DigestAlgorithm, content_digest_header_with,
    sha256_digest_header,
};
use http::Method;
use http::header::{CONTENT_TYPE, DATE, HOST};
use reqwest::{Client, ClientBuilder};
use serde_json::Value;
use url::Url;

use crate::config::FederationConfig;
use crate::error::Error;
use crate::fetcher::AP_CONTENT_TYPE;

/// Asynchronous one-shot deliverer.
///
/// Trait, not type, so callers (and the `outbox` retry queue) can
/// swap in a fake for testing without touching the runtime wiring.
pub trait Deliverer: Send + Sync {
    /// POSTs `activity` (already a JSON value) to `inbox`.
    ///
    /// Returns `Ok(())` only when the receiving server replies with a
    /// 2xx status and the entire HTTP exchange succeeded.
    ///
    /// # Errors
    ///
    /// May return any [`Error`] variant: [`Error::PolicyViolation`]
    /// for forbidden inboxes, [`Error::Http`] for transport failures,
    /// [`Error::Status`] for non-2xx responses, [`Error::HttpSig`]
    /// for signing failures.
    fn deliver(
        &self,
        activity: &Value,
        inbox: &Url,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Production [`Deliverer`] implementation backed by [`reqwest`].
///
/// Cheap to clone — the underlying HTTP client and configuration are
/// stored in an [`Arc`].
#[derive(Clone)]
pub struct ReqwestDeliverer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ReqwestDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestDeliverer")
            .field("user_agent", &self.inner.config.user_agent)
            .finish()
    }
}

struct Inner {
    client: Client,
    config: Arc<FederationConfig>,
}

impl ReqwestDeliverer {
    /// Builds a deliverer wired against `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the underlying [`reqwest::Client`]
    /// cannot be constructed (typically a TLS init failure).
    pub fn new(config: Arc<FederationConfig>) -> Result<Self, Error> {
        let client = ClientBuilder::new()
            .user_agent(config.user_agent.clone())
            .timeout(config.request_timeout)
            .https_only(config.url_policy.require_https)
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner { client, config }),
        })
    }

    /// Returns the configuration shared with this deliverer.
    #[must_use]
    pub fn config(&self) -> &Arc<FederationConfig> {
        &self.inner.config
    }
}

impl Deliverer for ReqwestDeliverer {
    async fn deliver(&self, activity: &Value, inbox: &Url) -> Result<(), Error> {
        self.inner.config.url_policy.check(inbox)?;

        let body = serde_json::to_vec(activity)?;
        // Both digests: the legacy `Digest:` header (Mastodon's
        // mandatory Cavage signing input) and RFC 9530
        // `Content-Digest:` (modern SHA-256 only; multi-algo can
        // come later as we observe peer support).
        let legacy_digest = sha256_digest_header(&body);
        let modern_digest = content_digest_header_with(&body, &[DigestAlgorithm::Sha256]);
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let host = inbox.host_str().unwrap_or("");

        // Build a typed http::Request, sign it via Cavage, then copy
        // the produced headers into the reqwest builder so the
        // exchange matches what every Mastodon-compatible peer
        // expects on the wire.
        let mut signing_req = http::Request::builder()
            .method(Method::POST)
            .uri(inbox.as_str())
            .header(HOST, host)
            .header(DATE, date.clone())
            .header(CONTENT_TYPE, AP_CONTENT_TYPE)
            .header("digest", legacy_digest.clone())
            .header(CONTENT_DIGEST_HEADER, modern_digest.clone())
            .body(body.clone())
            .map_err(|e| Error::PolicyViolation {
                url: inbox.clone(),
                reason: format!("could not build delivery request: {e}"),
            })?;
        CavageSigner::new(
            &self.inner.config.signing_key,
            self.inner.config.key_id.as_str(),
        )
        .sign(&mut signing_req)?;

        let mut req = self
            .inner
            .client
            .request(Method::POST, inbox.clone())
            .header(CONTENT_TYPE, AP_CONTENT_TYPE)
            .body(body);
        for (name, value) in signing_req.headers() {
            // `host` is set by reqwest from the request URL; copying
            // it again would cause a duplicate-header collision.
            if name == HOST {
                continue;
            }
            let Ok(v) = value.to_str() else { continue };
            req = req.header(name.as_str(), v);
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Status {
                url: inbox.clone(),
                status: status.as_u16(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actpub_httpsig::SigningKey;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::policy::UrlPolicy;

    fn test_config(server_url: &str) -> Arc<FederationConfig> {
        FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id(format!("{server_url}/users/alice#key").parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .build()
            .shared()
    }

    fn sample_activity() -> Value {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://example.com/activities/01HQ4N7G",
            "type": "Create",
            "actor": "https://example.com/users/alice",
            "object": {
                "id": "https://example.com/notes/01HQ4N7H",
                "type": "Note",
                "content": "<p>hi Fediverse</p>"
            }
        })
    }

    #[tokio::test]
    async fn deliver_succeeds_when_inbox_returns_2xx() {
        let server = MockServer::start().await;
        let inbox: Url = format!("{}/users/bob/inbox", server.uri()).parse().unwrap();
        Mock::given(method("POST"))
            .and(path("/users/bob/inbox"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let deliverer = ReqwestDeliverer::new(test_config(&server.uri())).unwrap();
        deliverer.deliver(&sample_activity(), &inbox).await.unwrap();
    }

    #[tokio::test]
    async fn deliver_rejects_non_2xx_with_status_error() {
        let server = MockServer::start().await;
        let inbox: Url = format!("{}/users/dead/inbox", server.uri())
            .parse()
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/users/dead/inbox"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let deliverer = ReqwestDeliverer::new(test_config(&server.uri())).unwrap();
        let err = deliverer
            .deliver(&sample_activity(), &inbox)
            .await
            .expect_err("500 must propagate");
        assert!(matches!(err, Error::Status { status: 500, .. }));
    }

    #[tokio::test]
    async fn deliver_short_circuits_on_url_policy_violation() {
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .build()
            .shared();
        let deliverer = ReqwestDeliverer::new(cfg).unwrap();
        // Strict default policy: HTTP scheme is rejected before any IO.
        let err = deliverer
            .deliver(
                &sample_activity(),
                &"http://example.com/inbox".parse().unwrap(),
            )
            .await
            .expect_err("HTTP must fail strict policy");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn delivery_request_carries_content_type_digest_signature_and_date_headers() {
        let server = MockServer::start().await;
        let inbox: Url = format!("{}/inbox", server.uri()).parse().unwrap();
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(|req: &Request| {
                let headers = &req.headers;
                // Mandatory federation headers per Mastodon's inbox
                // contract: Content-Type, Date, Signature, and a
                // body-binding digest.
                assert_eq!(
                    headers.get("content-type").map(http::HeaderValue::as_bytes),
                    Some(AP_CONTENT_TYPE.as_bytes()),
                );
                assert!(headers.contains_key("date"), "Date header missing");
                assert!(
                    headers.contains_key("signature"),
                    "Cavage Signature header missing",
                );
                assert!(
                    headers.contains_key("content-digest"),
                    "RFC 9530 Content-Digest header missing",
                );
                ResponseTemplate::new(200)
            })
            .expect(1)
            .mount(&server)
            .await;

        let deliverer = ReqwestDeliverer::new(test_config(&server.uri())).unwrap();
        deliverer.deliver(&sample_activity(), &inbox).await.unwrap();
    }

    #[tokio::test]
    async fn delivery_body_round_trips_through_the_wire() {
        // The receiving peer MUST be able to deserialise the body we
        // send back into the same JSON value (modulo serde_json key
        // ordering, which we don't constrain here).
        let server = MockServer::start().await;
        let inbox: Url = format!("{}/echo", server.uri()).parse().unwrap();
        let activity = sample_activity();
        let expected_id = activity["id"].clone();
        Mock::given(method("POST"))
            .and(path("/echo"))
            .respond_with(move |req: &Request| {
                let body: Value = serde_json::from_slice(&req.body).expect("valid JSON body");
                assert_eq!(body["id"], expected_id);
                assert_eq!(body["type"], json!("Create"));
                ResponseTemplate::new(200)
            })
            .expect(1)
            .mount(&server)
            .await;

        let deliverer = ReqwestDeliverer::new(test_config(&server.uri())).unwrap();
        deliverer.deliver(&activity, &inbox).await.unwrap();
    }
}
