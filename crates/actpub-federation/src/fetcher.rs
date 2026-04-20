//! HTTP-based fetcher for `ActivityPub` objects.
//!
//! [`Fetcher`] is the trait every higher-level component (inbox
//! pipeline, outbox helper, dereferencing collection iterator) calls
//! when it needs to follow a URL into a JSON-LD `ActivityPub` document.
//! [`ReqwestFetcher`] is the production implementation built on
//! [`reqwest`], adding URL admission, response-size capping, content-
//! type validation, in-memory caching and (optionally) signed
//! authorised fetch.
//!
//! # IO contract
//!
//! Every call enters the URL through [`UrlPolicy::check`]; if a URL
//! cannot pass policy the fetcher returns
//! [`Error::PolicyViolation`] **without** initiating any network IO.
//! When a request does proceed, response bodies are read through a
//! streaming counter so that an oversize response is rejected with
//! [`Error::ResponseTooLarge`] long before it can exhaust memory.
//!
//! # Caching
//!
//! Successful responses are cached as raw bytes keyed by the absolute
//! URL with TTL [`FederationConfig::cache_ttl`]. Setting
//! [`FederationConfig::cache_capacity`] to `0` disables caching. The
//! cache is per-`ReqwestFetcher`; clone the fetcher (it is internally
//! `Arc`-shared via [`Self::clone`]) to share a cache across worker
//! tasks.
//!
//! # Signed fetch (Mastodon "authorized fetch" / "secure mode")
//!
//! When [`FederationConfig::signed_fetch`] is true the fetcher signs
//! every outbound GET with the configured [`SigningKey`] using the
//! Cavage HTTP-Signatures profile that Mastodon expects. Disabled by
//! default to keep the fetcher usable against Pleroma / Misskey
//! deployments that block unsigned actor fetches in restricted modes.

use std::sync::Arc;

use actpub_httpsig::CavageSigner;
use bytes::Bytes;
use futures::StreamExt;
use http::Method;
use moka::future::Cache;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, ClientBuilder};
use serde::de::DeserializeOwned;
use url::Url;

use crate::config::FederationConfig;
use crate::error::Error;

/// `Accept:` header value sent on every fetch.
///
/// Lists both the modern `application/activity+json` and the JSON-LD
/// profile media type so implementations that emit either shape
/// (Mastodon vs Lemmy) can service us with their canonical document.
pub const AP_ACCEPT_HEADER: &str = "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

/// Bare `ActivityPub` media type sent by Mastodon for actor /
/// activity JSON.
pub const AP_CONTENT_TYPE: &str = "application/activity+json";

/// JSON-LD media type prefix used by Lemmy, Mitra and others for
/// the same documents.
pub const LD_CONTENT_TYPE_PREFIX: &str = "application/ld+json";

/// Header set used when signing authenticated GET fetches.
///
/// Per Mastodon's authorized-fetch contract: `(request-target)`,
/// `host`, `date` — `digest` is intentionally excluded because GET
/// requests carry no body to digest.
const SIGNED_FETCH_HEADER_SET: &[&str] = &["(request-target)", "host", "date"];

/// Asynchronous accessor that turns an `ActivityPub` URL into a JSON
/// document.
///
/// Implementors are expected to enforce URL admission, response-size
/// caps and any cache they care to maintain. The trait is generic in
/// the wire shape ([`fetch_raw`](Self::fetch_raw) returns
/// [`serde_json::Value`]) so callers pick their own typed wrapper
/// outside the trait — keeping the trait dyn-compatible if they want.
pub trait Fetcher: Send + Sync {
    /// Fetches the JSON document at `url` and returns the parsed
    /// [`serde_json::Value`].
    ///
    /// # Errors
    ///
    /// May return any [`Error`] variant depending on whether the
    /// failure originated from URL policy, transport, status code,
    /// content-type validation, body size cap, or JSON parsing.
    fn fetch_raw(&self, url: &Url)
    -> impl Future<Output = Result<serde_json::Value, Error>> + Send;

    /// Convenience that fetches `url` and deserialises into `T`.
    ///
    /// # Errors
    ///
    /// Same as [`fetch_raw`](Self::fetch_raw), plus
    /// [`Error::Json`] when the document does not deserialise into
    /// the requested shape.
    fn fetch_typed<T>(&self, url: &Url) -> impl Future<Output = Result<T, Error>> + Send
    where
        T: DeserializeOwned + Send,
    {
        async move {
            let v = self.fetch_raw(url).await?;
            Ok(serde_json::from_value(v)?)
        }
    }
}

/// Production [`Fetcher`] implementation backed by [`reqwest`].
///
/// Cheap to clone — the underlying HTTP client and cache are stored
/// in an [`Arc`].
#[derive(Clone)]
pub struct ReqwestFetcher {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ReqwestFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestFetcher")
            .field("user_agent", &self.inner.config.user_agent)
            .field("cache_enabled", &self.inner.cache.is_some())
            .finish()
    }
}

struct Inner {
    client: Client,
    config: Arc<FederationConfig>,
    cache: Option<Cache<Url, Arc<Bytes>>>,
}

impl ReqwestFetcher {
    /// Builds a fetcher wired against `config`.
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
        let cache = (config.cache_capacity > 0).then(|| {
            Cache::builder()
                .max_capacity(config.cache_capacity)
                .time_to_live(config.cache_ttl)
                .build()
        });
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                config,
                cache,
            }),
        })
    }

    /// Returns the configuration shared with this fetcher.
    #[must_use]
    pub fn config(&self) -> &Arc<FederationConfig> {
        &self.inner.config
    }

    /// Issues the underlying HTTP GET. Separated from
    /// [`Fetcher::fetch_raw`] so the integration tests can poke the
    /// pre-cache, post-policy fetch path independently.
    async fn fetch_bytes(&self, url: &Url) -> Result<Bytes, Error> {
        let mut req = self
            .inner
            .client
            .request(Method::GET, url.clone())
            .header(ACCEPT, AP_ACCEPT_HEADER);
        if self.inner.config.signed_fetch {
            req = sign_get_request(req, url, &self.inner.config)?;
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Status {
                url: url.clone(),
                status: status.as_u16(),
            });
        }
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if !is_activitypub_media_type(&content_type) {
            return Err(Error::UnexpectedContentType {
                url: url.clone(),
                content_type,
            });
        }

        let limit = self.inner.config.max_response_bytes;
        let mut stream = resp.bytes_stream();
        let mut acc: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let new_total = acc.len() as u64 + chunk.len() as u64;
            if new_total > limit {
                return Err(Error::ResponseTooLarge {
                    url: url.clone(),
                    limit,
                });
            }
            acc.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(acc))
    }
}

impl Fetcher for ReqwestFetcher {
    async fn fetch_raw(&self, url: &Url) -> Result<serde_json::Value, Error> {
        self.inner.config.url_policy.check(url)?;

        if let Some(cache) = &self.inner.cache
            && let Some(hit) = cache.get(url).await
        {
            return Ok(serde_json::from_slice(&hit)?);
        }

        let bytes = self.fetch_bytes(url).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(cache) = &self.inner.cache {
            cache.insert(url.clone(), Arc::new(bytes)).await;
        }
        Ok(value)
    }
}

/// Builds an `http::Request` with the headers a signed GET fetch must
/// carry: `host` and `date`. The signer then adds `Signature:`.
fn build_signed_get_skeleton(url: &Url) -> Result<http::Request<Vec<u8>>, Error> {
    http::Request::builder()
        .method(Method::GET)
        .uri(url.as_str())
        .header("host", url.host_str().unwrap_or(""))
        .header(
            "date",
            httpdate::fmt_http_date(std::time::SystemTime::now()),
        )
        .body(Vec::<u8>::new())
        .map_err(|e| Error::PolicyViolation {
            url: url.clone(),
            reason: format!("could not build signed GET request: {e}"),
        })
}

/// Signs an outbound `reqwest` GET builder with the configured
/// Cavage HTTP-Signature key. Used by the fetcher when
/// [`FederationConfig::signed_fetch`] is enabled.
fn sign_get_request(
    mut req: reqwest::RequestBuilder,
    url: &Url,
    config: &FederationConfig,
) -> Result<reqwest::RequestBuilder, Error> {
    let mut http_req = build_signed_get_skeleton(url)?;
    CavageSigner::new(&config.signing_key, config.key_id.as_str())
        .with_headers(SIGNED_FETCH_HEADER_SET.iter().copied())
        .sign(&mut http_req)?;
    for (name, value) in http_req.headers() {
        let Ok(v) = value.to_str() else { continue };
        req = req.header(name.as_str(), v);
    }
    Ok(req)
}

/// Computes a Cavage HTTP-Signature `Signature:` header value for the
/// hypothetical `GET <url>` request the fetcher would emit when
/// [`FederationConfig::signed_fetch`] is enabled.
///
/// Useful in tests and tooling that need to inspect or replay the
/// wire-format signature without performing a real fetch. The header
/// set signed is the same as the one used by [`sign_get_request`]:
/// `(request-target)`, `host`, `date` (no `digest`, since GETs have
/// no body).
///
/// # Errors
///
/// Returns [`Error::PolicyViolation`] when the request cannot be
/// constructed (the helper does not perform IO and so cannot return
/// transport errors), or [`Error::HttpSig`] when Cavage signing fails.
pub fn signed_fetch_signature_header(
    config: &FederationConfig,
    url: &Url,
) -> Result<String, Error> {
    let mut req = build_signed_get_skeleton(url)?;
    CavageSigner::new(&config.signing_key, config.key_id.as_str())
        .with_headers(SIGNED_FETCH_HEADER_SET.iter().copied())
        .sign(&mut req)?;
    Ok(req
        .headers()
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned())
}

/// Whether `content_type` names one of the media types the
/// `ActivityPub` specification permits for actor / activity
/// documents: [`AP_CONTENT_TYPE`] or anything beginning with
/// [`LD_CONTENT_TYPE_PREFIX`].
///
/// Bare `application/json` is intentionally rejected: `ActivityPub`
/// §3.2 is explicit about the two acceptable media types, and
/// accepting plain JSON invites content-type confusion where a
/// non-AP endpoint (OAuth error, RSS feed, etc.) is misread as an
/// actor document.
fn is_activitypub_media_type(content_type: &str) -> bool {
    let primary = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    primary == AP_CONTENT_TYPE || primary.starts_with(LD_CONTENT_TYPE_PREFIX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actpub_httpsig::SigningKey;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::FederationConfig;
    use crate::policy::UrlPolicy;

    fn test_config(server_url: &str) -> Arc<FederationConfig> {
        FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id(format!("{server_url}/users/alice#key").parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .build()
            .shared()
    }

    #[test]
    fn media_type_helper_recognises_activity_pub_and_json_ld_variants() {
        assert!(is_activitypub_media_type("application/activity+json"));
        assert!(is_activitypub_media_type(
            "application/activity+json; charset=utf-8"
        ));
        assert!(is_activitypub_media_type("application/ld+json"));
        assert!(is_activitypub_media_type(
            "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""
        ));
        // `application/json` is NOT a valid ActivityPub media type
        // per §3.2 — accepting it would allow content-type confusion.
        assert!(!is_activitypub_media_type("application/json"));
        assert!(!is_activitypub_media_type("text/html"));
        assert!(!is_activitypub_media_type(""));
    }

    #[tokio::test]
    async fn fetch_returns_json_for_a_well_formed_actor() {
        let server = MockServer::start().await;
        let url = format!("{}/users/alice", server.uri());
        Mock::given(method("GET"))
            .and(path("/users/alice"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(
                    serde_json::to_vec(&json!({
                        "id": url,
                        "type": "Person",
                        "preferredUsername": "alice"
                    }))
                    .unwrap(),
                    AP_CONTENT_TYPE,
                ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let value = fetcher.fetch_raw(&url.parse().unwrap()).await.unwrap();
        assert_eq!(value["preferredUsername"], json!("alice"));
    }

    #[tokio::test]
    async fn fetch_caches_subsequent_requests_to_the_same_url() {
        let server = MockServer::start().await;
        let url = format!("{}/users/bob", server.uri());
        Mock::given(method("GET"))
            .and(path("/users/bob"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&json!({ "id": url, "type": "Person" })).unwrap(),
                AP_CONTENT_TYPE,
            ))
            // Second call MUST be served from the cache, not the server.
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        fetcher.fetch_raw(&url.parse().unwrap()).await.unwrap();
        fetcher.fetch_raw(&url.parse().unwrap()).await.unwrap();
    }

    #[tokio::test]
    async fn fetch_disables_cache_when_capacity_is_zero() {
        let server = MockServer::start().await;
        let url = format!("{}/users/carol", server.uri());
        Mock::given(method("GET"))
            .and(path("/users/carol"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&json!({ "id": url, "type": "Person" })).unwrap(),
                AP_CONTENT_TYPE,
            ))
            // Both calls MUST hit the server.
            .expect(2)
            .mount(&server)
            .await;

        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id(format!("{}/users/x#key", server.uri()).parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .cache_capacity(0)
            .build()
            .shared();
        let fetcher = ReqwestFetcher::new(cfg).unwrap();
        fetcher.fetch_raw(&url.parse().unwrap()).await.unwrap();
        fetcher.fetch_raw(&url.parse().unwrap()).await.unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_non_2xx_status() {
        let server = MockServer::start().await;
        let url = format!("{}/missing", server.uri());
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let err = fetcher
            .fetch_raw(&url.parse().unwrap())
            .await
            .expect_err("404 must propagate as Status");
        assert!(matches!(err, Error::Status { status: 404, .. }));
    }

    #[tokio::test]
    async fn fetch_rejects_unexpected_content_type() {
        let server = MockServer::start().await;
        let url = format!("{}/html", server.uri());
        Mock::given(method("GET"))
            .and(path("/html"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(b"<html>oops</html>".to_vec(), "text/html"),
            )
            .mount(&server)
            .await;
        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let err = fetcher
            .fetch_raw(&url.parse().unwrap())
            .await
            .expect_err("HTML must be rejected by content-type check");
        assert!(matches!(err, Error::UnexpectedContentType { .. }));
    }

    #[tokio::test]
    async fn fetch_caps_response_body_size() {
        let server = MockServer::start().await;
        let url = format!("{}/big", server.uri());
        // 64 KiB of JSON; we cap at 1 KiB.
        let big = "x".repeat(65_536);
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!("{{\"data\":\"{big}\"}}").into_bytes(),
                AP_CONTENT_TYPE,
            ))
            .mount(&server)
            .await;
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id(format!("{}/users/x#key", server.uri()).parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .max_response_bytes(1024)
            .build()
            .shared();
        let fetcher = ReqwestFetcher::new(cfg).unwrap();
        let err = fetcher
            .fetch_raw(&url.parse().unwrap())
            .await
            .expect_err("oversize body must be rejected");
        assert!(
            matches!(err, Error::ResponseTooLarge { limit: 1024, .. }),
            "expected ResponseTooLarge, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_short_circuits_on_url_policy_violation() {
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://example.com/users/x#key".parse().unwrap())
            .build()
            .shared();
        let fetcher = ReqwestFetcher::new(cfg).unwrap();
        // strict default policy: HTTP scheme is rejected before any IO.
        let err = fetcher
            .fetch_raw(&"http://example.com/".parse().unwrap())
            .await
            .expect_err("HTTP must fail strict policy");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn fetch_typed_round_trips_through_serde() {
        let server = MockServer::start().await;
        let url = format!("{}/u/dave", server.uri());
        Mock::given(method("GET"))
            .and(path("/u/dave"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(
                    serde_json::to_vec(&json!({
                        "id": url,
                        "type": "Person",
                        "preferredUsername": "dave"
                    }))
                    .unwrap(),
                    AP_CONTENT_TYPE,
                ),
            )
            .mount(&server)
            .await;
        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let person: actpub_activitystreams::Object = fetcher
            .fetch_typed(&url.parse().unwrap())
            .await
            .expect("typed fetch");
        assert!(person.is_kind("Person"));
        assert_eq!(person.preferred_username.as_deref(), Some("dave"));
    }

    #[test]
    fn signed_fetch_helper_emits_a_signature_header() {
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .signed_fetch(true)
            .build();
        let url: Url = "https://example.com/users/alice".parse().unwrap();
        let header = signed_fetch_signature_header(&cfg, &url).unwrap();
        assert!(header.contains("keyId="));
        assert!(header.contains("algorithm="));
        assert!(header.contains("signature="));
    }
}
