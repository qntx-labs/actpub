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
use http::{Method, StatusCode};
use moka::future::Cache;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Client, ClientBuilder};
use serde::de::DeserializeOwned;
use url::Url;

use crate::config::FederationConfig;
use crate::error::Error;
use crate::fetch_ctx::FetchContext;

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
///
/// # Budget propagation
///
/// Every call takes a [`FetchContext`] that tracks how many fetches
/// have been issued while servicing the current logical request.
/// Recursive dereferencing (an activity's `object` being a URL, whose
/// fetched object has an `inReplyTo` URL, …) MUST thread the **same**
/// context through so that the runtime can apply a single upper
/// bound via [`FederationConfig::http_fetch_limit`](crate::FederationConfig::http_fetch_limit).
pub trait Fetcher: Send + Sync {
    /// Fetches the JSON document at `url` and returns the parsed
    /// [`serde_json::Value`].
    ///
    /// # Errors
    ///
    /// May return any [`Error`] variant depending on whether the
    /// failure originated from URL policy, transport, status code,
    /// content-type validation, body size cap, or JSON parsing,
    /// including [`Error::RecursiveFetchLimit`] when the
    /// per-request budget in `ctx` has been exhausted and
    /// [`Error::FetchIdMismatch`] when the response's `id` field
    /// does not match the fetched URL.
    fn fetch_raw(
        &self,
        url: &Url,
        ctx: &FetchContext,
    ) -> impl Future<Output = Result<serde_json::Value, Error>> + Send;

    /// Convenience that fetches `url` and deserialises into `T`.
    ///
    /// # Errors
    ///
    /// Same as [`fetch_raw`](Self::fetch_raw), plus
    /// [`Error::Json`] when the document does not deserialise into
    /// the requested shape.
    fn fetch_typed<T>(
        &self,
        url: &Url,
        ctx: &FetchContext,
    ) -> impl Future<Output = Result<T, Error>> + Send
    where
        T: DeserializeOwned + Send,
    {
        async move {
            let v = self.fetch_raw(url, ctx).await?;
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
    /// The underlying [`reqwest::Client`] is built with
    /// [`RedirectPolicy::none`] so that every 3xx is surfaced to
    /// this crate, which then applies the configured
    /// [`UrlPolicy`](crate::UrlPolicy) to the `Location` target
    /// before (optionally) following it exactly once — closing the
    /// SSRF-via-redirect and TOCTOU-via-rebind holes that
    /// `reqwest`'s default 10-hop follower would otherwise leave
    /// open.
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
            .redirect(RedirectPolicy::none())
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

    /// Sends one GET request and returns the response body, **with
    /// explicit single-hop redirect handling**.
    ///
    /// Behaviour:
    ///
    /// - On 2xx, the response is validated (`Content-Type`, body
    ///   size cap) and the bytes returned.
    /// - On 3xx, the `Location` header is parsed and re-checked
    ///   against [`UrlPolicy::check_full`](crate::UrlPolicy::check_full).
    ///   If the target passes and `redirects_remaining > 0`, the
    ///   helper recurses once. Exceeding the hop budget or failing
    ///   policy produces [`Error::RedirectRejected`].
    /// - On other statuses, [`Error::Status`] is produced.
    ///
    /// This is the choke point where the
    /// [`FederationConfig::http_fetch_limit`](crate::FederationConfig::http_fetch_limit)
    /// budget is charged: each call is one fetch from the runtime's
    /// perspective, regardless of how many redirect hops were
    /// followed.
    async fn fetch_bytes(&self, url: &Url, ctx: &FetchContext) -> Result<(Bytes, Url), Error> {
        // One charge per *logical* fetch. Redirect hops are not
        // separately charged because a malicious chain still stops
        // at the one-hop ceiling enforced below.
        ctx.charge()?;
        self.fetch_bytes_with_hops(url, 1).await
    }

    /// Inner body of [`fetch_bytes`]. Returns both the validated
    /// body and the **final** URL after any permitted redirect, so
    /// the caller can perform `id`-integrity checks against the URL
    /// the bytes actually came from. The loop follows at most one
    /// redirect hop, which simplifies correctness reasoning: every
    /// iteration either (a) returns a validated body, (b) returns
    /// an error, or (c) rewrites `current` to the `Location`
    /// target and decrements `redirects_remaining`.
    async fn fetch_bytes_with_hops(
        &self,
        url: &Url,
        mut redirects_remaining: u32,
    ) -> Result<(Bytes, Url), Error> {
        let mut current = url.clone();
        loop {
            self.inner.config.url_policy.check_full(&current).await?;
            let resp = self.send_one(&current).await?;
            let status = resp.status();

            if status.is_redirection() {
                let target = self
                    .resolve_redirect(&current, &resp, redirects_remaining)
                    .await?;
                redirects_remaining -= 1;
                current = target;
                continue;
            }
            if !status.is_success() {
                return Err(translate_status(&current, status));
            }
            validate_content_type(&current, &resp)?;
            let bytes =
                read_capped_body(&current, resp, self.inner.config.max_response_bytes).await?;
            return Ok((bytes, current));
        }
    }

    /// Sends the HTTP request for `url`, attaching the signed-fetch
    /// `Signature:` header when the runtime is configured for it.
    async fn send_one(&self, url: &Url) -> Result<reqwest::Response, Error> {
        let mut req = self
            .inner
            .client
            .request(Method::GET, url.clone())
            .header(ACCEPT, AP_ACCEPT_HEADER);
        if self.inner.config.signed_fetch {
            req = sign_get_request(req, url, &self.inner.config)?;
        }
        Ok(req.send().await?)
    }

    /// Parses the `Location` header of a 3xx response, re-resolves it
    /// against `current`, re-applies [`UrlPolicy::check_full`] to the
    /// target, and enforces the single-hop ceiling by inspecting
    /// `redirects_remaining`.
    async fn resolve_redirect(
        &self,
        current: &Url,
        resp: &reqwest::Response,
        redirects_remaining: u32,
    ) -> Result<Url, Error> {
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| Error::RedirectRejected {
                from: current.clone(),
                to: String::new(),
                reason: "3xx without a `Location` header".to_owned(),
            })?;
        if redirects_remaining == 0 {
            return Err(Error::RedirectRejected {
                from: current.clone(),
                to: location,
                reason: "redirect chain exceeded one-hop ceiling".to_owned(),
            });
        }
        // `Location` may be absolute or relative; resolve against the
        // request URL so the re-check sees the target the transport
        // would actually connect to.
        let target = match Url::parse(&location) {
            Ok(u) => u,
            Err(_) => current
                .join(&location)
                .map_err(|e| Error::RedirectRejected {
                    from: current.clone(),
                    to: location.clone(),
                    reason: format!("`Location` is not a resolvable URL: {e}"),
                })?,
        };
        self.inner
            .config
            .url_policy
            .check_full(&target)
            .await
            .map_err(|e| match e {
                Error::PolicyViolation { reason, .. } => Error::RedirectRejected {
                    from: current.clone(),
                    to: target.to_string(),
                    reason,
                },
                other => other,
            })?;
        Ok(target)
    }
}

/// Validates the `Content-Type` header of a 2xx response against the
/// `ActivityPub` admission rule encoded in [`is_activitypub_media_type`].
fn validate_content_type(url: &Url, resp: &reqwest::Response) -> Result<(), Error> {
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
    Ok(())
}

/// Streams the body into memory, refusing any response that grows
/// past `limit` bytes. Prevents an oversize / infinite body from
/// exhausting the server's memory under adversarial load.
async fn read_capped_body(url: &Url, resp: reqwest::Response, limit: u64) -> Result<Bytes, Error> {
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

impl Fetcher for ReqwestFetcher {
    async fn fetch_raw(&self, url: &Url, ctx: &FetchContext) -> Result<serde_json::Value, Error> {
        // At most one iteration re-targets the request to the URL
        // named in the response's `id` field; every subsequent `id`
        // mismatch is treated as a rebinding attempt and rejected.
        let mut current = url.clone();
        let mut id_retries_remaining: u32 = 1;
        loop {
            // Cache hits bypass both the counter and the DNS check: they
            // represent fetches already budgeted for in a previous call,
            // and the cached bytes cannot possibly reach a new IP.
            if let Some(cache) = &self.inner.cache
                && let Some(hit) = cache.get(&current).await
            {
                return Ok(serde_json::from_slice(&hit)?);
            }

            // `final_url` is the URL the bytes actually came from
            // (after any permitted redirect hop). All `id`-integrity
            // reasoning MUST be against that URL, not the probe URL
            // we originally issued: otherwise every legitimate peer
            // that 302s an alias at `/u/alice → /users/alice` would
            // trip the rebinding guard.
            let (bytes, final_url) = self.fetch_bytes(&current, ctx).await?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;

            match check_id_integrity(&value, &final_url, id_retries_remaining) {
                IdCheck::Ok => {
                    self.populate_cache(final_url, bytes).await;
                    return Ok(value);
                }
                IdCheck::RetrySameHost(id_url) => {
                    id_retries_remaining -= 1;
                    current = id_url;
                }
                IdCheck::CrossDomainMismatch(id_url) => {
                    return Err(Error::FetchIdMismatch {
                        url: final_url,
                        id: id_url,
                    });
                }
            }
        }
    }
}

impl ReqwestFetcher {
    /// Inserts `(url → bytes)` into the fetch cache when caching is
    /// enabled. Extracted so the happy-path branch of
    /// [`Fetcher::fetch_raw`] stays flat.
    async fn populate_cache(&self, url: Url, bytes: Bytes) {
        if let Some(cache) = &self.inner.cache {
            cache.insert(url, Arc::new(bytes)).await;
        }
    }
}

/// Outcome of the `id`-integrity check applied after every fetch.
enum IdCheck {
    /// The response's `id` matches the URL it was served from, or
    /// the response carries no `id` field we could cross-check.
    Ok,
    /// The response claims a different `id` on the **same** host;
    /// the caller may re-fetch the claimed URL once.
    RetrySameHost(Url),
    /// The response claims an `id` on a different host — the
    /// classic `GHSA-jhrq-qvrm-qr36` rebinding shape.
    CrossDomainMismatch(Url),
}

/// Runs the Mastodon-GHSA-jhrq-qvrm-qr36 check against a freshly
/// fetched JSON document: the `id` field MUST agree with the URL
/// the bytes were served from, modulo cosmetic URL differences.
fn check_id_integrity(
    value: &serde_json::Value,
    final_url: &Url,
    id_retries_remaining: u32,
) -> IdCheck {
    let Some(id_str) = value.get("id").and_then(serde_json::Value::as_str) else {
        return IdCheck::Ok;
    };
    let Ok(id_url) = Url::parse(id_str) else {
        return IdCheck::Ok;
    };
    if urls_reference_same_resource(&id_url, final_url) {
        return IdCheck::Ok;
    }
    let same_host = matches!(
        (id_url.host_str(), final_url.host_str()),
        (Some(id_host), Some(url_host)) if id_host.eq_ignore_ascii_case(url_host),
    );
    if same_host && id_retries_remaining > 0 {
        IdCheck::RetrySameHost(id_url)
    } else {
        IdCheck::CrossDomainMismatch(id_url)
    }
}

/// Returns `true` when `a` and `b` address the same `ActivityPub`
/// resource, ignoring fragments and a lone trailing slash in the
/// path — both of which are cosmetic per RFC 3986 but happen in
/// practice (Mastodon's actor URL vs its inbox URL).
fn urls_reference_same_resource(a: &Url, b: &Url) -> bool {
    fn canonical(u: &Url) -> (Option<String>, String, String, Option<String>) {
        let scheme = u.scheme().to_ascii_lowercase();
        let host = u
            .host_str()
            .map(|h| h.to_ascii_lowercase().trim_end_matches('.').to_owned());
        let path = {
            let p = u.path();
            if p.len() > 1 && p.ends_with('/') && u.query().is_none() {
                p.trim_end_matches('/').to_owned()
            } else {
                p.to_owned()
            }
        };
        let query = u.query().map(str::to_owned);
        (host, scheme, path, query)
    }
    canonical(a) == canonical(b)
}

/// Maps a non-2xx, non-3xx response into an [`Error`]. Extracted so
/// the redirect-hop code path can reuse the exact same translation.
fn translate_status(url: &Url, status: StatusCode) -> Error {
    Error::Status {
        url: url.clone(),
        status: status.as_u16(),
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
    CavageSigner::new(config.signing_key_ref(), config.key_id.as_str())
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
    CavageSigner::new(config.signing_key_ref(), config.key_id.as_str())
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
/// documents: exactly [`AP_CONTENT_TYPE`] or exactly
/// [`LD_CONTENT_TYPE_PREFIX`].
///
/// Matching is performed against the media-type portion (before the
/// first `;`) lowercased for case-folding. Parameters that may
/// legitimately accompany the media type (`charset=utf-8`,
/// `profile="https://www.w3.org/ns/activitystreams"`) are accepted
/// because they sit past the separator and do not affect the
/// comparison.
///
/// Bare `application/json` is intentionally rejected: `ActivityPub`
/// §3.2 is explicit about the two acceptable media types, and
/// accepting plain JSON invites content-type confusion where a
/// non-AP endpoint (OAuth error, RSS feed, etc.) is misread as an
/// actor document. A prefix-match on `application/ld+json` is also
/// rejected, which would otherwise admit bogus media types like
/// `application/ld+jsonsomething` that happen to share the prefix.
fn is_activitypub_media_type(content_type: &str) -> bool {
    let primary = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    primary == AP_CONTENT_TYPE || primary == LD_CONTENT_TYPE_PREFIX
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
    use crate::config::{DEFAULT_HTTP_FETCH_LIMIT, FederationConfig};
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

    #[test]
    fn media_type_helper_rejects_values_that_only_share_the_ld_json_prefix() {
        // Previously we used `starts_with("application/ld+json")`,
        // which would green-light bogus media types like the two
        // below. The exact-match rule closes that loophole.
        assert!(!is_activitypub_media_type("application/ld+jsonsomething"));
        assert!(!is_activitypub_media_type(
            "application/ld+jsonextra; charset=utf-8"
        ));
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let value = fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .unwrap();
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .unwrap();
        fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .unwrap();
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .unwrap();
        fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .unwrap();
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let err = fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let err = fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let err = fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        // strict default policy: HTTP scheme is rejected before any IO.
        let err = fetcher
            .fetch_raw(&"http://example.com/".parse().unwrap(), &ctx)
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
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let person: actpub_activitystreams::Object = fetcher
            .fetch_typed(&url.parse().unwrap(), &ctx)
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

    #[tokio::test]
    async fn fetch_budget_exhaustion_surfaces_as_recursive_fetch_limit() {
        // A `FetchContext` with a hard cap of 1 allows exactly one
        // successful fetch; the second call against the same context
        // must fail with the dedicated error variant so the caller
        // can distinguish DoS guards from transport failures.
        let server = MockServer::start().await;
        let url1 = format!("{}/u/a", server.uri());
        let url2 = format!("{}/u/b", server.uri());
        for path_str in ["/u/a", "/u/b"] {
            Mock::given(method("GET"))
                .and(path(path_str))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(
                        serde_json::to_vec(&json!({
                            "id": format!("{}{path_str}", server.uri()),
                            "type": "Person",
                        }))
                        .unwrap(),
                        AP_CONTENT_TYPE,
                    ),
                )
                .mount(&server)
                .await;
        }
        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let ctx = FetchContext::new(1);
        fetcher
            .fetch_raw(&url1.parse().unwrap(), &ctx)
            .await
            .expect("first fetch consumes the only budget slot");
        let err = fetcher
            .fetch_raw(&url2.parse().unwrap(), &ctx)
            .await
            .expect_err("second fetch must exceed the budget");
        assert!(matches!(err, Error::RecursiveFetchLimit { limit: 1 }));
    }

    #[tokio::test]
    async fn fetch_rejects_cross_domain_id_mismatch() {
        // The response claims an `id` on a host DIFFERENT from the
        // request URL's host — the classic rebinding shape. We must
        // refuse to cache the attacker's document under the victim's
        // URL.
        let server = MockServer::start().await;
        let url = format!("{}/u/victim", server.uri());
        Mock::given(method("GET"))
            .and(path("/u/victim"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(
                    serde_json::to_vec(&json!({
                        "id": "https://attacker.example/u/attacker",
                        "type": "Person",
                    }))
                    .unwrap(),
                    AP_CONTENT_TYPE,
                ),
            )
            .mount(&server)
            .await;
        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let err = fetcher
            .fetch_raw(&url.parse().unwrap(), &ctx)
            .await
            .expect_err("cross-domain id mismatch must be rejected");
        assert!(
            matches!(err, Error::FetchIdMismatch { .. }),
            "expected FetchIdMismatch, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_allows_same_domain_id_mismatch_once_via_re_fetch() {
        // Mastodon's actor-at-`/u/alice` commonly 301s or self-
        // references `/users/alice` via an `id` that differs only in
        // path. When `id` stays on the same host we re-fetch the
        // canonical URL once, which must succeed.
        let server = MockServer::start().await;
        let probe = format!("{}/u/alice", server.uri());
        let canonical = format!("{}/users/alice", server.uri());
        Mock::given(method("GET"))
            .and(path("/u/alice"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(
                    serde_json::to_vec(&json!({
                        "id": canonical,
                        "type": "Person",
                    }))
                    .unwrap(),
                    AP_CONTENT_TYPE,
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users/alice"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(
                    serde_json::to_vec(&json!({
                        "id": canonical,
                        "type": "Person",
                        "preferredUsername": "alice",
                    }))
                    .unwrap(),
                    AP_CONTENT_TYPE,
                ),
            )
            .mount(&server)
            .await;

        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let value = fetcher
            .fetch_raw(&probe.parse().unwrap(), &ctx)
            .await
            .expect("same-domain re-fetch must succeed");
        assert_eq!(value["id"], json!(canonical));
        assert_eq!(value["preferredUsername"], json!("alice"));
        // Two fetches against the shared context: the probe + the
        // canonical re-fetch.
        assert_eq!(ctx.count(), 2);
    }

    #[tokio::test]
    async fn fetch_follows_one_redirect_hop_but_no_more() {
        // The peer redirects once, then the redirected endpoint
        // returns a normal body. The fetcher must follow through
        // the `Location` target; the overall fetch counts as ONE
        // charge against the budget.
        let server = MockServer::start().await;
        let first = format!("{}/redirect-here", server.uri());
        let target = format!("{}/final", server.uri());
        Mock::given(method("GET"))
            .and(path("/redirect-here"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", &target))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&json!({ "id": target, "type": "Person" })).unwrap(),
                AP_CONTENT_TYPE,
            ))
            .mount(&server)
            .await;

        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let value = fetcher
            .fetch_raw(&first.parse().unwrap(), &ctx)
            .await
            .expect("single-hop redirect must succeed");
        assert_eq!(value["id"], json!(target));
        // One redirect chain is still one logical fetch in budget
        // terms.
        assert_eq!(ctx.count(), 1);
    }

    #[tokio::test]
    async fn fetch_rejects_second_redirect_hop() {
        // Two consecutive 3xx's: after the first hop the fetcher
        // has burned its `redirects_remaining`, so the second hop
        // MUST produce `RedirectRejected`.
        let server = MockServer::start().await;
        let hop_a = format!("{}/a", server.uri());
        let hop_b = format!("{}/b", server.uri());
        let hop_c = format!("{}/c", server.uri());
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", &hop_b))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", &hop_c))
            .mount(&server)
            .await;

        let fetcher = ReqwestFetcher::new(test_config(&server.uri())).unwrap();
        let ctx = FetchContext::new(DEFAULT_HTTP_FETCH_LIMIT);
        let err = fetcher
            .fetch_raw(&hop_a.parse().unwrap(), &ctx)
            .await
            .expect_err("two-hop redirect chain must be rejected");
        assert!(
            matches!(err, Error::RedirectRejected { .. }),
            "expected RedirectRejected, got: {err:?}",
        );
    }
}
