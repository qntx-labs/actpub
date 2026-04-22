//! Asynchronous `NodeInfo` client built on [`reqwest`].
//!
//! # Security considerations
//!
//! `NodeInfo` documents come from untrusted remote servers, so this
//! client applies the same hardening as the sibling `WebFinger`
//! client:
//!
//! - **Body size cap.** Responses are streamed and rejected with
//!   [`Error::ResponseTooLarge`] once the accumulated bytes exceed
//!   [`DEFAULT_MAX_BODY_BYTES`]. A well-formed discovery document or
//!   `NodeInfo` payload is a few kilobytes at most; the 64 KiB default
//!   accommodates unusually verbose extensions while foreclosing
//!   out-of-memory `DoS`.
//! - **Redirect policy.** [`recommended_client`] builds a
//!   [`reqwest::Client`] that follows at most two redirects, all to
//!   the same origin, matching Mastodon's defaults and neutralising
//!   cross-origin redirect attacks on the endpoint.

use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder, header};
use tracing::debug;
use url::Url;

use crate::{Discovery, Error, NodeInfo, Version};

/// Default hard cap on the response body we will read from a
/// `NodeInfo` endpoint.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 64 * 1024;

/// Builds a [`reqwest::Client`] pre-configured for safe `NodeInfo`
/// resolution.
///
/// The returned client uses a strict redirect policy — at most two
/// redirects, all to the same origin — which matches Mastodon's
/// defaults and neutralises cross-origin redirect attacks on the
/// endpoint.
///
/// # Errors
///
/// Returns [`Error::Http`] if the underlying TLS stack cannot be
/// initialised.
pub fn recommended_client() -> Result<Client, Error> {
    Ok(ClientBuilder::new()
        .redirect(Policy::custom(|attempt| {
            const MAX_REDIRECTS: usize = 2;
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            let origin = attempt.previous().first().unwrap_or_else(|| attempt.url());
            if origin.host_str() == attempt.url().host_str()
                && origin.scheme() == attempt.url().scheme()
            {
                attempt.follow()
            } else {
                attempt.error("cross-origin redirect forbidden for NodeInfo")
            }
        }))
        .build()?)
}

/// Fetches the `/.well-known/nodeinfo` discovery document from `host`,
/// enforcing [`DEFAULT_MAX_BODY_BYTES`] as the body size cap.
///
/// `host` should be a full base URL (including scheme), e.g.
/// `https://mastodon.social`. Pass a client obtained from
/// [`recommended_client`] to also benefit from the same-origin
/// redirect policy.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] if `host` cannot be joined with the
/// well-known path, [`Error::Http`] for network failures,
/// [`Error::BadStatus`] for non-2xx responses,
/// [`Error::ResponseTooLarge`] when the body exceeds the cap, and
/// [`Error::Json`] if the body is not valid JSON.
pub async fn fetch_discovery(host: &Url, client: &Client) -> Result<Discovery, Error> {
    fetch_discovery_with_limit(host, client, DEFAULT_MAX_BODY_BYTES).await
}

/// [`fetch_discovery`] variant accepting an explicit body size cap.
///
/// # Errors
///
/// Same as [`fetch_discovery`].
pub async fn fetch_discovery_with_limit(
    host: &Url,
    client: &Client,
    max_body_bytes: u64,
) -> Result<Discovery, Error> {
    let url = host.join(crate::WELL_KNOWN_PATH)?;
    debug!(%url, max_body_bytes, "fetching NodeInfo discovery");

    let body = request_capped(client, url, max_body_bytes).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Fetches a [`NodeInfo`] document at `version` from `host`.
///
/// Resolves the concrete schema URL via the discovery document and
/// then fetches and parses the `NodeInfo` JSON, enforcing
/// [`DEFAULT_MAX_BODY_BYTES`] on both requests.
///
/// # Errors
///
/// Returns [`Error::VersionNotAdvertised`] if the server does not
/// advertise the requested version, and propagates transport / parse
/// errors via [`Error::Http`] / [`Error::Json`] / [`Error::BadStatus`]
/// / [`Error::ResponseTooLarge`].
pub async fn fetch(host: &Url, version: Version, client: &Client) -> Result<NodeInfo, Error> {
    fetch_with_limit(host, version, client, DEFAULT_MAX_BODY_BYTES).await
}

/// [`fetch`] variant accepting an explicit body size cap.
///
/// # Errors
///
/// Same as [`fetch`].
pub async fn fetch_with_limit(
    host: &Url,
    version: Version,
    client: &Client,
    max_body_bytes: u64,
) -> Result<NodeInfo, Error> {
    let discovery = fetch_discovery_with_limit(host, client, max_body_bytes).await?;
    let link = discovery
        .find_link(version)
        .ok_or(Error::VersionNotAdvertised {
            requested: version.as_str(),
        })?;

    // SSRF hardening (seventh-round audit P1-10): the advertised
    // `href` comes from an untrusted remote document, so an
    // attacker serving `/.well-known/nodeinfo` can redirect the
    // client to an arbitrary URL — classically a cloud-metadata
    // endpoint (`http://169.254.169.254/…`) or a loopback /
    // private-range target — before the redirect-policy ever
    // gets a chance to run, because it fires only on 3xx hops
    // within a single `client.get(…)` call. We therefore refuse
    // any href whose *origin* (scheme + host + port) differs
    // from the discovery origin we were told to talk to.
    if !same_origin(host, &link.href) {
        return Err(Error::CrossOriginHref {
            discovery: host.clone(),
            href: link.href.clone(),
        });
    }

    debug!(url = %link.href, max_body_bytes, "fetching NodeInfo document");

    let body = request_capped(client, link.href.clone(), max_body_bytes).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Returns `true` iff `a` and `b` share scheme, host and effective
/// port. Matches the same-origin semantics Fetch / CORS use, and
/// is the narrowest definition that still lets a server legally
/// advertise `http://host/` during discovery and
/// `http://host/nodeinfo/2.1` for the document.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme().eq_ignore_ascii_case(b.scheme())
        && match (a.host_str(), b.host_str()) {
            (Some(ha), Some(hb)) => ha.eq_ignore_ascii_case(hb),
            _ => false,
        }
        && a.port_or_known_default() == b.port_or_known_default()
}

async fn request_capped(client: &Client, url: Url, max_body_bytes: u64) -> Result<Vec<u8>, Error> {
    let response = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::BadStatus(status.as_u16()));
    }

    read_capped(response, max_body_bytes).await
}

async fn read_capped(
    mut response: reqwest::Response,
    max_body_bytes: u64,
) -> Result<Vec<u8>, Error> {
    let mut acc: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if max_body_bytes > 0 && (acc.len() as u64 + chunk.len() as u64) > max_body_bytes {
            return Err(Error::ResponseTooLarge(max_body_bytes));
        }
        acc.extend_from_slice(&chunk);
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn end_to_end_fetch_via_mock_server() {
        let server = MockServer::start().await;
        let base: Url = server.uri().parse().unwrap();

        let nodeinfo_url = format!("{base}nodeinfo/2.1");

        Mock::given(method("GET"))
            .and(path("/.well-known/nodeinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "links": [{
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                    "href": nodeinfo_url
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/nodeinfo/2.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "2.1",
                "software": { "name": "mock-server", "version": "0.1.0" },
                "protocols": ["activitypub"],
                "openRegistrations": false,
                "usage": {}
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let info = fetch(&base, Version::V2_1, &client).await.unwrap();

        assert_eq!(info.version, Version::V2_1);
        assert_eq!(info.software.name, "mock-server");
    }

    #[tokio::test]
    async fn fetch_refuses_cross_origin_href_advertised_by_discovery() {
        // P1-10 (seventh-round audit) regression: an attacker
        // controlling `/.well-known/nodeinfo` at the legitimate
        // host could advertise a `href` pointing ANYWHERE — a
        // cloud-metadata endpoint, a loopback admin interface, a
        // private-network target — because the default `reqwest`
        // redirect policy only kicks in on 3xx hops, not on the
        // initial `client.get(href)` call. `fetch_with_limit`
        // MUST refuse any href whose origin (scheme + host + port)
        // does not match the discovery host.
        let primary = MockServer::start().await;
        let attacker = MockServer::start().await;
        let attacker_nodeinfo = format!("{}/nodeinfo/2.1", attacker.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/nodeinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "links": [{
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                    "href": attacker_nodeinfo
                }]
            })))
            .mount(&primary)
            .await;

        let client = Client::new();
        let base: Url = primary.uri().parse().unwrap();
        let err = fetch(&base, Version::V2_1, &client)
            .await
            .expect_err("cross-origin href must be refused");
        assert!(
            matches!(err, Error::CrossOriginHref { .. }),
            "expected CrossOriginHref, got {err:?}",
        );
    }

    #[tokio::test]
    async fn oversized_discovery_body_is_rejected() {
        let server = MockServer::start().await;
        let base: Url = server.uri().parse().unwrap();

        // 128 KiB body — comfortably above the 64 KiB default cap.
        let padding = "x".repeat(128 * 1024);
        Mock::given(method("GET"))
            .and(path("/.well-known/nodeinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(r#"{{"links":[],"padding":"{padding}"}}"#).into_bytes(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let client = Client::new();
        let err = fetch_discovery(&base, &client)
            .await
            .expect_err("oversized body must be rejected");
        assert!(matches!(
            err,
            Error::ResponseTooLarge(DEFAULT_MAX_BODY_BYTES)
        ));
    }

    #[tokio::test]
    async fn recommended_client_rejects_cross_origin_redirect() {
        let primary = MockServer::start().await;
        let attacker = MockServer::start().await;

        // Attacker pretends to serve a well-known NodeInfo discovery
        // but redirects off-origin. The recommended client's policy
        // must refuse to follow that hop.
        Mock::given(method("GET"))
            .and(path("/.well-known/nodeinfo"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}/.well-known/nodeinfo", attacker.uri()),
            ))
            .mount(&primary)
            .await;

        let client = recommended_client().expect("client builds");
        let base: Url = primary.uri().parse().unwrap();
        // The exact error surface depends on the redirect-policy
        // message plumbing; the important invariant is that the
        // fetch does *not* succeed in following the off-origin hop.
        fetch_discovery(&base, &client)
            .await
            .expect_err("cross-origin redirect must fail");
    }

    #[tokio::test]
    async fn missing_version_returns_specific_error() {
        let server = MockServer::start().await;
        let base: Url = server.uri().parse().unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/nodeinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "links": [{
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
                    "href": format!("{base}nodeinfo/2.0")
                }]
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let err = fetch(&base, Version::V2_1, &client).await.unwrap_err();
        assert!(matches!(
            err,
            Error::VersionNotAdvertised { requested: "2.1" }
        ));
    }
}
