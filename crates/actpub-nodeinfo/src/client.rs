//! Asynchronous `NodeInfo` client built on [`reqwest`].

use reqwest::{Client, header};
use tracing::debug;
use url::Url;

use crate::{Discovery, Error, NodeInfo, Version};

/// Fetches the `/.well-known/nodeinfo` discovery document from `host`.
///
/// `host` should be a full base URL (including scheme), e.g.
/// `https://mastodon.social`.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] if `host` cannot be joined with the
/// well-known path, [`Error::Http`] for network failures, and
/// [`Error::BadStatus`] / [`Error::Json`] for invalid responses.
pub async fn fetch_discovery(host: &Url, client: &Client) -> Result<Discovery, Error> {
    let url = host.join(crate::WELL_KNOWN_PATH)?;
    debug!(%url, "fetching NodeInfo discovery");

    let response = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::BadStatus(status.as_u16()));
    }

    Ok(response.json::<Discovery>().await?)
}

/// Fetches a [`NodeInfo`] document at `version` from `host`.
///
/// Resolves the concrete schema URL via the discovery document and then
/// fetches and parses the `NodeInfo` JSON.
///
/// # Errors
///
/// Returns [`Error::VersionNotAdvertised`] if the server does not advertise
/// the requested version, and propagates transport / parse errors via
/// [`Error::Http`] / [`Error::Json`] / [`Error::BadStatus`].
pub async fn fetch(host: &Url, version: Version, client: &Client) -> Result<NodeInfo, Error> {
    let discovery = fetch_discovery(host, client).await?;
    let link = discovery
        .find_link(version)
        .ok_or(Error::VersionNotAdvertised {
            requested: version.as_str(),
        })?;

    debug!(url = %link.href, "fetching NodeInfo document");

    let response = client
        .get(link.href.clone())
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::BadStatus(status.as_u16()));
    }

    Ok(response.json::<NodeInfo>().await?)
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
