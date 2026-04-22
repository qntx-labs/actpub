//! Error types for [`actpub-nodeinfo`](crate).

use thiserror::Error;

/// All failure modes for this crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// The requested schema version was not advertised by the server.
    #[error("requested NodeInfo version {requested} not advertised by server")]
    VersionNotAdvertised {
        /// The requested version.
        requested: &'static str,
    },

    /// An HTTP transport error.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The server responded with a non-success status.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("NodeInfo server returned status {0}")]
    BadStatus(u16),

    /// The response body exceeded the configured maximum size. Raised
    /// only by the client helpers, which cap incoming bodies to a
    /// generous default (see
    /// [`DEFAULT_MAX_BODY_BYTES`](crate::DEFAULT_MAX_BODY_BYTES)).
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("NodeInfo response body exceeds the {0}-byte limit")]
    ResponseTooLarge(u64),

    /// The response body could not be parsed as JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The discovery document advertised a `NodeInfo` document URL
    /// whose origin (scheme + host + port) does not match the
    /// `host` the discovery fetch was directed at.
    ///
    /// This defends against an SSRF pivot where an attacker serves
    /// `/.well-known/nodeinfo` pointing at a cloud-metadata or
    /// loopback URL; [`fetch_with_limit`](crate::fetch_with_limit)
    /// refuses to follow the cross-origin hop before it reaches
    /// the transport.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error(
        "NodeInfo discovery at `{discovery}` advertised a cross-origin href `{href}`; \
         refusing to follow"
    )]
    CrossOriginHref {
        /// The trusted host the discovery document was fetched from.
        discovery: url::Url,
        /// The attacker-controlled href the discovery tried to send us to.
        href: url::Url,
    },
}
