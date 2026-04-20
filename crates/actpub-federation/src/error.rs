//! Crate-wide error type for [`actpub-federation`](crate).
//!
//! Errors flow up from every fallible runtime API: fetching, delivery,
//! signature verification, URL policy enforcement, JSON parsing.
//! Variants are `#[non_exhaustive]` so adding a new failure mode is
//! not a breaking change.

use thiserror::Error;
use url::Url;

/// Top-level error type for `actpub-federation`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying HTTP client error (DNS, connect, TLS, body, …).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// Server returned a non-2xx HTTP status when fetching or
    /// delivering.
    #[error("server at {url} returned status {status}")]
    Status {
        /// Wire URL that produced the failed status.
        url: Url,
        /// HTTP status code returned.
        status: u16,
    },

    /// JSON deserialisation failed.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP signature creation or verification failed.
    #[error(transparent)]
    HttpSig(#[from] actpub_httpsig::Error),

    /// FEP-8b32 Data Integrity proof creation or verification failed.
    #[error(transparent)]
    Cryptosuite(#[from] actpub_core::Error),

    /// URL was rejected by the configured [`UrlPolicy`](crate::UrlPolicy)
    /// before any IO took place.
    ///
    /// Returned for example when the URL scheme is `http` while the
    /// policy requires `https`, or when the host is on the deny-list.
    #[error("URL `{url}` violates the federation URL policy: {reason}")]
    PolicyViolation {
        /// Wire URL that was rejected.
        url: Url,
        /// Human-readable explanation of which policy rule fired.
        reason: String,
    },

    /// The remote response body exceeded
    /// [`FederationConfig::max_response_bytes`](crate::FederationConfig::max_response_bytes).
    #[error("response from `{url}` exceeded {limit} bytes")]
    ResponseTooLarge {
        /// Wire URL whose response was capped.
        url: Url,
        /// Configured byte limit at the moment of failure.
        limit: u64,
    },

    /// The remote `Content-Type` was not an `ActivityPub`-compatible
    /// JSON / JSON-LD media type.
    #[error("response from `{url}` had unexpected Content-Type `{content_type}`")]
    UnexpectedContentType {
        /// Wire URL whose Content-Type was rejected.
        url: Url,
        /// The offending Content-Type header value.
        content_type: String,
    },

    /// Per-request timeout fired before the response completed.
    #[error("request to `{url}` timed out after {seconds}s")]
    Timeout {
        /// Wire URL whose request timed out.
        url: Url,
        /// Configured timeout in seconds at the moment of failure.
        seconds: u64,
    },

    /// Invalid URL syntax.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
