//! Error types for [`actpub-webfinger`](crate).

use thiserror::Error;

/// All failure modes for [`crate`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The input string was not a valid `acct:` URI.
    #[error("invalid acct URI: {0}")]
    InvalidAcct(String),

    /// A URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// The `WebFinger` response had no subject.
    #[error("WebFinger JRD is missing `subject`")]
    MissingSubject,

    /// The `WebFinger` subject did not match the requested resource.
    #[error("WebFinger subject mismatch: requested {requested}, got {returned}")]
    SubjectMismatch {
        /// The resource URI that was requested.
        requested: String,
        /// The resource URI returned by the server.
        returned: String,
    },

    /// The `WebFinger` response did not include an `ActivityPub` actor link.
    #[error("WebFinger JRD does not reference an ActivityPub actor")]
    MissingActorLink,

    /// An HTTP transport error during client resolution.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The server responded with a non-success status.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("WebFinger server returned status {0}")]
    BadStatus(u16),

    /// The server's response body exceeded the configured body cap
    /// before it could be fully read.
    ///
    /// This is a `DoS` guard: a malicious or compromised `WebFinger`
    /// responder could otherwise stream gigabytes of JSON into the
    /// client and exhaust memory.
    #[cfg(feature = "client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    #[error("WebFinger response exceeded {0} bytes")]
    ResponseTooLarge(u64),

    /// The response body could not be parsed as JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
