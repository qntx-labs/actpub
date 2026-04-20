//! Error types for [`actpub-activitystreams`](crate).

use thiserror::Error;

/// Errors that can arise when parsing or constructing Activity Streams values.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A URL-valued property could not be parsed as a valid URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// A `mediaType` property was not a valid MIME type.
    #[error("invalid media type: {0}")]
    InvalidMediaType(#[from] mime::FromStrError),

    /// An error occurred during JSON (de)serialization.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
