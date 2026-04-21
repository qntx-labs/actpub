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

    /// The signing actor exposed no public key (neither a FEP-521a
    /// `assertionMethod` Multikey nor a legacy `publicKey.publicKeyPem`)
    /// matching the signature's `keyId`.
    #[error("actor has no usable public key: {0}")]
    ActorWithoutKey(String),

    /// The signing actor's identity does not match the key that
    /// signed the request.
    ///
    /// Raised when one of the cross-checks that binds the HTTP
    /// signature to a Fediverse identity fails:
    ///
    /// - the `keyId` host differs from the `actor.id` host returned
    ///   by the fetcher (classic cross-domain impersonation attack),
    /// - a legacy `publicKey.id` is present but does not equal the
    ///   `keyId` actually used to sign the request.
    ///
    /// This variant is the security boundary between "verified the
    /// signature" and "trusted the signer" -- treat it as a 401 / 403
    /// at the HTTP layer.
    #[error("signer identity does not match signing key: {0}")]
    SignerKeyMismatch(String),

    /// The user-supplied [`ActivityHandler`](crate::ActivityHandler)
    /// returned an error.
    #[error("activity handler failed: {0}")]
    HandlerFailed(String),

    /// A federation actor returned by [`Fetcher`](crate::Fetcher)
    /// did not expose an `inbox` (and no `endpoints.sharedInbox`),
    /// so [`Outbox`](crate::Outbox) cannot deliver to it.
    #[error("actor `{0}` has no `inbox` or `sharedInbox` endpoint")]
    ActorWithoutInbox(String),

    /// A single inbox request triggered more recursive HTTP fetches
    /// than [`FederationConfig::http_fetch_limit`](crate::FederationConfig::http_fetch_limit)
    /// allows.
    ///
    /// This is the load-shedding guard for the AP
    /// [Security Considerations §B.5 recursive fetch DoS]
    /// scenario: a malicious peer builds an activity whose `object`
    /// points at another object on a third server, whose `inReplyTo`
    /// points at a fourth, and so on. Without a counter the inbox
    /// handler can be induced to perform an unbounded chain of
    /// signed fetches.
    ///
    /// [Security Considerations §B.5 recursive fetch DoS]: https://www.w3.org/TR/activitypub/#security-recursive
    #[error("recursive fetch limit ({limit}) exceeded for this request")]
    RecursiveFetchLimit {
        /// Configured limit at the moment of failure.
        limit: u32,
    },

    /// The JSON returned by a fetch had an `id` field that did not
    /// match the final response URL (after a single permitted
    /// redirect hop).
    ///
    /// The classic Mastodon `GHSA-jhrq-qvrm-qr36` URL-rebinding
    /// shape: an attacker controlling `victim.example` returns
    /// `{"id": "https://attacker.example/u/me"}` so that a credulous
    /// consumer caches the attacker's document under the victim's
    /// URL. This variant is raised when that mismatch cannot be
    /// resolved by a same-domain re-fetch.
    #[error("response from `{url}` declared id `{id}` (cross-domain mismatch)")]
    FetchIdMismatch {
        /// Wire URL the response was fetched from.
        url: Url,
        /// The `id` field the response itself declared.
        id: Url,
    },

    /// An HTTP 3xx response's `Location` pointed at a URL that the
    /// configured [`UrlPolicy`](crate::UrlPolicy) rejected, or the
    /// response chained more redirects than the runtime is willing
    /// to follow (exactly one, per
    /// [ActivityPub §B.5](https://www.w3.org/TR/activitypub/#security-considerations)).
    #[error("redirect from `{from}` to `{to}` was rejected: {reason}")]
    RedirectRejected {
        /// URL that produced the redirect.
        from: Url,
        /// Target URL named by the `Location` header.
        to: String,
        /// Human-readable explanation.
        reason: String,
    },

    /// The [`Outbox`](crate::Outbox) worker has been shut down and
    /// the delivery channel is closed, so a delivery job could not
    /// be enqueued.
    ///
    /// Surfaced by [`Outbox::dispatch`](crate::Outbox::dispatch) when
    /// `dispatch` races a concurrent
    /// [`Outbox::graceful_shutdown`](crate::Outbox::graceful_shutdown)
    /// — e.g. a SIGTERM handler that fires while a large fan-out is
    /// mid-flight. Previously this condition was silently logged and
    /// the [`DispatchReport`](crate::DispatchReport) falsely claimed
    /// every recipient had been enqueued; callers now receive one
    /// `OutboxShutdown` entry per undelivered recipient so they can
    /// persist, retry, or report accurately.
    #[error("outbox worker is shutting down; delivery to `{inbox}` was not enqueued")]
    OutboxShutdown {
        /// Inbox URL whose delivery job was rejected.
        inbox: Url,
    },
}
