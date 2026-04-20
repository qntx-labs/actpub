//! Federation runtime configuration.
//!
//! [`FederationConfig`] is the single value users supply to spin up a
//! federation runtime. It bundles every knob the runtime needs into a
//! single immutable record so that fetchers, deliverers, and inbox
//! pipelines all share a coherent view of policy.
//!
//! The struct is intentionally `#[non_exhaustive]` and built via
//! [`bon::Builder`]: callers describe **what** they want, not **in
//! which order** to set it, and adding new fields in future versions
//! will not be a breaking change.

use std::sync::Arc;
use std::time::Duration;

use actpub_httpsig::SigningKey;
use bon::Builder;
use url::Url;

use crate::policy::UrlPolicy;

/// Default per-request timeout (10 seconds) — generous enough for
/// slow-loris peers, short enough to fit inside Mastodon's 30-second
/// inbox-delivery deadline.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on the response body size (1 MiB).
///
/// Large enough for any real `ActivityPub` object (Mastodon caps at
/// 100 KiB for actors and 1 MiB for activities), small enough to
/// bound memory under adversarial load.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// Default in-memory cache size (1024 entries).
pub const DEFAULT_CACHE_CAPACITY: u64 = 1024;

/// Default cache TTL (10 minutes) — short enough that a key rotation
/// reaches verifiers quickly, long enough that a hot inbox does not
/// re-fetch the same actor on every delivery.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);

/// Default user agent header (`actpub-federation/<version>`).
#[must_use] 
pub fn default_user_agent() -> String {
    format!("actpub-federation/{}", env!("CARGO_PKG_VERSION"))
}

/// Immutable, shareable configuration for a federation runtime.
///
/// Constructed via the [`bon`]-derived [`FederationConfig::builder`]
/// associated function and then handed to [`Arc::new`] before being
/// passed to runtime components. The builder enforces that
/// [`signing_key`](Self::signing_key) and [`key_id`](Self::key_id)
/// are always supplied, since both are mandatory for outbound
/// signing and inbound key resolution.
#[derive(Debug, Builder)]
#[non_exhaustive]
pub struct FederationConfig {
    /// The actor's HTTP-Signature signing key, used by the deliverer
    /// to authenticate outbound POSTs and by the (optional) signed
    /// fetcher to authenticate outbound GETs.
    pub signing_key: SigningKey,

    /// Stable URL identifying [`signing_key`](Self::signing_key) on
    /// the wire. Goes into the `keyId` parameter of every emitted
    /// `Signature:` / `Signature-Input:` header so verifiers can
    /// fetch and check our public key.
    pub key_id: Url,

    /// `User-Agent` header sent on every outbound request. Defaults
    /// to `actpub-federation/<crate version>`.
    #[builder(default = default_user_agent())]
    pub user_agent: String,

    /// Per-request HTTP timeout. Defaults to
    /// [`DEFAULT_REQUEST_TIMEOUT`].
    #[builder(default = DEFAULT_REQUEST_TIMEOUT)]
    pub request_timeout: Duration,

    /// Maximum response body size, in bytes. Defaults to
    /// [`DEFAULT_MAX_RESPONSE_BYTES`]. Responses that exceed this
    /// limit are truncated and the request fails with
    /// [`crate::Error::ResponseTooLarge`].
    #[builder(default = DEFAULT_MAX_RESPONSE_BYTES)]
    pub max_response_bytes: u64,

    /// In-memory fetch-cache capacity (number of entries). Defaults
    /// to [`DEFAULT_CACHE_CAPACITY`]. Set to `0` to disable caching.
    #[builder(default = DEFAULT_CACHE_CAPACITY)]
    pub cache_capacity: u64,

    /// In-memory fetch-cache TTL. Defaults to [`DEFAULT_CACHE_TTL`].
    #[builder(default = DEFAULT_CACHE_TTL)]
    pub cache_ttl: Duration,

    /// URL admission policy. Defaults to [`UrlPolicy::default`]
    /// (HTTPS only, no IP literals, no loopback).
    #[builder(default)]
    pub url_policy: UrlPolicy,

    /// Whether the fetcher signs outgoing GET requests with
    /// [`signing_key`](Self::signing_key) (the Mastodon "authorized
    /// fetch" / "secure mode" feature). `false` by default.
    #[builder(default = false)]
    pub signed_fetch: bool,
}

impl FederationConfig {
    /// Wraps `self` in an [`Arc`] for cheap sharing with runtime
    /// components.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::generate_ed25519()
    }

    #[test]
    fn builder_applies_all_documented_defaults() {
        let cfg = FederationConfig::builder()
            .signing_key(signing_key())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .build();

        assert_eq!(cfg.user_agent, default_user_agent());
        assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(cfg.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(cfg.cache_capacity, DEFAULT_CACHE_CAPACITY);
        assert_eq!(cfg.cache_ttl, DEFAULT_CACHE_TTL);
        assert!(!cfg.signed_fetch, "signed fetch is opt-in");
        assert!(cfg.url_policy.require_https, "default policy is HTTPS-only");
    }

    #[test]
    fn builder_overrides_take_effect() {
        let cfg = FederationConfig::builder()
            .signing_key(signing_key())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .user_agent("MyServer/1.0".to_owned())
            .request_timeout(Duration::from_secs(30))
            .max_response_bytes(2 << 20)
            .cache_capacity(256)
            .cache_ttl(Duration::from_secs(60))
            .signed_fetch(true)
            .build();

        assert_eq!(cfg.user_agent, "MyServer/1.0");
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_response_bytes, 2 << 20);
        assert_eq!(cfg.cache_capacity, 256);
        assert_eq!(cfg.cache_ttl, Duration::from_secs(60));
        assert!(cfg.signed_fetch);
    }

    #[test]
    fn shared_returns_an_arc_pointing_at_the_same_config() {
        let cfg = FederationConfig::builder()
            .signing_key(signing_key())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .build();
        let key_id_str = cfg.key_id.to_string();
        let arc = cfg.shared();
        assert_eq!(arc.key_id.to_string(), key_id_str);
    }

    #[test]
    fn url_policy_can_be_overridden_with_a_test_profile() {
        let cfg = FederationConfig::builder()
            .signing_key(signing_key())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .build();
        assert!(!cfg.url_policy.require_https);
    }
}
