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

use actpub_httpsig::{SigningKey, VerifyPolicy};
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

/// Default actor-fetch cache size (1024 entries).
///
/// Sized for the working-set of one Fediverse instance's
/// `assertionMethod` and profile fetches; the inbox-dedup cache is
/// sized separately by [`DEFAULT_DEDUP_CAPACITY`] because it serves
/// a different purpose and needs a much larger window.
pub const DEFAULT_CACHE_CAPACITY: u64 = 1024;

/// Default actor-fetch cache TTL (10 minutes) — short enough that a
/// key rotation reaches verifiers quickly, long enough that a hot
/// inbox does not re-fetch the same actor on every delivery.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_mins(10);

/// Default inbox-dedup cache size (100 000 entries).
///
/// The dedup cache is a **replay-protection** structure, not a
/// fetch cache: each entry is one inbox POST the pipeline has
/// already accepted, kept so a verbatim resend is dropped as a
/// duplicate. Sized for a Mastodon-class instance receiving
/// O(100) posts/sec — a 10-minute rolling window of activity fits
/// in ~60 000 entries, so 100 000 leaves comfortable headroom
/// before the LRU starts evicting entries the 12 h freshness
/// window still considers replayable.
pub const DEFAULT_DEDUP_CAPACITY: u64 = 100_000;

/// Default inbox-dedup cache TTL (1 hour).
///
/// Must be **at least** as large as the
/// [`VerifyPolicy`](actpub_httpsig::VerifyPolicy) `max_age`
/// window: a dedup entry older than `max_age` is irrelevant
/// because the signature-freshness gate would reject the
/// replayed request anyway. One hour is a conservative middle
/// ground between CPU cost and memory pressure.
pub const DEFAULT_DEDUP_TTL: Duration = Duration::from_hours(1);

/// Default cap on the number of recursive HTTP fetches a single
/// inbox request or activity resolution is allowed to trigger.
///
/// Mirrors Lemmy's `activitypub-federation` default and the rough
/// upper bound under which every mainstream Fediverse object graph
/// can be traversed without giving up `ActivityPub` Security
/// Considerations §B.5 `DoS` protection.
pub const DEFAULT_HTTP_FETCH_LIMIT: u32 = 20;

/// Default ceiling on the number of in-flight deliveries the
/// [`Outbox`](crate::Outbox) worker tolerates concurrently.
///
/// Prevents a `Create` addressed to tens of thousands of followers
/// from pinning tens of thousands of TCP sockets and reqwest
/// connection slots. Tune up on servers with abundant FDs and
/// network bandwidth, tune down on constrained deployments.
pub const DEFAULT_DELIVERY_CONCURRENCY: usize = 100;

/// Default capacity of the outbox's delivery channel.
///
/// Jobs accepted by [`Outbox::enqueue`](crate::Outbox::enqueue)
/// queue here until the worker picks them up. The channel is
/// **bounded**: once full, `enqueue` awaits a slot to open before
/// returning, propagating backpressure all the way to the caller
/// instead of letting a misbehaving producer grow the queue
/// unbounded. Sized for a Mastodon-class outbox: 10 000 jobs is
/// ~100 MB of activity clones at ~10 KB each, a memory budget
/// every moderately-funded deployment can accept.
pub const DEFAULT_DELIVERY_QUEUE_CAPACITY: usize = 10_000;

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
///
/// The struct implements a hand-written [`Debug`] impl that renders
/// `signing_key` as `"[redacted]"` rather than deferring to the
/// underlying type's [`Debug`]; this keeps a log line or panic
/// message from accidentally leaking the private-key material even
/// if a downstream [`SigningKey`] implementation regresses to a
/// verbose [`Debug`].
#[derive(Builder)]
#[non_exhaustive]
pub struct FederationConfig {
    /// The actor's HTTP-Signature signing key, used by the deliverer
    /// to authenticate outbound POSTs and by the (optional) signed
    /// fetcher to authenticate outbound GETs.
    ///
    /// Deliberately `pub(crate)` so downstream code cannot read the
    /// private key out of the configuration (e.g. to PEM-export it or
    /// log it by accident). The runtime components that need it —
    /// [`ReqwestFetcher`](crate::ReqwestFetcher) and
    /// [`ReqwestDeliverer`](crate::ReqwestDeliverer) — access it
    /// through [`Self::signing_key_ref`].
    pub(crate) signing_key: SigningKey,

    /// Stable URL identifying [`Self::signing_key_ref`] on the wire.
    /// Goes into the `keyId` parameter of every emitted `Signature:` /
    /// `Signature-Input:` header so verifiers can fetch and check our
    /// public key.
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

    /// In-memory actor-fetch cache capacity (number of entries).
    /// Defaults to [`DEFAULT_CACHE_CAPACITY`]. Set to `0` to disable
    /// caching. This is the cache the [`Fetcher`](crate::Fetcher)
    /// uses to amortise successive dereferences of the same URL; it
    /// is **not** the inbox-replay dedup cache (see
    /// [`Self::dedup_capacity`]).
    #[builder(default = DEFAULT_CACHE_CAPACITY)]
    pub cache_capacity: u64,

    /// In-memory actor-fetch cache TTL. Defaults to
    /// [`DEFAULT_CACHE_TTL`]. Bounds how long stale actor JSON is
    /// allowed to survive key-rotation events.
    #[builder(default = DEFAULT_CACHE_TTL)]
    pub cache_ttl: Duration,

    /// Inbox-replay dedup cache capacity (number of entries).
    /// Defaults to [`DEFAULT_DEDUP_CAPACITY`]. One entry per
    /// accepted inbox POST; sized for a Mastodon-class instance.
    /// Eviction here is a **security** event — an activity evicted
    /// before [`VerifyPolicy::max_age`](actpub_httpsig::VerifyPolicy)
    /// passes becomes replayable — so tune up, not down, for
    /// high-traffic deployments.
    #[builder(default = DEFAULT_DEDUP_CAPACITY)]
    pub dedup_capacity: u64,

    /// Inbox-replay dedup cache TTL. Defaults to
    /// [`DEFAULT_DEDUP_TTL`]. Should be at least as long as
    /// [`Self::verify_policy`]'s `max_age`, otherwise a captured
    /// POST can be replayed once the dedup entry expires even
    /// though the freshness window is still open.
    #[builder(default = DEFAULT_DEDUP_TTL)]
    pub dedup_ttl: Duration,

    /// URL admission policy. Defaults to [`UrlPolicy::default`]
    /// (HTTPS only, no IP literals, no loopback).
    #[builder(default)]
    pub url_policy: UrlPolicy,

    /// Whether the fetcher signs outgoing GET requests with
    /// [`signing_key`](Self::signing_key) (the Mastodon "authorized
    /// fetch" / "secure mode" feature). `false` by default.
    #[builder(default = false)]
    pub signed_fetch: bool,

    /// Maximum number of recursive HTTP fetches a single inbox
    /// request or activity resolution is allowed to trigger.
    /// Defaults to [`DEFAULT_HTTP_FETCH_LIMIT`]. Set to `0` to
    /// forbid **any** outbound fetch for the scope sharing the
    /// counter (primarily useful in tests).
    #[builder(default = DEFAULT_HTTP_FETCH_LIMIT)]
    pub http_fetch_limit: u32,

    /// Upper bound on the number of concurrent deliveries the
    /// [`Outbox`](crate::Outbox) worker is permitted to run. The
    /// retry queue serialises delivery dispatches through a
    /// [`tokio::sync::Semaphore`] sized by this value, so a fan-out
    /// to thousands of inboxes cannot instantly saturate the
    /// socket, FD and memory budget of the process. Defaults to
    /// [`DEFAULT_DELIVERY_CONCURRENCY`].
    #[builder(default = DEFAULT_DELIVERY_CONCURRENCY)]
    pub delivery_concurrency: usize,

    /// Capacity of the [`Outbox`](crate::Outbox) job channel.
    /// Defaults to [`DEFAULT_DELIVERY_QUEUE_CAPACITY`].
    /// Once the channel is full, [`Outbox::enqueue`](crate::Outbox::enqueue)
    /// **awaits** a slot to open, applying backpressure to the
    /// caller — a misbehaving producer cannot grow the queue
    /// unbounded. Retry jobs reuse the same channel, so under a
    /// storm of transient failures the queue can approach capacity
    /// even without external fan-in; tune up for bursty workloads.
    #[builder(default = DEFAULT_DELIVERY_QUEUE_CAPACITY)]
    pub delivery_queue_capacity: usize,

    /// Freshness / replay-protection policy applied to every inbound
    /// HTTP signature by [`InboxPipeline`](crate::InboxPipeline).
    ///
    /// Defaults to [`VerifyPolicy::mastodon`] — the 12 h past / 5 min
    /// future skew window, with the Cavage and RFC 9421 minimum
    /// covered-component sets enforced. Override with
    /// [`VerifyPolicy::strict`] for internal deployments with
    /// NTP-synchronised clocks, or build a custom `VerifyPolicy`
    /// directly for unusual interop requirements.
    ///
    /// **Do not** use [`VerifyPolicy::no_freshness_check`] in
    /// production: it disables every anti-replay gate this crate
    /// ships with.
    #[builder(default = VerifyPolicy::mastodon())]
    pub verify_policy: VerifyPolicy,
}

impl FederationConfig {
    /// Wraps `self` in an [`Arc`] for cheap sharing with runtime
    /// components.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Crate-internal accessor for [`Self::signing_key`]. Kept
    /// private to the crate so application code cannot pull the
    /// secret out of the config; the runtime's signing call-sites
    /// (deliverer, signed fetcher) use this to reach the key.
    /// NOT `const fn`: `SigningKey` cannot be constructed in a
    /// const context, so declaring this `const` is misleading
    /// without conferring any benefit.
    #[must_use]
    pub(crate) const fn signing_key_ref(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl std::fmt::Debug for FederationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `signing_key` is redacted unconditionally so a future
        // change to `SigningKey`'s own `Debug` cannot regress into
        // leaking key material from a panic, log, or `dbg!`.
        f.debug_struct("FederationConfig")
            .field("signing_key", &"[redacted]")
            .field("key_id", &self.key_id)
            .field("user_agent", &self.user_agent)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("cache_capacity", &self.cache_capacity)
            .field("cache_ttl", &self.cache_ttl)
            .field("dedup_capacity", &self.dedup_capacity)
            .field("dedup_ttl", &self.dedup_ttl)
            .field("url_policy", &self.url_policy)
            .field("signed_fetch", &self.signed_fetch)
            .field("http_fetch_limit", &self.http_fetch_limit)
            .field("delivery_concurrency", &self.delivery_concurrency)
            .field("delivery_queue_capacity", &self.delivery_queue_capacity)
            .field("verify_policy", &self.verify_policy)
            .finish()
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
            .cache_ttl(Duration::from_mins(1))
            .signed_fetch(true)
            .build();

        assert_eq!(cfg.user_agent, "MyServer/1.0");
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_response_bytes, 2 << 20);
        assert_eq!(cfg.cache_capacity, 256);
        assert_eq!(cfg.cache_ttl, Duration::from_mins(1));
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

    #[test]
    fn debug_impl_redacts_signing_key() {
        // P2-N13 regression: even if the underlying `SigningKey`
        // type ships a verbose `Debug` that leaks key material, the
        // hand-written `Debug for FederationConfig` must show the
        // key as `"[redacted]"` so panic / log / `dbg!` output is
        // always safe.
        let cfg = FederationConfig::builder()
            .signing_key(signing_key())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .build();
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("signing_key: \"[redacted]\""),
            "signing_key not redacted in Debug output: {dbg}",
        );
        assert!(
            !dbg.to_lowercase().contains("ed25519"),
            "Debug output must not leak the key algorithm: {dbg}",
        );
    }
}
