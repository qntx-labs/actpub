//! Exponential-backoff retry policy for federated activity delivery.
//!
//! [`RetryPolicy`] is the value object that decides, given the
//! current attempt number, how long to wait before the next try and
//! whether to give up. The federation runtime quotes Mastodon's
//! observable retry schedule as the baseline ([`RetryPolicy::mastodon`])
//! so that an `actpub-federation`-powered server's outbox behaviour
//! looks identical to one Sidekiq-driven Mastodon instance from a
//! receiving peer's perspective.
//!
//! The policy is **pure** — it performs no IO, holds no state, and
//! does not own the queue. The retry queue itself (which combines
//! [`RetryPolicy`] with a [`Deliverer`](crate::Deliverer) and a
//! tokio scheduler) lives in the [`outbox`](crate::outbox) module
//! introduced in a later step.

use std::time::Duration;

/// Exponential-backoff retry schedule.
///
/// All four fields participate in the schedule:
///
/// - [`initial_delay`](Self::initial_delay) is the wait before the
///   **second** attempt (i.e. before the **first** retry); the very
///   first attempt fires immediately.
/// - [`multiplier`](Self::multiplier) is applied between consecutive
///   waits, so attempt _n_ waits `initial_delay * multiplier^(n-1)`
///   capped at [`max_delay`](Self::max_delay).
/// - [`max_retries`](Self::max_retries) bounds the total number of
///   retries (i.e. `attempt = max_retries` is the last try).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Wait before the first retry. The very first attempt is
    /// always immediate.
    pub initial_delay: Duration,

    /// Maximum wait between attempts. Caps the otherwise unbounded
    /// exponential growth so a single failed delivery cannot
    /// monopolise the queue indefinitely.
    pub max_delay: Duration,

    /// Multiplier applied between consecutive waits. Mastodon uses
    /// `≈ 2.0` (Sidekiq's default), which doubles the delay every
    /// retry until the cap.
    pub multiplier: f64,

    /// Maximum number of retries (so total attempts =
    /// `max_retries + 1`). Mastodon retries 25 times over ~21 days;
    /// we default to 11 (~2½ days) which is plenty for transient
    /// peer outages without overwhelming queue storage.
    pub max_retries: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::mastodon()
    }
}

impl RetryPolicy {
    /// The Mastodon-compatible default schedule:
    /// 5min initial, ×2 backoff, 60h cap, 11 retries.
    ///
    /// This produces the wait sequence
    /// `5m → 10m → 20m → 40m → 80m → 160m → 320m → 640m (cap 60h)`,
    /// totalling roughly 2½ days before giving up. It matches what a
    /// receiving peer would observe from a vanilla Mastodon outbox
    /// well enough that a misbehaving peer cannot distinguish our
    /// retry curve from theirs.
    #[must_use]
    pub const fn mastodon() -> Self {
        Self {
            initial_delay: Duration::from_mins(5),
            max_delay: Duration::from_hours(60),
            multiplier: 2.0,
            max_retries: 11,
        }
    }

    /// A short-fused profile suited to integration tests where waiting
    /// minutes between attempts is impractical: 10ms initial, ×2,
    /// 100ms cap, 3 retries.
    #[must_use]
    pub const fn for_tests() -> Self {
        Self {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            multiplier: 2.0,
            max_retries: 3,
        }
    }

    /// Returns the wait before the `attempt`-th retry.
    ///
    /// `attempt` is 1-indexed: `delay_before_retry(1)` is the wait
    /// before the **first** retry (i.e. before the second total
    /// attempt). `delay_before_retry(0)` is defined to be zero so
    /// the helper composes naturally with the first immediate
    /// attempt.
    #[must_use]
    pub fn delay_before_retry(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        // attempt N → multiplier^(N-1)
        let exp = self
            .multiplier
            .powi(i32::try_from(attempt - 1).unwrap_or(i32::MAX));
        let secs = self.initial_delay.as_secs_f64() * exp;
        let capped = secs.min(self.max_delay.as_secs_f64());
        Duration::from_secs_f64(capped.max(0.0))
    }

    /// Returns `true` when the runtime should give up because
    /// `attempt` has reached or exceeded
    /// [`max_retries`](Self::max_retries).
    #[must_use]
    pub const fn is_exhausted(&self, attempt: u32) -> bool {
        attempt >= self.max_retries
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn delay_before_retry_zero_is_immediate() {
        let p = RetryPolicy::mastodon();
        assert_eq!(p.delay_before_retry(0), Duration::ZERO);
    }

    #[test]
    fn delay_before_retry_one_equals_initial_delay() {
        let p = RetryPolicy::mastodon();
        assert_eq!(p.delay_before_retry(1), Duration::from_mins(5));
    }

    #[test]
    fn delay_before_retry_grows_exponentially_until_cap() {
        let p = RetryPolicy::mastodon();
        // 5min, 10min, 20min, 40min — pure exponential under the cap.
        assert_eq!(p.delay_before_retry(1), Duration::from_mins(5));
        assert_eq!(p.delay_before_retry(2), Duration::from_mins(10));
        assert_eq!(p.delay_before_retry(3), Duration::from_mins(20));
        assert_eq!(p.delay_before_retry(4), Duration::from_mins(40));
    }

    #[test]
    fn delay_before_retry_caps_at_max_delay() {
        let p = RetryPolicy::mastodon();
        // After enough retries the curve hits the 60h cap and stays
        // there; attempt 50 must be exactly capped, not overflowed.
        assert_eq!(p.delay_before_retry(50), Duration::from_hours(60));
    }

    #[test]
    fn is_exhausted_fires_at_max_retries_boundary() {
        let p = RetryPolicy::mastodon();
        assert!(!p.is_exhausted(p.max_retries - 1));
        assert!(p.is_exhausted(p.max_retries));
        assert!(p.is_exhausted(p.max_retries + 1));
    }

    #[test]
    fn for_tests_profile_caps_at_100ms_after_a_few_retries() {
        let p = RetryPolicy::for_tests();
        // 10ms × 2 = 20ms (attempt 2), × 2 = 40ms (3), × 2 = 80ms (4),
        // × 2 = 160ms but capped at 100ms.
        assert_eq!(p.delay_before_retry(1), Duration::from_millis(10));
        assert_eq!(p.delay_before_retry(2), Duration::from_millis(20));
        assert_eq!(p.delay_before_retry(3), Duration::from_millis(40));
        assert_eq!(p.delay_before_retry(4), Duration::from_millis(80));
        assert_eq!(p.delay_before_retry(5), Duration::from_millis(100));
        assert_eq!(p.delay_before_retry(50), Duration::from_millis(100));
    }

    #[test]
    fn default_is_mastodon_profile() {
        let d = RetryPolicy::default();
        let m = RetryPolicy::mastodon();
        assert_eq!(d.initial_delay, m.initial_delay);
        assert_eq!(d.max_delay, m.max_delay);
        assert_eq!(d.max_retries, m.max_retries);
    }
}
