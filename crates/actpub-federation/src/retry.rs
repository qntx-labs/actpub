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
//! The policy is **almost pure**: it performs no IO and owns no
//! queue state, but [`delay_before_retry`](RetryPolicy::delay_before_retry)
//! does read from the thread-local RNG when
//! [`jitter_fraction`](RetryPolicy::jitter_fraction) is non-zero,
//! so it is not `const fn` and is not repeatable for the same
//! input. The retry queue itself (which combines [`RetryPolicy`]
//! with a [`Deliverer`](crate::Deliverer) and a tokio scheduler)
//! lives in the [`outbox`](crate::outbox) module.

use std::time::Duration;

use rand::RngExt;

/// Exponential-backoff retry schedule with optional jitter.
///
/// Fields and their role in the schedule:
///
/// - [`initial_delay`](Self::initial_delay) is the wait before the
///   **second** attempt (i.e. before the **first** retry); the very
///   first attempt fires immediately.
/// - [`multiplier`](Self::multiplier) is applied between consecutive
///   waits, so attempt _n_ waits `initial_delay * multiplier^(n-1)`
///   capped at [`max_delay`](Self::max_delay).
/// - [`max_retries`](Self::max_retries) bounds the total number of
///   retries (i.e. `attempt = max_retries` is the last try).
/// - [`jitter_fraction`](Self::jitter_fraction) spreads synchronised
///   fan-out retries across a window so the peer is not
///   thundering-herded on each back-off boundary.
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
    /// `max_retries + 1`).
    ///
    /// The default [`Self::mastodon`] profile sets this to `11`
    /// (~2½ days of exponential back-off before giving up), which
    /// is a **conservative subset** of vanilla Mastodon's own
    /// schedule (25 retries spread over ~21 days). See
    /// [`Self::mastodon`] for the asymmetric-reliability caveat
    /// this choice implies and guidance on when to override.
    pub max_retries: u32,

    /// Fraction of each back-off to scatter uniformly around the
    /// deterministic exponential target, in `[0.0, 1.0]`.
    ///
    /// At `0.0` the schedule is perfectly deterministic: every
    /// [`run_one`](crate::outbox) backing off `attempt=N` sleeps exactly
    /// `initial_delay * multiplier^(N-1)`. When a single outbox
    /// fan-outs to N followers on the same remote instance (common
    /// for a popular actor broadcasting a Create activity) those N
    /// deliveries are all started within milliseconds of each
    /// other, so a deterministic schedule synchronises their
    /// retries: the remote instance sees a burst of N simultaneous
    /// POSTs every back-off boundary — the
    /// [thundering-herd pattern].
    ///
    /// A positive `jitter_fraction` `j` multiplies the
    /// deterministic target by a uniform random factor in
    /// `[1-j, 1+j]`, so N synchronised retries spread out over a
    /// `2·j·base` window. Mastodon's Sidekiq default is roughly
    /// `0.33` (±33 % jitter per attempt); we default to `0.1`,
    /// which breaks up fan-out synchronisation meaningfully while
    /// staying well inside the next back-off bucket.
    ///
    /// Values outside `[0.0, 1.0]` are clamped to that range.
    ///
    /// [thundering-herd pattern]: https://en.wikipedia.org/wiki/Thundering_herd_problem
    pub jitter_fraction: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::mastodon()
    }
}

impl RetryPolicy {
    /// A conservative **subset** of Mastodon's retry profile:
    /// 5 min initial, ×2 backoff, 60 h cap, 11 retries,
    /// ±10 % jitter.
    ///
    /// The deterministic curve produces the wait sequence
    /// `5 m → 10 m → 20 m → 40 m → 80 m → 160 m → 320 m → 640 m (cap 60 h)`,
    /// totalling roughly **2½ days** before giving up.
    ///
    /// # Relationship to vanilla Mastodon
    ///
    /// Mastodon itself retries **25** times over **~21 days** via
    /// Sidekiq. This profile trades that long tail for bounded
    /// queue storage — a misbehaving peer's undelivered activities
    /// do not pile up on disk for three weeks. The exponential
    /// curve is otherwise identical, so a well-behaved peer cannot
    /// distinguish our back-off shape from Mastodon's in the first
    /// ~2½ days.
    ///
    /// # Asymmetric-reliability caveat
    ///
    /// A peer running vanilla Mastodon will keep retrying to us
    /// for ~21 days while this profile gives up at day 2½, so a
    /// network partition lasting 3–21 days produces **silently
    /// non-symmetric** delivery: Mastodon → us eventually succeeds,
    /// us → Mastodon has already been abandoned. Deployments that
    /// can afford the extra queue state and want full parity
    /// should override `max_retries = 25`.
    ///
    /// # Jitter
    ///
    /// Jitter defaults to `0.1` (±10 % of the deterministic
    /// target). This breaks up thundering-herd retries on
    /// fan-outs to popular remote instances without widening the
    /// tail beyond the next back-off bucket. See
    /// [`Self::jitter_fraction`] for the rationale.
    #[must_use]
    pub const fn mastodon() -> Self {
        Self {
            initial_delay: Duration::from_mins(5),
            max_delay: Duration::from_hours(60),
            multiplier: 2.0,
            max_retries: 11,
            jitter_fraction: 0.1,
        }
    }

    /// A short-fused profile suited to integration tests where
    /// waiting minutes between attempts is impractical: 10 ms
    /// initial, ×2, 100 ms cap, 3 retries, **no jitter**.
    ///
    /// Jitter is disabled so tests that assert on the exact
    /// delivery schedule remain deterministic. Tests that
    /// specifically exercise the jitter path can construct a
    /// custom [`RetryPolicy`] with `jitter_fraction > 0`.
    #[must_use]
    pub const fn for_tests() -> Self {
        Self {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            multiplier: 2.0,
            max_retries: 3,
            jitter_fraction: 0.0,
        }
    }

    /// Returns the wait to observe before attempting retry
    /// number `retries_so_far`.
    ///
    /// Semantics, with `retries_so_far` interpreted as "how many
    /// retries have already failed":
    ///
    /// - `0` -> `Duration::ZERO`: the first attempt runs
    ///   immediately, without delay.
    /// - `1` -> [`initial_delay`](Self::initial_delay) multiplied
    ///   by a random factor in `[1 - jitter, 1 + jitter]`.
    /// - `N` -> `initial_delay * multiplier^(N-1)` capped at
    ///   [`max_delay`](Self::max_delay), multiplied by the same
    ///   jitter factor.
    ///
    /// When [`jitter_fraction`](Self::jitter_fraction) is `0.0`
    /// (e.g. under [`Self::for_tests`]) the returned `Duration` is
    /// the deterministic exponential target.
    #[must_use]
    pub fn delay_before_retry(&self, retries_so_far: u32) -> Duration {
        if retries_so_far == 0 {
            return Duration::ZERO;
        }
        // retries_so_far N -> multiplier^(N-1)
        let exp = self
            .multiplier
            .powi(i32::try_from(retries_so_far - 1).unwrap_or(i32::MAX));
        let secs = self.initial_delay.as_secs_f64() * exp;
        let base = secs.min(self.max_delay.as_secs_f64()).max(0.0);

        // Clamp to `[0.0, 1.0]` so a misconfigured positive jitter
        // cannot produce a negative back-off, and a negative value
        // does not flip the arithmetic sign. The `base == 0` guard
        // avoids calling into the RNG when jitter would be a no-op.
        let jitter = self.jitter_fraction.clamp(0.0, 1.0);
        if jitter == 0.0 || base == 0.0 {
            return Duration::from_secs_f64(base);
        }
        // `random_range(a..=b)` requires `a <= b`; clamp produced
        // `jitter >= 0`, so `-jitter <= 0 <= jitter` holds.
        let offset: f64 = rand::rng().random_range(-jitter..=jitter);
        let jittered = (base * (1.0 + offset)).max(0.0);
        Duration::from_secs_f64(jittered)
    }

    /// Returns `true` when the runtime should give up because the
    /// number of retries completed so far has reached or exceeded
    /// [`max_retries`](Self::max_retries).
    #[must_use]
    pub const fn is_exhausted(&self, retries_so_far: u32) -> bool {
        retries_so_far >= self.max_retries
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
        // Force jitter to zero so this existing test still asserts
        // on the deterministic curve shape; the jittered shape is
        // covered separately by
        // `delay_before_retry_respects_jitter_bounds_and_actually_jitters`.
        let mut p = RetryPolicy::mastodon();
        p.jitter_fraction = 0.0;
        assert_eq!(p.delay_before_retry(1), Duration::from_mins(5));
    }

    #[test]
    fn delay_before_retry_grows_exponentially_until_cap() {
        let mut p = RetryPolicy::mastodon();
        p.jitter_fraction = 0.0;
        // 5min, 10min, 20min, 40min — pure exponential under the cap.
        assert_eq!(p.delay_before_retry(1), Duration::from_mins(5));
        assert_eq!(p.delay_before_retry(2), Duration::from_mins(10));
        assert_eq!(p.delay_before_retry(3), Duration::from_mins(20));
        assert_eq!(p.delay_before_retry(4), Duration::from_mins(40));
    }

    #[test]
    fn delay_before_retry_caps_at_max_delay() {
        let mut p = RetryPolicy::mastodon();
        p.jitter_fraction = 0.0;
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
        assert!(
            (d.jitter_fraction - m.jitter_fraction).abs() < f64::EPSILON,
            "Default::default MUST mirror RetryPolicy::mastodon including jitter",
        );
    }

    #[test]
    fn for_tests_profile_has_jitter_disabled() {
        // P1-N27 regression: the test profile MUST stay
        // deterministic so existing wall-clock-oriented tests
        // (e.g. `outbox_retries_on_transient_failure`) keep
        // passing without flake. Production profiles enable
        // jitter; test profiles do not.
        assert!(
            RetryPolicy::for_tests().jitter_fraction == 0.0,
            "for_tests() must disable jitter for deterministic assertions",
        );
    }

    #[test]
    fn mastodon_profile_carries_positive_default_jitter() {
        // P1-N27 regression: the production default MUST ship
        // with a non-zero jitter_fraction so a fan-out to N
        // followers on the same remote instance does not
        // thunder-herd that instance on every back-off boundary.
        let m = RetryPolicy::mastodon();
        assert!(
            m.jitter_fraction > 0.0,
            "mastodon() profile must have positive jitter_fraction, \
             got {}",
            m.jitter_fraction,
        );
        assert!(
            m.jitter_fraction <= 1.0,
            "jitter_fraction must be a sensible fraction, got {}",
            m.jitter_fraction,
        );
    }

    #[test]
    fn delay_before_retry_is_deterministic_when_jitter_disabled() {
        // With jitter_fraction == 0 the schedule is completely
        // reproducible: 128 calls must all return exactly the
        // same value so downstream tests can rely on strict
        // equality against the expected curve.
        let p = RetryPolicy::for_tests();
        let first = p.delay_before_retry(3);
        for _ in 0..128 {
            assert_eq!(
                p.delay_before_retry(3),
                first,
                "deterministic profile leaked RNG",
            );
        }
    }

    #[test]
    fn delay_before_retry_respects_jitter_bounds_and_actually_jitters() {
        // P1-N27 regression: a positive jitter_fraction MUST
        // (a) keep every sample inside `[base*(1-j), base*(1+j)]`
        //     (correctness), and
        // (b) actually produce at least TWO distinct values over
        //     a large enough sample so we know the code path is
        //     live (no "constant 1.0 multiplier" regression).
        let base = Duration::from_secs(1);
        let policy = RetryPolicy {
            initial_delay: base,
            max_delay: base,
            multiplier: 1.0,
            max_retries: 5,
            jitter_fraction: 0.25,
        };
        let lower = base.mul_f64(0.75);
        let upper = base.mul_f64(1.25);

        let mut distinct = std::collections::HashSet::new();
        for _ in 0..256 {
            let d = policy.delay_before_retry(1);
            assert!(
                d >= lower,
                "jittered delay {d:?} must be >= lower bound {lower:?}",
            );
            assert!(
                d <= upper,
                "jittered delay {d:?} must be <= upper bound {upper:?}",
            );
            distinct.insert(d.as_nanos());
        }
        assert!(
            distinct.len() > 1,
            "256 jittered samples collapsed to a single value — jitter \
             path is not live (seen values: {distinct:?})",
        );
    }

    #[test]
    fn delay_before_retry_clamps_nonsense_jitter_fraction() {
        // A misconfigured policy with jitter_fraction > 1.0 MUST
        // NOT produce a negative Duration (which would panic
        // inside `Duration::from_secs_f64`) — the clamp is the
        // safety belt.
        let mut policy = RetryPolicy::mastodon();
        policy.jitter_fraction = 5.0; // clamped to 1.0 internally
        for _ in 0..128 {
            let d = policy.delay_before_retry(1);
            assert!(
                d <= Duration::from_mins(5).mul_f64(2.0),
                "clamped jitter must stay within [0, 2 * base], \
                 got {d:?}",
            );
        }
    }

    #[test]
    fn delay_before_retry_zero_is_immediate_even_with_jitter() {
        // attempt 0 always fires immediately, jitter or not —
        // don't accidentally paint the first attempt with RNG.
        let mut policy = RetryPolicy::mastodon();
        policy.jitter_fraction = 0.5;
        assert_eq!(policy.delay_before_retry(0), Duration::ZERO);
    }
}
