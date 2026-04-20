//! Timestamp freshness / replay-protection policy for signature verification.
//!
//! The HTTP-Signatures specs (Cavage draft-12 §2.1.2 and RFC 9421
//! §7.2.2) both warn that signatures alone do **not** protect against
//! replay attacks: an intermediary who captures a valid signed request
//! can resend it verbatim until the signer's key rotates. The standard
//! mitigation is to require each signature to carry a `created`
//! parameter (or a `Date` header) and reject anything older than a
//! configured age, bounded on the future side by a small clock-skew
//! tolerance.
//!
//! [`VerifyPolicy`] captures the tunables for this check. Callers
//! choose a policy via one of the presets ([`VerifyPolicy::mastodon`],
//! [`VerifyPolicy::strict`]) or build one directly and pass it to the
//! `*_verify_with_policy` variants.

use chrono::{DateTime, Duration, Utc};
use httpdate::parse_http_date;

use crate::error::Error;

/// Minimum Cavage header set every compliant verifier should enforce.
///
/// The three names together bind the signature to the exact request
/// URI — omitting any of them lets an intermediary replay a captured
/// signature against a different path or a different virtual host.
/// Mastodon's own verifier hard-codes this requirement, so matching it
/// keeps us bug-for-bug compatible with the reference Fediverse
/// implementation.
pub const CAVAGE_REQUIRED_HEADERS: &[&str] = &["(request-target)", "host", "date"];

/// Tunables governing which signed requests are accepted at
/// verification time.
///
/// A `max_age` of `None` disables the past-side check and a
/// `max_clock_skew_future` of `None` disables the future-side check;
/// both default to `Some(...)` in the presets. `cavage_required_headers`
/// defaults to [`CAVAGE_REQUIRED_HEADERS`], and `allow_multiple_signatures`
/// defaults to `false` — callers that need the historical permissive
/// behaviour can flip either knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyPolicy {
    /// Maximum permissible age of a signature. A `created` (or `Date`)
    /// timestamp older than `now - max_age` is rejected. `None`
    /// disables the past-side check.
    pub max_age: Option<Duration>,

    /// Maximum permissible future skew. A timestamp claimed to be more
    /// than `max_clock_skew_future` ahead of the verifier's clock is
    /// rejected, to catch badly-set signer clocks and straight-out
    /// forgeries. `None` disables the future-side check.
    pub max_clock_skew_future: Option<Duration>,

    /// If `true`, a request carrying neither a `created` parameter nor
    /// a `Date` header is rejected. Defaults to `false` to stay
    /// compatible with servers that only emit one of the two.
    pub require_timestamp: bool,

    /// Cavage-specific: the list of header names whose presence in the
    /// `headers=` parameter is mandatory. A signature whose coverage
    /// does not include every name listed here is rejected with
    /// [`Error::RequiredHeaderAbsent`]. The names are compared
    /// case-insensitively.
    pub cavage_required_headers: &'static [&'static str],

    /// If `false` (the default), a `Signature-Input:` header containing
    /// more than one label is rejected outright. Mastodon and the RFC
    /// 9421 interop profile both expect exactly one signature per
    /// request; permitting additional labels opens a fallback channel
    /// an attacker can use to bypass policy by attaching a second
    /// signature of their own.
    pub allow_multiple_signatures: bool,
}

impl VerifyPolicy {
    /// Returns the policy Mastodon applies to inbound federated
    /// requests: 12 hours past, 5 minutes future, timestamps optional,
    /// and the Cavage minimum header set enforced.
    ///
    /// See <https://docs.joinmastodon.org/spec/security/>.
    #[must_use]
    pub const fn mastodon() -> Self {
        Self {
            max_age: Some(Duration::hours(12)),
            max_clock_skew_future: Some(Duration::minutes(5)),
            require_timestamp: false,
            cavage_required_headers: CAVAGE_REQUIRED_HEADERS,
            allow_multiple_signatures: false,
        }
    }

    /// Returns a tight policy appropriate for internal services where
    /// every hop has NTP-synchronised clocks: 5 minutes past, 1 minute
    /// future, timestamps mandatory, Cavage minimum header set
    /// enforced, and multi-signature requests rejected.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_age: Some(Duration::minutes(5)),
            max_clock_skew_future: Some(Duration::minutes(1)),
            require_timestamp: true,
            cavage_required_headers: CAVAGE_REQUIRED_HEADERS,
            allow_multiple_signatures: false,
        }
    }

    /// Returns a policy that **disables** freshness checking entirely.
    ///
    /// Only intended for byte-level conformance tests against static
    /// RFC 9421 / Cavage fixtures that bake fixed timestamps into their
    /// inputs. Do not use in production.
    #[must_use]
    pub const fn no_freshness_check() -> Self {
        Self {
            max_age: None,
            max_clock_skew_future: None,
            require_timestamp: false,
            cavage_required_headers: CAVAGE_REQUIRED_HEADERS,
            allow_multiple_signatures: false,
        }
    }

    /// Evaluates the policy against a signature whose `created`
    /// parameter is `created_unix` (seconds since epoch), `expires`
    /// parameter is `expires_unix`, and whose companion `Date` header
    /// (if any) contained `date_header`. Returns `Ok` when the
    /// signature is fresh, or a specific error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampMissing`] when `require_timestamp`
    /// is on and no source is available, [`Error::TimestampTooOld`]
    /// when `now - source > max_age`, [`Error::TimestampInFuture`]
    /// when the source is too far ahead of `now`, and
    /// [`Error::TimestampExpired`] when `expires` is already in the
    /// past.
    pub fn check(
        &self,
        created_unix: Option<i64>,
        expires_unix: Option<i64>,
        date_header: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        let reference = created_unix
            .and_then(unix_to_datetime)
            .or_else(|| date_header.and_then(parse_date_header));

        let Some(reference) = reference else {
            if self.require_timestamp {
                return Err(Error::TimestampMissing);
            }
            return Ok(());
        };

        if let Some(future_skew) = self.max_clock_skew_future
            && reference > now + future_skew
        {
            return Err(Error::TimestampInFuture {
                timestamp: reference,
                now,
            });
        }

        if let Some(max_age) = self.max_age
            && now.signed_duration_since(reference) > max_age
        {
            return Err(Error::TimestampTooOld {
                timestamp: reference,
                now,
            });
        }

        // `expires` is evaluated without clock-skew tolerance on the
        // past side: a signature with an `expires` parameter tells the
        // verifier *exactly* when it becomes invalid.
        if let Some(expires_unix) = expires_unix
            && let Some(expires) = unix_to_datetime(expires_unix)
            && now > expires
        {
            return Err(Error::TimestampExpired { expires, now });
        }

        Ok(())
    }
}

impl Default for VerifyPolicy {
    /// Returns [`Self::mastodon`] — the Fediverse-compatible default.
    fn default() -> Self {
        Self::mastodon()
    }
}

const fn unix_to_datetime(seconds: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(seconds, 0)
}

fn parse_date_header(value: &str) -> Option<DateTime<Utc>> {
    let system_time = parse_http_date(value).ok()?;
    Some(DateTime::<Utc>::from(system_time))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid UNIX time")
    }

    #[test]
    fn default_is_mastodon_policy() {
        assert_eq!(VerifyPolicy::default(), VerifyPolicy::mastodon());
    }

    #[test]
    fn fresh_signature_with_created_passes() {
        let policy = VerifyPolicy::mastodon();
        // created 1 hour before now — within the 12h window.
        let created = now().timestamp() - 3600;
        policy
            .check(Some(created), None, None, now())
            .expect("fresh");
    }

    #[test]
    fn too_old_signature_is_rejected() {
        let policy = VerifyPolicy::mastodon();
        // created 13 hours ago — beyond the 12h window.
        let created = now().timestamp() - 13 * 3600;
        let err = policy
            .check(Some(created), None, None, now())
            .expect_err("too old");
        assert!(matches!(err, Error::TimestampTooOld { .. }));
    }

    #[test]
    fn signature_in_the_future_is_rejected() {
        let policy = VerifyPolicy::mastodon();
        // created 10 minutes in the future — beyond the 5m skew window.
        let created = now().timestamp() + 10 * 60;
        let err = policy
            .check(Some(created), None, None, now())
            .expect_err("future");
        assert!(matches!(err, Error::TimestampInFuture { .. }));
    }

    #[test]
    fn expires_in_the_past_is_rejected() {
        let policy = VerifyPolicy::mastodon();
        let created = now().timestamp() - 60;
        let expires = now().timestamp() - 30;
        let err = policy
            .check(Some(created), Some(expires), None, now())
            .expect_err("expired");
        assert!(matches!(err, Error::TimestampExpired { .. }));
    }

    #[test]
    fn date_header_is_used_when_created_is_absent() {
        let policy = VerifyPolicy::mastodon();
        // 1 hour before `now`: 2023-11-14 21:13:20 UTC (epoch 1699996400).
        let ts = DateTime::<Utc>::from_timestamp(now().timestamp() - 3600, 0).expect("valid");
        let header = httpdate::fmt_http_date(std::time::SystemTime::from(ts));
        policy
            .check(None, None, Some(&header), now())
            .expect("date-header fallback");
    }

    #[test]
    fn missing_timestamp_passes_by_default() {
        let policy = VerifyPolicy::mastodon();
        policy.check(None, None, None, now()).expect("tolerated");
    }

    #[test]
    fn missing_timestamp_fails_under_strict_policy() {
        let policy = VerifyPolicy::strict();
        let err = policy.check(None, None, None, now()).expect_err("required");
        assert!(matches!(err, Error::TimestampMissing));
    }

    #[test]
    fn malformed_date_header_is_ignored_and_treated_as_absent() {
        let policy = VerifyPolicy::mastodon();
        // With `require_timestamp=false`, a bad Date just falls through.
        policy
            .check(None, None, Some("not a date"), now())
            .expect("ignored");
    }

    #[test]
    fn no_freshness_check_preset_accepts_stale_timestamps() {
        let policy = VerifyPolicy::no_freshness_check();
        // 100 years in the past — should still pass.
        let stale = now().timestamp() - 100 * 365 * 24 * 3600;
        policy
            .check(Some(stale), None, None, now())
            .expect("stale OK");
    }
}
