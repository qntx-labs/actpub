//! Per-request fetch context shared across recursive dereferences.
//!
//! [`FetchContext`] is the value every [`Fetcher`](crate::Fetcher)
//! call threads through so that the runtime can impose a single
//! budget on the total number of HTTP fetches one logical request
//! (one inbox POST, one outbox dispatch, one user-initiated
//! `ObjectId::dereference`) is allowed to trigger.
//!
//! Without such a budget, a malicious peer can induce an unbounded
//! chain of signed fetches by pointing `object.inReplyTo.inReplyTo…`
//! at a new remote object each hop — the classic `ActivityPub`
//! [Security Considerations §B.5] recursive-fetch `DoS`. The runtime
//! checks the counter on every `fetch_raw` entry and surfaces
//! [`Error::RecursiveFetchLimit`](crate::Error::RecursiveFetchLimit)
//! once the configured ceiling is hit.
//!
//! The context is cheap to clone (everything lives behind an `Arc`)
//! so callers can freely propagate it through futures / spawned
//! tasks; cloning does **not** reset the counter.
//!
//! [Security Considerations §B.5]: https://www.w3.org/TR/activitypub/#security-considerations

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::Error;

/// Budget shared between every [`Fetcher::fetch_raw`](crate::Fetcher::fetch_raw)
/// call issued while servicing one logical request.
///
/// Cheap to clone — the counter and limit are `Arc`-shared, so a
/// clone observes the same budget as the original.
#[derive(Debug, Clone)]
pub struct FetchContext {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    counter: AtomicU32,
    limit: u32,
}

impl FetchContext {
    /// Creates a fresh budget of `limit` recursive fetches.
    ///
    /// `limit = 0` forbids every outbound fetch for the scope
    /// sharing this context (useful in tests that want to assert a
    /// code path performs no IO).
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            inner: Arc::new(Inner {
                counter: AtomicU32::new(0),
                limit,
            }),
        }
    }

    /// Registers one outbound fetch against the budget.
    ///
    /// Every [`Fetcher`](crate::Fetcher) implementation MUST call
    /// this at the head of `fetch_raw` (before any IO) so that the
    /// counter reflects the fetch that is *about to* happen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecursiveFetchLimit`] once the running
    /// total exceeds the limit this context was constructed with.
    pub fn charge(&self) -> Result<(), Error> {
        // `fetch_add` returns the *old* value, so `+ 1` tells us the
        // running total including this fetch.
        let n = self.inner.counter.fetch_add(1, Ordering::SeqCst) + 1;
        if n > self.inner.limit {
            return Err(Error::RecursiveFetchLimit {
                limit: self.inner.limit,
            });
        }
        Ok(())
    }

    /// Returns the number of fetches already charged against this
    /// context. Primarily useful in tests that want to assert an
    /// expected level of recursion.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.inner.counter.load(Ordering::Relaxed)
    }

    /// Returns the configured ceiling.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.inner.limit
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn charge_increments_until_limit_then_errors() {
        let ctx = FetchContext::new(3);
        assert_eq!(ctx.count(), 0);
        ctx.charge().expect("1st");
        ctx.charge().expect("2nd");
        ctx.charge().expect("3rd");
        // Next call is the over-budget one.
        let err = ctx.charge().expect_err("4th must fail");
        assert!(matches!(err, Error::RecursiveFetchLimit { limit: 3 }));
    }

    #[test]
    fn clone_shares_counter_with_original() {
        let ctx = FetchContext::new(2);
        ctx.charge().expect("1st");
        let twin = ctx.clone();
        twin.charge().expect("2nd");
        // The third charge on EITHER twin must fail — budget is shared.
        assert!(ctx.charge().is_err());
    }

    #[test]
    fn zero_limit_forbids_any_fetch() {
        let ctx = FetchContext::new(0);
        let err = ctx.charge().expect_err("zero-budget context must reject");
        assert!(matches!(err, Error::RecursiveFetchLimit { limit: 0 }));
    }
}
