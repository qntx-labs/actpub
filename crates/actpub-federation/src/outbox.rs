//! Outbox fan-out helper with background retry queue.
//!
//! [`Outbox`] is the send-side counterpart of
//! [`InboxPipeline`](crate::InboxPipeline): it takes one activity
//! plus a list of recipient actor URLs, resolves each actor to its
//! inbox (preferring [`sharedInbox`](https://www.w3.org/TR/activitypub/#shared-inbox-delivery)
//! to amortise per-server delivery cost), de-duplicates the inbox
//! set, and POSTs the activity to each unique inbox.
//!
//! Failures do not bubble up to the caller — they are enqueued onto
//! a background tokio task that retries them per the configured
//! [`RetryPolicy`]. From the caller's perspective `dispatch` is
//! fire-and-forget by design (this matches the contract that
//! Mastodon's Sidekiq queue offers user-facing code).
//!
//! # Resource model
//!
//! Each [`Outbox`] holds **one** background tokio task driving its
//! retry loop, owning an unbounded channel of pending deliveries.
//! Cloning an `Outbox` shares the same task. Drop the last clone to
//! shut the loop down (the sender half closes, the worker drains
//! and exits).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;
use url::Url;

use crate::deliver::Deliverer;
use crate::error::Error;
use crate::fetcher::Fetcher;
use crate::retry::RetryPolicy;

/// Send-side counterpart of [`InboxPipeline`](crate::InboxPipeline).
///
/// Cheap to clone (the worker handle, channel sender, and pinned
/// dependencies all live behind an `Arc`).
pub struct Outbox<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    inner: Arc<Inner<D, F>>,
}

impl<D, F> Clone for Outbox<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<D, F> std::fmt::Debug for Outbox<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field("retry_policy", &self.inner.retry_policy)
            .finish()
    }
}

struct Inner<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    deliverer: D,
    fetcher: F,
    retry_policy: RetryPolicy,
    tx: mpsc::UnboundedSender<DeliveryJob>,
}

#[derive(Debug)]
struct DeliveryJob {
    activity: Value,
    inbox: Url,
    /// 0 for the immediate first attempt; incremented on every retry.
    attempt: u32,
}

impl<D, F> Outbox<D, F>
where
    D: Deliverer + 'static,
    F: Fetcher + 'static,
{
    /// Builds an outbox that drives `deliverer` for actual POSTs and
    /// `fetcher` for actor-to-inbox resolution, retrying transient
    /// failures per `retry_policy`.
    ///
    /// Spawns one background tokio task; consequently MUST be called
    /// from inside a tokio runtime context.
    #[must_use]
    pub fn new(deliverer: D, fetcher: F, retry_policy: RetryPolicy) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<DeliveryJob>();
        let inner = Arc::new(Inner {
            deliverer,
            fetcher,
            retry_policy,
            tx,
        });
        spawn_worker(Arc::clone(&inner), rx);
        Self { inner }
    }

    /// Resolves every URL in `recipient_actors` to an inbox URL,
    /// de-duplicates the result, and enqueues a delivery job per
    /// unique inbox.
    ///
    /// `recipient_actors` should contain actor URLs as they appear
    /// on the wire in the activity's `to` / `cc` fields. The special
    /// public collection URL
    /// `https://www.w3.org/ns/activitystreams#Public` MUST be filtered
    /// out by the caller before this call — it is not a real
    /// addressable actor.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error`] produced while fetching one of the
    /// actors. Callers that want partial delivery (best-effort across
    /// recipients) should resolve actors themselves and call
    /// [`enqueue`](Self::enqueue) per inbox.
    pub async fn dispatch(
        &self,
        activity: Value,
        recipient_actors: &[Url],
    ) -> Result<usize, Error> {
        let inboxes = self.resolve_inboxes(recipient_actors).await?;
        let count = inboxes.len();
        for inbox in inboxes {
            self.enqueue(activity.clone(), inbox);
        }
        Ok(count)
    }

    /// Enqueues a single delivery job — bypassing the actor-to-inbox
    /// resolution step — to be dispatched by the background worker.
    pub fn enqueue(&self, activity: Value, inbox: Url) {
        // The receiver is owned by the worker task we spawned in
        // `new`, so `send` only fails after the worker has already
        // panicked or been dropped — both are unrecoverable, and
        // there is nothing the caller could meaningfully do about
        // it. We log at error level instead of returning a Result.
        if self
            .inner
            .tx
            .send(DeliveryJob {
                activity,
                inbox,
                attempt: 0,
            })
            .is_err()
        {
            tracing::error!(
                target: "actpub::outbox",
                "outbox worker is gone; dropping delivery job",
            );
        }
    }

    /// Resolves a recipient list to the de-duplicated set of inbox
    /// URLs, preferring `endpoints.sharedInbox` whenever an actor
    /// publishes one.
    ///
    /// # Errors
    ///
    /// Returns the first fetcher error or
    /// [`Error::ActorWithoutInbox`].
    pub async fn resolve_inboxes(
        &self,
        recipient_actors: &[Url],
    ) -> Result<HashSet<Url>, Error> {
        let mut inboxes: HashSet<Url> = HashSet::new();
        for actor_url in recipient_actors {
            let actor = self.inner.fetcher.fetch_raw(actor_url).await?;
            let inbox = pick_inbox(&actor, actor_url)?;
            inboxes.insert(inbox);
        }
        Ok(inboxes)
    }
}

fn spawn_worker<D, F>(inner: Arc<Inner<D, F>>, mut rx: mpsc::UnboundedReceiver<DeliveryJob>)
where
    D: Deliverer + 'static,
    F: Fetcher + 'static,
{
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            let inner = Arc::clone(&inner);
            tokio::spawn(async move {
                run_one(inner, job).await;
            });
        }
    });
}

async fn run_one<D, F>(inner: Arc<Inner<D, F>>, job: DeliveryJob)
where
    D: Deliverer,
    F: Fetcher,
{
    let delay = inner.retry_policy.delay_before_retry(job.attempt);
    if delay > Duration::ZERO {
        tokio::time::sleep(delay).await;
    }
    let DeliveryJob {
        activity,
        inbox,
        attempt,
    } = job;
    match inner.deliverer.deliver(&activity, &inbox).await {
        Ok(()) => {
            tracing::debug!(target: "actpub::outbox", attempt, %inbox, "delivered");
        }
        Err(err) => {
            let next = attempt + 1;
            if inner.retry_policy.is_exhausted(next) {
                tracing::warn!(
                    target: "actpub::outbox",
                    attempt = next,
                    max = inner.retry_policy.max_retries,
                    %inbox,
                    %err,
                    "delivery exhausted retries",
                );
            } else {
                tracing::warn!(
                    target: "actpub::outbox",
                    attempt = next,
                    max = inner.retry_policy.max_retries,
                    %inbox,
                    %err,
                    "delivery failed; retrying",
                );
                if inner
                    .tx
                    .send(DeliveryJob {
                        activity,
                        inbox,
                        attempt: next,
                    })
                    .is_err()
                {
                    tracing::error!(
                        target: "actpub::outbox",
                        "outbox worker is gone; dropping retry job",
                    );
                }
            }
        }
    }
}

fn pick_inbox(actor: &Value, actor_url: &Url) -> Result<Url, Error> {
    if let Some(shared) = actor
        .get("endpoints")
        .and_then(|e| e.get("sharedInbox"))
        .and_then(Value::as_str)
        && let Ok(url) = shared.parse::<Url>()
    {
        return Ok(url);
    }
    if let Some(inbox) = actor.get("inbox").and_then(Value::as_str)
        && let Ok(url) = inbox.parse::<Url>()
    {
        return Ok(url);
    }
    Err(Error::ActorWithoutInbox(actor_url.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    /// Test deliverer that records every (inbox, attempt) call and
    /// can be configured to fail the first N attempts to drive the
    /// retry path.
    struct RecordingDeliverer {
        calls: Mutex<Vec<(Url, Value)>>,
        fail_first_n: AtomicUsize,
    }

    impl RecordingDeliverer {
        fn new(fail_first_n: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_first_n: AtomicUsize::new(fail_first_n),
            }
        }
    }

    impl Deliverer for RecordingDeliverer {
        async fn deliver(&self, activity: &Value, inbox: &Url) -> Result<(), Error> {
            self.calls.lock().unwrap().push((inbox.clone(), activity.clone()));
            if self.fail_first_n.load(Ordering::SeqCst) > 0 {
                self.fail_first_n.fetch_sub(1, Ordering::SeqCst);
                return Err(Error::Status {
                    url: inbox.clone(),
                    status: 503,
                });
            }
            Ok(())
        }
    }

    /// Test fetcher returning canned actor JSONs by URL.
    struct StaticFetcher {
        actors: std::collections::HashMap<String, Value>,
    }

    impl Fetcher for StaticFetcher {
        async fn fetch_raw(&self, url: &Url) -> Result<Value, Error> {
            self.actors
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| Error::Status {
                    url: url.clone(),
                    status: 404,
                })
        }
    }

    fn actor_with_inbox(actor_url: &str, inbox_url: &str) -> Value {
        json!({
            "id": actor_url,
            "type": "Person",
            "inbox": inbox_url,
        })
    }

    fn actor_with_shared_inbox(actor_url: &str, inbox: &str, shared: &str) -> Value {
        json!({
            "id": actor_url,
            "type": "Person",
            "inbox": inbox,
            "endpoints": { "sharedInbox": shared },
        })
    }

    #[test]
    fn pick_inbox_prefers_shared_over_personal() {
        let actor = actor_with_shared_inbox(
            "https://example.com/users/alice",
            "https://example.com/users/alice/inbox",
            "https://example.com/inbox",
        );
        let actor_url: Url = "https://example.com/users/alice".parse().unwrap();
        let inbox = pick_inbox(&actor, &actor_url).unwrap();
        assert_eq!(inbox.as_str(), "https://example.com/inbox");
    }

    #[test]
    fn pick_inbox_falls_back_to_personal_when_no_shared_inbox() {
        let actor = actor_with_inbox(
            "https://example.com/users/alice",
            "https://example.com/users/alice/inbox",
        );
        let actor_url: Url = "https://example.com/users/alice".parse().unwrap();
        let inbox = pick_inbox(&actor, &actor_url).unwrap();
        assert_eq!(inbox.as_str(), "https://example.com/users/alice/inbox");
    }

    #[test]
    fn pick_inbox_errors_when_no_endpoint_present() {
        let actor = json!({ "id": "https://example.com/u/alice", "type": "Person" });
        let actor_url: Url = "https://example.com/u/alice".parse().unwrap();
        let err = pick_inbox(&actor, &actor_url)
            .expect_err("actor without inbox must surface an error");
        assert!(matches!(err, Error::ActorWithoutInbox(_)));
    }

    #[tokio::test]
    async fn dispatch_deduplicates_recipients_sharing_a_shared_inbox() {
        // Two actors hosted on the same server share one sharedInbox.
        // The runtime MUST POST exactly once.
        let alice_url = "https://example.com/users/alice";
        let bob_url = "https://example.com/users/bob";
        let shared = "https://example.com/inbox";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_shared_inbox(
                alice_url,
                "https://example.com/users/alice/inbox",
                shared,
            ),
        );
        actors.insert(
            bob_url.into(),
            actor_with_shared_inbox(bob_url, "https://example.com/users/bob/inbox", shared),
        );

        let deliverer = Arc::new(RecordingDeliverer::new(0));
        let outbox = Outbox::new(
            // Wrap deliverer in a wrapper so the trait bound is on `Arc<...>`'s contents:
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
        );

        let activity = json!({ "id": "https://send.example/a/1", "type": "Create" });
        let n = outbox
            .dispatch(activity, &[alice_url.parse().unwrap(), bob_url.parse().unwrap()])
            .await
            .unwrap();
        assert_eq!(n, 1, "shared inbox dedupes two recipients into one delivery");

        // Give the worker a chance to drain.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let calls = deliverer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.as_str(), shared);
    }

    #[tokio::test]
    async fn dispatch_retries_on_transient_failure_then_succeeds() {
        let alice_url = "https://example.com/users/alice";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );

        // Deliverer fails once, then succeeds on the retry.
        let deliverer = Arc::new(RecordingDeliverer::new(1));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
        );

        outbox
            .dispatch(
                json!({ "id": "https://send.example/a/2", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await
            .unwrap();

        // First attempt is immediate, retry waits ~10ms; sleep
        // 200ms to be safe across CI timing jitter.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let calls = deliverer.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "first attempt + one retry");
    }

    #[tokio::test]
    async fn dispatch_gives_up_after_max_retries() {
        let alice_url = "https://example.com/users/alice";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );

        // Deliverer always fails. for_tests() = 3 retries → 4 total
        // attempts before exhaustion.
        let deliverer = Arc::new(RecordingDeliverer::new(usize::MAX));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
        );

        outbox
            .dispatch(
                json!({ "id": "https://send.example/a/3", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await
            .unwrap();

        // for_tests() schedule: 0, 10, 20, 40 ms → total <100 ms.
        // Wait generously to let the worker exhaust retries.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let calls = deliverer.calls.lock().unwrap();
        // attempt=0,1,2 produce 3 calls; attempt=3 is the boundary
        // where is_exhausted fires before scheduling, so the call is
        // not made. The worker thus stops after exactly 3 attempts.
        assert_eq!(calls.len(), 3, "attempts up to but not including max_retries");
    }

    #[tokio::test]
    async fn dispatch_propagates_actor_without_inbox_error() {
        let alice_url = "https://example.com/users/keyless";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            json!({ "id": alice_url, "type": "Person" }),
        );
        let outbox = Outbox::new(
            ArcDeliverer(Arc::new(RecordingDeliverer::new(0))),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
        );
        let err = outbox
            .dispatch(
                json!({ "id": "https://send.example/a/4", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await
            .expect_err("actor without inbox must surface");
        assert!(matches!(err, Error::ActorWithoutInbox(_)));
    }

    /// Adapter so the `Outbox` (which owns its `Deliverer` by value)
    /// can share a `RecordingDeliverer` instance with the test for
    /// post-hoc assertions.
    struct ArcDeliverer<D: Deliverer>(Arc<D>);

    impl<D: Deliverer> Deliverer for ArcDeliverer<D> {
        async fn deliver(&self, activity: &Value, inbox: &Url) -> Result<(), Error> {
            self.0.deliver(activity, inbox).await
        }
    }
}
