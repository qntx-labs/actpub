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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use url::Url;

use crate::config::FederationConfig;
use crate::deliver::Deliverer;
use crate::error::Error;
use crate::fetch_ctx::FetchContext;
use crate::fetcher::Fetcher;
use crate::retry::RetryPolicy;

/// Outcome of a single [`Outbox::dispatch`] call.
///
/// `dispatch` is best-effort: a broken recipient never aborts the
/// fan-out. The resulting report enumerates how many unique inboxes
/// were actually enqueued and records (`actor_url`, `error`) pairs
/// for every recipient whose actor could not be resolved or whose
/// JSON did not expose a usable inbox.
#[derive(Debug)]
#[non_exhaustive]
pub struct DispatchReport {
    /// Number of unique inbox URLs enqueued for background delivery.
    pub enqueued: usize,
    /// Per-actor resolution failures. Empty on full success.
    pub errors: Vec<(Url, Error)>,
}

impl DispatchReport {
    /// `true` when every recipient resolved to an enqueued inbox.
    #[must_use]
    pub const fn is_full_success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Outcome of [`Outbox::resolve_inboxes`].
///
/// Best-effort counterpart to the older fail-fast API: both the
/// successful inbox URLs and the per-actor failures are surfaced so
/// the caller can observe partial success.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct InboxResolution {
    /// De-duplicated set of inbox URLs that resolved successfully.
    pub inboxes: HashSet<Url>,
    /// Per-actor resolution failures in submission order.
    pub errors: Vec<(Url, Error)>,
}

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
    /// Shared runtime configuration. Held on the outbox so
    /// [`Outbox::resolve_inboxes`] can apply the configured
    /// [`UrlPolicy`](crate::UrlPolicy) to every picked inbox URL
    /// *before* it enters the retry queue — this is the admission
    /// gate that keeps `sharedInbox` URLs served by a malicious
    /// actor from turning the outbox into an SSRF amplifier.
    config: Arc<FederationConfig>,
    /// Budget applied to each recipient's actor-resolution fetch.
    /// A fresh [`FetchContext`] is minted *per recipient* inside
    /// [`Outbox::resolve_inboxes`] so one dead actor burning
    /// through its recursive budget cannot starve the siblings.
    http_fetch_limit: u32,
    /// Global ceiling on concurrent deliveries. Every call to
    /// `run_one` acquires one permit before touching the network,
    /// so a fan-out to 10 000 inboxes cannot instantly pin 10 000
    /// TCP sockets. Sized by
    /// [`FederationConfig::delivery_concurrency`].
    delivery_semaphore: Arc<Semaphore>,
    /// Handle to the single background worker task spawned by
    /// [`spawn_worker`]. Stored so that dropping the last
    /// [`Outbox`] clone aborts the worker instead of leaking it
    /// past the runtime's lifetime.
    worker_handle: Mutex<Option<JoinHandle<()>>>,
}

impl<D, F> Drop for Inner<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    fn drop(&mut self) {
        // Dropping the last `Outbox` clone closes `tx` (because
        // `Inner::tx` is gone with the `Arc`), which in turn lets
        // the worker's `rx.recv().await` return `None` and the
        // loop exit cleanly. We still abort explicitly as a
        // defence-in-depth against the worker spinning on an
        // in-flight delivery after the runtime tried to shut down.
        if let Ok(mut slot) = self.worker_handle.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
    }
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
    /// failures per `retry_policy` and applying `config`'s URL
    /// policy to every picked inbox before it enters the queue.
    ///
    /// Spawns one background tokio task; consequently MUST be called
    /// from inside a tokio runtime context.
    #[must_use]
    pub fn new(
        deliverer: D,
        fetcher: F,
        retry_policy: RetryPolicy,
        config: Arc<FederationConfig>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<DeliveryJob>();
        let http_fetch_limit = config.http_fetch_limit;
        // `Semaphore::new(0)` would deadlock every delivery; clamp
        // the configured concurrency to at least 1 so a misconfigured
        // build can still make (serialised) forward progress.
        let delivery_semaphore = Arc::new(Semaphore::new(config.delivery_concurrency.max(1)));
        let inner = Arc::new(Inner {
            deliverer,
            fetcher,
            retry_policy,
            tx,
            config,
            http_fetch_limit,
            delivery_semaphore,
            worker_handle: Mutex::new(None),
        });
        let handle = spawn_worker(Arc::clone(&inner), rx);
        // `inner` is held by both the handle struct we return and
        // the worker task; storing the `JoinHandle` lets `Drop`
        // abort the worker the moment the last clone goes away.
        if let Ok(mut slot) = inner.worker_handle.lock() {
            *slot = Some(handle);
        }
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
    /// out by the caller before this call -- it is not a real
    /// addressable actor.
    ///
    /// # Best-effort semantics
    ///
    /// Actor resolution is best-effort: if one recipient's actor
    /// cannot be dereferenced or exposes no inbox, the failure is
    /// recorded in [`DispatchReport::errors`] but all **other**
    /// recipients continue to be resolved and enqueued. This
    /// matches how Mastodon / Pleroma / Lemmy all treat a broken
    /// remote peer -- a single dead recipient never stops the
    /// fan-out. Callers that want strict fail-fast behaviour can
    /// check `report.errors.is_empty()` themselves.
    pub async fn dispatch(&self, activity: Value, recipient_actors: &[Url]) -> DispatchReport {
        let resolution = self.resolve_inboxes(recipient_actors).await;
        let enqueued = resolution.inboxes.len();
        for inbox in resolution.inboxes {
            self.enqueue(activity.clone(), inbox);
        }
        DispatchReport {
            enqueued,
            errors: resolution.errors,
        }
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
    /// Never returns a top-level `Result`: actor-resolution failures
    /// are collected into [`InboxResolution::errors`] while every
    /// other recipient continues to be resolved. This matches the
    /// best-effort fan-out contract used by every mainstream
    /// Fediverse server.
    pub async fn resolve_inboxes(&self, recipient_actors: &[Url]) -> InboxResolution {
        let mut resolution = InboxResolution::default();
        for actor_url in recipient_actors {
            match self.resolve_one(actor_url).await {
                Ok(inbox) => {
                    resolution.inboxes.insert(inbox);
                }
                Err(e) => resolution.errors.push((actor_url.clone(), e)),
            }
        }
        resolution
    }

    /// Resolves a single recipient to its admissible inbox URL, or
    /// surfaces the reason the recipient was dropped. Extracted so
    /// [`Self::resolve_inboxes`] stays a flat fan-out driver and the
    /// three branching failure modes (fetch, pick, policy) stay
    /// legible side-by-side here.
    async fn resolve_one(&self, actor_url: &Url) -> Result<Url, Error> {
        // Per-recipient budget: each actor gets its own copy of the
        // recursive-fetch counter so a fan-out to 2,000 followers is
        // not artificially clamped by a global ceiling sized for
        // *one* inbox request's recursive chain. (The SSRF guard
        // inside `FetchContext` still applies per call; the budget
        // is only reset between recipients.)
        let ctx = FetchContext::new(self.inner.http_fetch_limit);
        let actor = self
            .inner
            .fetcher
            .fetch_raw(actor_url, &ctx)
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "actpub::outbox",
                    %actor_url, error = %e,
                    "failed to fetch recipient actor; skipping",
                );
                e
            })?;
        let inbox = pick_inbox(&actor, actor_url).map_err(|e| {
            tracing::warn!(
                target: "actpub::outbox",
                %actor_url, error = %e,
                "recipient has no usable inbox; skipping",
            );
            e
        })?;
        // Apply the URL policy (syntactic + DNS resolved) *before*
        // the inbox enters the retry queue so a malicious actor
        // that advertises a `sharedInbox` pointing at the loopback
        // interface cannot cost us one queue slot + several retries
        // per delivery.
        self.inner
            .config
            .url_policy
            .check_full(&inbox)
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "actpub::outbox",
                    %actor_url, %inbox, error = %e,
                    "picked inbox fails URL policy; skipping",
                );
                e
            })?;
        Ok(inbox)
    }
}

fn spawn_worker<D, F>(
    inner: Arc<Inner<D, F>>,
    mut rx: mpsc::UnboundedReceiver<DeliveryJob>,
) -> JoinHandle<()>
where
    D: Deliverer + 'static,
    F: Fetcher + 'static,
{
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            // Acquire one permit *in the dispatcher* so the
            // concurrency ceiling creates backpressure on the
            // receive side too: when every permit is in flight the
            // dispatcher blocks here instead of spawning yet
            // another task. `Semaphore::close` during shutdown
            // would surface as `AcquireError`; in that case we log
            // once and drop the remaining queue.
            let Ok(permit) = Arc::clone(&inner.delivery_semaphore).acquire_owned().await else {
                tracing::error!(
                    target: "actpub::outbox",
                    "delivery semaphore closed; draining queued jobs",
                );
                break;
            };
            let job_inner = Arc::clone(&inner);
            tokio::spawn(async move {
                // Hold the permit for the duration of
                // `run_one`; dropping it on exit releases a slot
                // back to the dispatcher.
                let _permit = permit;
                run_one(job_inner, job).await;
            });
        }
    })
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

    use actpub_httpsig::SigningKey;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;
    use crate::policy::UrlPolicy;

    /// Test config helper: a permissive [`UrlPolicy`] so the
    /// in-process mock inbox URLs used by these tests pass the
    /// outbox's `check_full` admission gate.
    fn test_config() -> Arc<FederationConfig> {
        FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://example.com/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .build()
            .shared()
    }

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
            self.calls
                .lock()
                .unwrap()
                .push((inbox.clone(), activity.clone()));
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
        async fn fetch_raw(&self, url: &Url, _ctx: &FetchContext) -> Result<Value, Error> {
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
        let err =
            pick_inbox(&actor, &actor_url).expect_err("actor without inbox must surface an error");
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
            actor_with_shared_inbox(alice_url, "https://example.com/users/alice/inbox", shared),
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
            test_config(),
        );

        let activity = json!({ "id": "https://send.example/a/1", "type": "Create" });
        let report = outbox
            .dispatch(
                activity,
                &[alice_url.parse().unwrap(), bob_url.parse().unwrap()],
            )
            .await;
        assert!(
            report.is_full_success(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(
            report.enqueued, 1,
            "shared inbox dedupes two recipients into one delivery",
        );

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
            test_config(),
        );

        let report = outbox
            .dispatch(
                json!({ "id": "https://send.example/a/2", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await;
        assert!(report.is_full_success());

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
            test_config(),
        );

        let report = outbox
            .dispatch(
                json!({ "id": "https://send.example/a/3", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await;
        assert!(report.is_full_success());

        // for_tests() schedule: 0, 10, 20, 40 ms → total <100 ms.
        // Wait generously to let the worker exhaust retries.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let calls = deliverer.calls.lock().unwrap();
        // attempt=0,1,2 produce 3 calls; attempt=3 is the boundary
        // where is_exhausted fires before scheduling, so the call is
        // not made. The worker thus stops after exactly 3 attempts.
        assert_eq!(
            calls.len(),
            3,
            "attempts up to but not including max_retries"
        );
    }

    #[tokio::test]
    async fn dispatch_records_actor_without_inbox_as_partial_failure() {
        // Best-effort contract: one broken recipient produces a
        // report entry, not a top-level error; the rest of the
        // fan-out (if any) continues unaffected.
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
            test_config(),
        );
        let report = outbox
            .dispatch(
                json!({ "id": "https://send.example/a/4", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await;
        assert_eq!(report.enqueued, 0, "no inbox means nothing to enqueue");
        assert_eq!(report.errors.len(), 1);
        let (ref url, ref err) = report.errors[0];
        assert_eq!(url.as_str(), alice_url);
        assert!(matches!(err, Error::ActorWithoutInbox(_)));
    }

    #[tokio::test]
    async fn resolve_rejects_actor_whose_shared_inbox_fails_url_policy() {
        // P0-9 regression: a malicious actor advertises a
        // `sharedInbox` pointing at localhost. `resolve_inboxes`
        // MUST refuse to enqueue that URL even though the actor
        // itself parses fine -- otherwise the retry queue ends up
        // POSTing a signed activity at the internal network.
        let attacker_url = "https://attacker.example/users/eve";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            attacker_url.into(),
            actor_with_shared_inbox(
                attacker_url,
                "https://attacker.example/users/eve/inbox",
                "https://localhost/inbox",
            ),
        );
        // Production-shape config: strict `UrlPolicy` (default),
        // which forbids loopback hostnames in admitted URLs.
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .build()
            .shared();
        let outbox = Outbox::new(
            ArcDeliverer(Arc::new(RecordingDeliverer::new(0))),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            cfg,
        );
        let report = outbox
            .dispatch(
                json!({ "id": "https://sender.example/a/poison", "type": "Create" }),
                &[attacker_url.parse().unwrap()],
            )
            .await;
        assert_eq!(
            report.enqueued, 0,
            "loopback sharedInbox must not be enqueued"
        );
        assert_eq!(report.errors.len(), 1);
        let (url, err) = &report.errors[0];
        assert_eq!(url.as_str(), attacker_url);
        assert!(
            matches!(err, Error::PolicyViolation { .. }),
            "unexpected: {err:?}",
        );
    }

    #[tokio::test]
    async fn dispatch_partially_succeeds_when_one_recipient_is_broken() {
        // Two recipients: one resolves cleanly, one cannot be
        // fetched. The good recipient still gets enqueued.
        let alice_url = "https://example.com/users/alice";
        let broken_url = "https://example.com/users/404";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );
        // `broken_url` deliberately absent -> StaticFetcher 404.
        let deliverer = Arc::new(RecordingDeliverer::new(0));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            test_config(),
        );
        let report = outbox
            .dispatch(
                json!({ "id": "https://send.example/a/5", "type": "Create" }),
                &[alice_url.parse().unwrap(), broken_url.parse().unwrap()],
            )
            .await;

        assert_eq!(
            report.enqueued, 1,
            "only the resolvable recipient is enqueued"
        );
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].0.as_str(), broken_url);
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

    /// Deliverer that records the instantaneous and peak number of
    /// concurrently-in-flight deliveries, holding each one open for
    /// ~30 ms so the outbox's concurrency ceiling is actually
    /// exercised. Pulled out of the test body to keep the
    /// concurrency book-keeping legible and to dodge the nested-
    /// async-closure lint inside `#[tokio::test]` fns.
    struct ConcurrencyObserver {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    impl Deliverer for ConcurrencyObserver {
        async fn deliver(&self, _activity: &Value, _inbox: &Url) -> Result<(), Error> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            bump_peak(&self.peak, cur);
            // Hold the permit long enough that the worker is forced
            // to queue the rest behind the semaphore.
            tokio::time::sleep(Duration::from_millis(30)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Monotonically lifts `peak` to `candidate` via a
    /// compare-exchange loop. Standalone so the observer impl stays
    /// a flat async fn.
    fn bump_peak(peak: &AtomicUsize, candidate: usize) {
        let mut current = peak.load(Ordering::SeqCst);
        while candidate > current {
            match peak.compare_exchange(current, candidate, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return,
                Err(got) => current = got,
            }
        }
    }

    /// Adapter mirroring [`ArcDeliverer`] but for the concurrency
    /// observer; needed because [`Outbox::new`] takes its deliverer
    /// by value and the test needs to inspect the observer after
    /// dispatching.
    struct ArcObserver(Arc<ConcurrencyObserver>);

    impl Deliverer for ArcObserver {
        async fn deliver(&self, a: &Value, i: &Url) -> Result<(), Error> {
            self.0.deliver(a, i).await
        }
    }

    #[tokio::test]
    async fn dispatch_caps_concurrent_deliveries_via_semaphore() {
        // P0-6 regression: a fan-out to many recipients must be
        // clamped by `delivery_concurrency`, not by whatever the
        // runtime happens to tolerate. We set the ceiling to 2, ask
        // the deliverer to record the concurrency peak it observes,
        // then dispatch to 8 recipients -- the peak MUST NOT exceed
        // the configured 2.
        use tokio::time::sleep;

        let mut actors = std::collections::HashMap::new();
        for n in 0..8 {
            let url = format!("https://example.com/users/a{n}");
            actors.insert(
                url.clone(),
                actor_with_inbox(&url, &format!("https://example.com/inbox/{n}")),
            );
        }
        let observer = Arc::new(ConcurrencyObserver {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });

        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .delivery_concurrency(2)
            .build()
            .shared();
        let outbox = Outbox::new(
            ArcObserver(Arc::clone(&observer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            cfg,
        );

        let recipients: Vec<Url> = (0..8)
            .map(|n| format!("https://example.com/users/a{n}").parse().unwrap())
            .collect();
        let report = outbox
            .dispatch(
                json!({ "id": "https://sender.example/a/fanout", "type": "Create" }),
                &recipients,
            )
            .await;
        assert_eq!(report.enqueued, 8);

        // Wait until all 8 deliveries have completed. 8 * 30 ms
        // with a concurrency of 2 takes roughly 120 ms; sleep
        // generously.
        sleep(Duration::from_millis(600)).await;
        let peak = observer.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 2,
            "observed concurrent deliveries {peak} exceeds the configured cap of 2",
        );
        assert!(
            peak >= 2,
            "expected the cap to actually be exercised; observed peak {peak}",
        );
    }
}
