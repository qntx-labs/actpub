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
//! best-effort: `dispatch` resolves the recipients and awaits a slot
//! in the bounded delivery channel, then returns; retries happen
//! entirely in the background.
//!
//! # Resource model
//!
//! Each [`Outbox`] holds **one** background tokio task driving its
//! retry loop, owning a **bounded** channel of pending deliveries
//! (sized by [`FederationConfig::delivery_queue_capacity`]).
//! Producers calling [`Outbox::enqueue`] / [`Outbox::dispatch`] wait
//! for a slot when the queue is full — this is the
//! end-to-end backpressure boundary that keeps a misbehaving caller
//! from growing the queue without limit.
//!
//! Cloning an [`Outbox`] shares the same background worker, channel,
//! and shutdown coordinator. When the **last** clone drops, the
//! shutdown coordinator aborts the worker; explicit graceful
//! shutdown is available via [`Outbox::graceful_shutdown`] which
//! stops admission and awaits the worker task within a deadline.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures::StreamExt;
use futures::stream;
use serde_json::Value;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
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
    /// Bounded channel sender. Held OUTSIDE `Inner` so the last
    /// [`Outbox`] clone dropping closes every producer handle —
    /// otherwise `Inner`'s own `Sender` clone would keep the
    /// channel alive and strand the worker in `rx.recv().await`
    /// forever. The worker holds its own clone of this sender
    /// (for retry enqueue) but under a [`Weak`] reference so it
    /// cannot keep [`Inner`] alive past user intent.
    tx: mpsc::Sender<DeliveryJob>,
    /// Shutdown coordinator shared by every [`Outbox`] clone.
    /// Its [`Drop`] runs exactly when the Arc's strong count hits
    /// zero — i.e. when the last clone goes away — and both
    /// notifies the worker and aborts its handle as a belt-and-
    /// braces fallback. See [`Self::graceful_shutdown`] for the
    /// explicit, non-panicking path.
    shutdown: Arc<ShutdownHandle>,
}

impl<D, F> Clone for Outbox<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            tx: self.tx.clone(),
            shutdown: Arc::clone(&self.shutdown),
        }
    }
}

impl<D, F> std::fmt::Debug for Outbox<D, F>
where
    D: Deliverer,
    F: Fetcher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `D` and `F` may not implement `Debug`, and we deliberately
        // do not want to surface the signing config / semaphore
        // state; `finish_non_exhaustive` signals that.
        f.debug_struct("Outbox")
            .field("retry_policy", &self.inner.retry_policy)
            .field("queue_capacity", &self.tx.max_capacity())
            .finish_non_exhaustive()
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
    /// Shared runtime configuration. Held on the outbox so
    /// [`Outbox::resolve_inboxes`] can apply the configured
    /// [`UrlPolicy`](crate::UrlPolicy) to every picked inbox URL
    /// *before* it enters the retry queue — this is the admission
    /// gate that keeps `sharedInbox` URLs served by a malicious
    /// actor from turning the outbox into an SSRF amplifier.
    ///
    /// The per-request budget ([`FederationConfig::http_fetch_limit`])
    /// and queue capacity ([`FederationConfig::delivery_queue_capacity`])
    /// are accessed through this field; no derived scalar is
    /// cached on [`Inner`] so the config stays the single source
    /// of truth at runtime.
    config: Arc<FederationConfig>,
    /// Global ceiling on concurrent deliveries. Every call to
    /// `run_one` acquires one permit before touching the network,
    /// so a fan-out to 10 000 inboxes cannot instantly pin 10 000
    /// TCP sockets. Sized by
    /// [`FederationConfig::delivery_concurrency`].
    delivery_semaphore: Arc<Semaphore>,
}

/// Shutdown coordinator for the outbox worker.
///
/// Held behind an `Arc<ShutdownHandle>` by every [`Outbox`] clone
/// **and nobody else**. The worker task holds separate
/// [`Arc<Notify>`] / [`Arc<AtomicBool>`] clones of the signalling
/// primitives plus a [`Weak<Inner>`]; it does **not** hold an
/// [`Arc<ShutdownHandle>`], so the strong count of the handle
/// exactly tracks the number of live [`Outbox`] clones. When that
/// count reaches zero, [`Drop`] fires and signals the worker to
/// exit.
struct ShutdownHandle {
    /// Wake-up signal for the worker's `select!`. Shared with the
    /// worker as [`Arc<Notify>`] so both sides refer to the same
    /// instance. We emit signals via [`Notify::notify_one`], which
    /// **stores a permit** when no waiter is currently parked on
    /// [`Notify::notified`] — this is what closes the race where
    /// a caller signals shutdown before the worker has yet
    /// reached its `select!` arm.
    stop: Arc<Notify>,
    /// Broadcast "worker has fully exited" signal. Used by
    /// [`Outbox::graceful_shutdown`] callers that do **not** own
    /// the worker `JoinHandle` (e.g. a second or third concurrent
    /// caller when the first has been cancelled) so they still
    /// get a true exit confirmation rather than an immediate
    /// misleading `Ok(())`.
    terminated: Arc<Notify>,
    /// Companion level-triggered flag for [`Self::terminated`].
    /// `Notify::notify_waiters` wakes only *currently-parked*
    /// waiters and stores no permit, which loses signals racing
    /// past the waiter's creation point. A caller observing this
    /// flag set to `true` knows the worker has exited even if it
    /// missed the notify edge. Readers MUST double-check the flag
    /// *after* creating the `Notified` future, per the standard
    /// Tokio Notify idiom.
    terminated_flag: Arc<AtomicBool>,
    /// Worker [`JoinHandle`]. Taken by [`Drop`] as a belt-and-
    /// braces `abort` and by [`Outbox::graceful_shutdown`] to
    /// `await` a clean exit with a deadline.
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        // First: unblock the worker so it stops accepting jobs and
        // exits. `notify_one` stores a permit if the worker is not
        // currently parked, so the signal is never lost.
        self.stop.notify_one();
        // Second: abort as a belt-and-braces safeguard. `Drop` is a
        // *synchronous* path and cannot `.await` a drain, so we
        // deliberately fall back to hard cancellation here — the
        // `JoinSet` of in-flight deliveries inside the worker task
        // is dropped along with it, aborting every pending POST.
        // Callers that want drain semantics must use
        // [`Outbox::graceful_shutdown`] instead.
        if let Ok(mut slot) = self.handle.lock()
            && let Some(h) = slot.take()
        {
            h.abort();
        }
    }
}

#[derive(Debug)]
struct DeliveryJob {
    /// Activity JSON shared between fan-out recipients. The outer
    /// [`Arc`] lets one `dispatch(..., N_recipients)` produce N
    /// cheap clones instead of N full JSON deep-copies.
    activity: Arc<Value>,
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
        // Bounded channel sized by config. `mpsc::channel` panics
        // on capacity 0; clamp to at least 1 so a misconfigured
        // build still makes serialised forward progress.
        let (tx, rx) = mpsc::channel::<DeliveryJob>(config.delivery_queue_capacity.max(1));
        // `Semaphore::new(0)` would deadlock every delivery; same
        // clamp rationale as above.
        let delivery_semaphore = Arc::new(Semaphore::new(config.delivery_concurrency.max(1)));
        let inner = Arc::new(Inner {
            deliverer,
            fetcher,
            retry_policy,
            config,
            delivery_semaphore,
        });
        // Shutdown signalling primitives are stored both in
        // `ShutdownHandle` (reached by every `Outbox` clone through
        // the `Arc<ShutdownHandle>`) and in the worker task
        // directly via separate `Arc` clones. Keeping the worker's
        // references independent of `ShutdownHandle` is what lets
        // the shutdown Arc's strong count reach zero when the last
        // `Outbox` clone drops.
        let stop = Arc::new(Notify::new());
        let terminated = Arc::new(Notify::new());
        let terminated_flag = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(ShutdownHandle {
            stop: Arc::clone(&stop),
            terminated: Arc::clone(&terminated),
            terminated_flag: Arc::clone(&terminated_flag),
            handle: Mutex::new(None),
        });
        // Worker holds a `Weak<Inner>` so it cannot keep `Inner`
        // alive past the last [`Outbox`] clone, plus its own
        // clones of the three shutdown-signalling primitives.
        let handle = spawn_worker(
            Arc::downgrade(&inner),
            rx,
            stop,
            terminated,
            terminated_flag,
        );
        if let Ok(mut slot) = shutdown.handle.lock() {
            *slot = Some(handle);
        }
        Self {
            inner,
            tx,
            shutdown,
        }
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
    ///
    /// # Backpressure
    ///
    /// Enqueueing is `.await`-blocking: if the delivery channel is
    /// already at [`FederationConfig::delivery_queue_capacity`],
    /// `dispatch` pauses until the worker drains a slot. This
    /// prevents a producer from growing the queue without bound.
    pub async fn dispatch(&self, activity: Value, recipient_actors: &[Url]) -> DispatchReport {
        let resolution = self.resolve_inboxes(recipient_actors).await;
        // W3C ActivityPub §6 MUST: the server MUST remove `bto` and
        // `bcc` before outgoing delivery so a blind-carbon-copied
        // actor's identity is never leaked to the public or the
        // non-blind recipients. Strip once here — before the
        // [`Arc`] is built — so every downstream consumer
        // (serialisation, HTTP signing, retry) sees the already
        // cleansed payload.
        let mut activity = activity;
        strip_private_recipients(&mut activity);
        // Clone the activity JSON **once** into an [`Arc`] and hand
        // every recipient a cheap Arc clone instead of N deep-copies.
        let activity = Arc::new(activity);
        let mut enqueued: usize = 0;
        let mut errors = resolution.errors;
        for inbox in resolution.inboxes {
            // Keep an inbox handle outside the match: any error
            // returned by `enqueue_arc` is attributed to THIS
            // recipient regardless of what fields the variant
            // carries. The clone is the sole extra allocation a
            // failed enqueue costs; the (far more common) success
            // path takes `inbox` by value into `enqueue_arc`.
            let inbox_for_error = inbox.clone();
            match self.enqueue_arc(Arc::clone(&activity), inbox).await {
                Ok(()) => enqueued += 1,
                Err(err) => errors.push((inbox_for_error, err)),
            }
        }
        DispatchReport { enqueued, errors }
    }

    /// Enqueues a single delivery job, awaiting a channel slot if
    /// the queue is full.
    ///
    /// Bypasses the actor-to-inbox resolution step; suitable for
    /// callers that already know the target inbox URL (e.g.
    /// sharedInbox-aware mailer middleware). Wraps the activity in
    /// an [`Arc`] before handing it to the worker; prefer the
    /// [`Arc`]-typed [`Self::enqueue_arc`] if you already have one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutboxShutdown`] if the worker has already
    /// exited and the delivery channel has been closed. Callers may
    /// persist the activity for later retry.
    pub async fn enqueue(&self, activity: Value, inbox: Url) -> Result<(), Error> {
        // W3C §6 MUST: strip `bto`/`bcc` before the payload leaves
        // the server. Single-recipient `enqueue` is also an outgoing
        // delivery path, so the invariant has to hold here too.
        let mut activity = activity;
        strip_private_recipients(&mut activity);
        self.enqueue_arc(Arc::new(activity), inbox).await
    }

    /// [`Arc`]-aware variant of [`Self::enqueue`]. Prefer this when
    /// fanning the same activity out to N sibling inboxes — it
    /// avoids an N-way deep-copy of the JSON.
    ///
    /// # Contract
    ///
    /// **Callers MUST strip `bto` / `bcc` from the activity before
    /// wrapping it in the [`Arc`].** W3C `ActivityPub` §6 requires
    /// those blind-recipient fields to be removed before any
    /// outgoing delivery; this low-level entry point does not touch
    /// the payload so that a dispatching caller can build one
    /// [`Arc`] and fan it out to N inboxes without a `make_mut`
    /// per recipient. Use [`Self::dispatch`] or [`Self::enqueue`]
    /// if you have not already stripped the fields — they handle
    /// the stripping for you.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutboxShutdown`] if the delivery channel
    /// has been closed by a prior
    /// [`Self::graceful_shutdown`] (or by a
    /// [`Drop`]-based hard abort). The original `inbox` URL is
    /// preserved inside the error so callers can persist the job
    /// for manual retry.
    pub async fn enqueue_arc(&self, activity: Arc<Value>, inbox: Url) -> Result<(), Error> {
        // `send` fails only once the worker is gone and the
        // channel has been closed — all graceful shutdown paths
        // let any remaining producer see a closed channel rather
        // than hanging forever.
        if let Err(send_err) = self
            .tx
            .send(DeliveryJob {
                activity,
                inbox: inbox.clone(),
                attempt: 0,
            })
            .await
        {
            // Reconstruct the rejected inbox URL from the returned
            // job so the diagnostic is accurate even if we ever
            // grow the `DeliveryJob` shape.
            let rejected = send_err.0.inbox;
            tracing::error!(
                target: "actpub::outbox",
                %rejected,
                "outbox worker is gone; dropping delivery job",
            );
            return Err(Error::OutboxShutdown { inbox: rejected });
        }
        Ok(())
    }

    /// Signals the worker to stop accepting new jobs and awaits
    /// its exit within `timeout`.
    ///
    /// Does **not** consume `self` — every [`Outbox`] clone can
    /// initiate shutdown; the first call wins and subsequent calls
    /// become no-ops. After this method returns, the worker is
    /// guaranteed to have exited (or been timed out) and the
    /// channel is closed; any later [`Self::enqueue`] returns
    /// [`Error::OutboxShutdown`].
    ///
    /// Returns `Ok(())` on a clean exit, `Err` if the deadline
    /// elapsed while the worker was still running — callers MAY
    /// retry with a larger deadline or fall through to
    /// [`Drop`]-based abort.
    ///
    /// # Phase-3 delay semantics
    ///
    /// `timeout` bounds **only this caller's `await`**; the worker
    /// task itself does NOT observe the value. Once the stop
    /// signal fires, the worker enters a three-phase epilogue:
    ///
    /// 1. **Accept-cutoff:** stop accepting new jobs and
    ///    `rx.close()` the delivery channel.
    /// 2. **Drain:** spawn a [`run_one`] task for every job still
    ///    buffered in the channel.
    /// 3. **Join:** await every in-flight [`run_one`], **including
    ///    its in-task retry loop**.
    ///
    /// Because retries are implemented as a [`run_one`]-local
    /// `loop { sleep; deliver; }` rather than a re-queue onto the
    /// channel, a delivery in the middle of a back-off contributes
    /// its full `RetryPolicy::delay_before_retry(attempt)` to the
    /// phase-3 wait. Under [`RetryPolicy::mastodon`] (8 retries,
    /// exponential) this can exceed **10 minutes**.
    ///
    /// If `timeout` elapses before the worker's phase-3 join
    /// completes, `graceful_shutdown` returns `Err(Elapsed)` but
    /// the worker **keeps running**. Two follow-ups are possible:
    ///
    /// - call `graceful_shutdown` again with a larger deadline to
    ///   block until the worker really finishes, or
    /// - drop the last [`Outbox`] clone to invoke the
    ///   [`Drop`]-based `JoinHandle::abort` path, which forcibly
    ///   kills in-flight deliveries (any HTTP request currently
    ///   on the wire is lost).
    ///
    /// # Errors
    ///
    /// Returns [`tokio::time::error::Elapsed`] when the worker
    /// does not finish before `timeout`.
    pub async fn graceful_shutdown(
        &self,
        timeout: Duration,
    ) -> Result<(), tokio::time::error::Elapsed> {
        // Ask the worker to stop admitting NEW jobs and start
        // draining. `notify_one` stores a permit if no waiter is
        // currently parked, so the signal is retained even when
        // this call races with the worker's first loop iteration.
        self.shutdown.stop.notify_one();

        // Resolution strategy:
        //   - if we are the first caller, take the `JoinHandle` and
        //     `.await` it directly;
        //   - if another caller (possibly cancelled) has already
        //     taken the handle, we fall through to the broadcast
        //     `terminated` signal so a second caller still blocks
        //     until the worker is really gone.
        let handle_opt = self
            .shutdown
            .handle
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());

        let terminated = Arc::clone(&self.shutdown.terminated);
        let terminated_flag = Arc::clone(&self.shutdown.terminated_flag);

        let wait = async move {
            if let Some(handle) = handle_opt {
                // Worker task's own JoinError (panic / cancel) is
                // swallowed intentionally: graceful shutdown is a
                // best-effort cleanup signal, not a reliability
                // contract for user-supplied deliverers.
                drop(handle.await);
                return;
            }
            wait_for_terminated(&terminated, &terminated_flag).await;
        };

        tokio::time::timeout(timeout, wait).await?;
        Ok(())
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
    ///
    /// Resolution runs with a concurrency of
    /// [`FederationConfig::resolve_concurrency`] via
    /// [`futures::stream::StreamExt::buffer_unordered`]. A 1 000-
    /// follower fan-out that would take 8+ minutes serialised
    /// completes in seconds at the default 32-way parallelism,
    /// matching Mastodon-class latency.
    pub async fn resolve_inboxes(&self, recipient_actors: &[Url]) -> InboxResolution {
        let concurrency = self.inner.config.resolve_concurrency.max(1);
        let results: Vec<(Url, Result<Url, Error>)> =
            stream::iter(recipient_actors.iter().cloned())
                .map(|actor| async move {
                    let result = self.resolve_one(&actor).await;
                    (actor, result)
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;

        let mut resolution = InboxResolution::default();
        for (actor, result) in results {
            match result {
                Ok(inbox) => {
                    resolution.inboxes.insert(inbox);
                }
                Err(e) => resolution.errors.push((actor, e)),
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
        let ctx = FetchContext::new(self.inner.config.http_fetch_limit);
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

/// Blocks until the worker's phase-3 epilogue has set
/// `terminated_flag` to `true`. Uses the standard
/// `AtomicBool` + `Notify` double-check idiom so a worker that
/// sets the flag between our load and the `notified()` future
/// creation cannot be missed.
async fn wait_for_terminated(terminated: &Notify, terminated_flag: &AtomicBool) {
    loop {
        if terminated_flag.load(Ordering::Acquire) {
            return;
        }
        let notified = terminated.notified();
        if terminated_flag.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

fn spawn_worker<D, F>(
    inner: Weak<Inner<D, F>>,
    mut rx: mpsc::Receiver<DeliveryJob>,
    stop: Arc<Notify>,
    terminated: Arc<Notify>,
    terminated_flag: Arc<AtomicBool>,
) -> JoinHandle<()>
where
    D: Deliverer + 'static,
    F: Fetcher + 'static,
{
    tokio::spawn(async move {
        // In-flight deliveries are tracked in a `JoinSet` instead
        // of being fire-and-forget. This is what gives
        // `Outbox::graceful_shutdown(timeout)` true drain
        // semantics: when `stop` is signalled we finish the
        // already-queued jobs AND wait for every spawned
        // `run_one` to complete before exiting.
        //
        // Retry is handled **inside** `run_one` as a tight
        // in-task loop (not by re-queueing onto the channel),
        // so a retry storm cannot interact with shutdown's
        // `rx.close()` to silently drop pending attempts, and
        // cannot livelock when `delivery_queue_capacity` is set
        // below `delivery_concurrency`.
        let mut in_flight = JoinSet::<()>::new();

        // Phase 1 — accept new jobs.
        //
        // `biased` so the stop signal ALWAYS wins over a queued
        // job when both are ready; otherwise the runtime could
        // starve the stop signal under a busy queue. Finished
        // `in_flight` tasks are reaped opportunistically so the
        // `JoinSet` cannot grow unbounded while the worker is
        // under steady-state load.
        loop {
            tokio::select! {
                biased;
                () = stop.notified() => {
                    // Close the receiving half so future `send()`
                    // calls on any outstanding sender fail fast
                    // instead of silently appearing to succeed
                    // while we are about to stop consuming.
                    // Already-buffered jobs remain retrievable
                    // via subsequent `rx.recv()` calls — that's
                    // precisely the drain contract we rely on in
                    // phase 2 below.
                    rx.close();
                    break;
                }
                maybe_job = rx.recv() => match maybe_job {
                    Some(job) => {
                        let Some(inner) = inner.upgrade() else { break };
                        in_flight.spawn(async move {
                            run_one(inner, job).await;
                        });
                    }
                    None => break, // all senders dropped
                },
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => {}
            }
        }

        // Phase 2 — drain already-enqueued jobs.
        //
        // `rx.close()` ensures no new job can be added, so this
        // loop terminates as soon as the buffered queue is empty.
        while let Some(job) = rx.recv().await {
            let Some(inner) = inner.upgrade() else { break };
            in_flight.spawn(async move {
                run_one(inner, job).await;
            });
        }

        // Phase 3 — wait for every in-flight delivery to finish,
        // **including their retry loops**. This is the key
        // distinction from the old channel-based retry design:
        // a `run_one` that is currently backing off between
        // attempts is still a live `JoinSet` entry, so the
        // worker does not exit until every retry has either
        // succeeded, exhausted the policy, or been aborted by
        // a hard `abort()` from the outer `Drop` path.
        //
        // Failures inside `run_one` are already logged by that
        // function; we only consume the `JoinError`/`()` outputs
        // so the `JoinSet` empties cleanly.
        while in_flight.join_next().await.is_some() {}

        // Broadcast completion to any caller parked inside a
        // second `graceful_shutdown`. Order matters: set the
        // flag FIRST so a late observer that only sees
        // `terminated_flag == true` never misses the exit
        // even if it arrives after `notify_waiters()` fires.
        terminated_flag.store(true, Ordering::Release);
        terminated.notify_waiters();
    })
}

async fn run_one<D, F>(inner: Arc<Inner<D, F>>, job: DeliveryJob)
where
    D: Deliverer,
    F: Fetcher,
{
    let DeliveryJob {
        activity,
        inbox,
        mut attempt,
    } = job;

    // Retry loop is fully **in-task**: a failed delivery does
    // not re-enter the delivery channel, so:
    //
    // 1. shutdown's `rx.close()` cannot silently discard a
    //    pending retry — this task is tracked in the worker's
    //    `JoinSet` and is therefore awaited by phase 3;
    // 2. `delivery_queue_capacity < delivery_concurrency`
    //    cannot livelock, because a run_one that is backing
    //    off between attempts releases its permit first and
    //    never parks on `channel.send`;
    // 3. a retry storm is still bounded: every retry acquires
    //    a permit from `delivery_semaphore`, so the steady-state
    //    concurrency ceiling remains `delivery_concurrency`.
    loop {
        // Back off BEFORE touching the permit. Retry sleeps can
        // span tens of minutes under `RetryPolicy::mastodon`,
        // and holding a permit across them would drain
        // `delivery_concurrency` to zero under even a modest
        // stream of transient failures (P0-R2 invariant).
        let delay = inner.retry_policy.delay_before_retry(attempt);
        if delay > Duration::ZERO {
            tokio::time::sleep(delay).await;
        }

        // Acquire one permit only for the actual deliver call. A
        // `Semaphore::close` during shutdown surfaces here; we
        // bail out instead of holding the job forever.
        let Ok(permit) = Arc::clone(&inner.delivery_semaphore).acquire_owned().await else {
            tracing::error!(
                target: "actpub::outbox",
                "delivery semaphore closed; dropping in-flight job",
            );
            return;
        };

        let err = match inner.deliverer.deliver(&activity, &inbox).await {
            Ok(()) => {
                tracing::debug!(target: "actpub::outbox", attempt, %inbox, "delivered");
                return;
            }
            Err(err) => err,
        };

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
            return;
        }
        tracing::warn!(
            target: "actpub::outbox",
            attempt = next,
            max = inner.retry_policy.max_retries,
            %inbox,
            %err,
            "delivery failed; retrying",
        );

        // Release the permit BEFORE the next back-off so other
        // jobs keep making progress while this task sleeps.
        drop(permit);
        attempt = next;
    }
}

/// Removes `bto` and `bcc` from the top-level activity and, if the
/// activity carries an inline `object`, from that nested object too.
///
/// W3C `ActivityPub` [§6 Delivery](https://www.w3.org/TR/activitypub/#delivery)
/// is a **MUST**:
///
/// > The server MUST remove the `bto` and/or `bcc` properties, if
/// > they exist, from the outgoing object.
///
/// The strip is confined to the two well-known top-level slots
/// (activity and inline `object`); deeper nested objects are not
/// traversed because a legitimate AS2.0 activity only carries
/// blind-recipient lists at those two levels, and a deeper traversal
/// risks mangling application-defined sub-objects that happen to use
/// the field names for unrelated purposes.
fn strip_private_recipients(activity: &mut Value) {
    if let Value::Object(map) = activity {
        map.remove("bto");
        map.remove("bcc");
        if let Some(Value::Object(inline_object)) = map.get_mut("object") {
            inline_object.remove("bto");
            inline_object.remove("bcc");
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

    /// Poll-wait until `counter.load(SeqCst) >= target` or the
    /// deadline elapses. Used by the graceful-shutdown and drain
    /// tests to block until the `GatedDeliverer` has actually
    /// entered `deliver()` on every enqueued job before the test
    /// proceeds to signal shutdown — the fixed-sleep alternative
    /// is flaky under CI scheduler pressure.
    async fn wait_until_counter(counter: &AtomicUsize, target: usize, deadline: Duration) {
        let deadline_at = std::time::Instant::now() + deadline;
        loop {
            if counter.load(Ordering::SeqCst) >= target {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline_at,
                "counter did not reach {target} within {deadline:?}",
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Poll-wait until `deliverer.calls.len() >= expected` or the
    /// deadline elapses. Replaces fixed `sleep(Duration::from_millis(50))`
    /// synchronisation in tests — under CI scheduler pressure the
    /// 50 ms sleep often fired before the worker had even been
    /// polled once, causing flaky failures.
    ///
    /// The loop polls at 5 ms granularity so a correct test
    /// typically completes in under 10 ms while a regression
    /// surfaces as a clear timeout rather than a silent wrong
    /// count.
    async fn wait_for_calls(deliverer: &RecordingDeliverer, expected: usize, deadline: Duration) {
        let deadline_at = std::time::Instant::now() + deadline;
        loop {
            let len = deliverer.calls.lock().unwrap().len();
            if len >= expected {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline_at,
                "expected >= {expected} deliver calls within {deadline:?}, got {len}",
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
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
        #[allow(
            unknown_lints,
            clippy::unused_async_trait_impl,
            reason = "trait definition requires async but mock implementation has no await"
        )]
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
        #[allow(
            unknown_lints,
            clippy::unused_async_trait_impl,
            reason = "trait definition requires async but mock implementation has no await"
        )]
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

        // Wait for the worker to drain (event-driven, not fixed
        // sleep — see `wait_for_calls` rationale).
        wait_for_calls(&deliverer, 1, Duration::from_secs(2)).await;
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

        // for_tests() schedule: 0, 10, 20, 40 ms → total <100 ms
        // for exactly 3 attempts. Wait for the 3 expected calls,
        // then give the scheduler one more tick to surface any
        // erroneous 4th call before asserting.
        wait_for_calls(&deliverer, 3, Duration::from_secs(2)).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
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
    async fn resolve_rejects_shared_inbox_at_loopback_ip_literal() {
        // P2-N21 deepens the P0-9 regression coverage: the existing
        // loopback test uses the hostname `localhost`, but a
        // malicious actor could equally well advertise a raw IP
        // literal like `http://127.0.0.1:8080/inbox`, which walks a
        // different branch of `UrlPolicy` (hostname-parsing vs
        // IP-address-parsing). Both branches MUST refuse the URL.
        //
        // Without this test, a future `UrlPolicy` refactor that
        // only tightened the hostname path would silently regress
        // the IP-literal path.
        let attacker_url = "https://attacker.example/users/mallory";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            attacker_url.into(),
            actor_with_shared_inbox(
                attacker_url,
                "https://attacker.example/users/mallory/inbox",
                "http://127.0.0.1:8080/inbox",
            ),
        );
        // Production-shape config: strict default `UrlPolicy`.
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
                json!({ "id": "https://sender.example/a/ip-poison", "type": "Create" }),
                &[attacker_url.parse().unwrap()],
            )
            .await;
        assert_eq!(
            report.enqueued, 0,
            "IP-literal loopback sharedInbox must not be enqueued",
        );
        assert_eq!(report.errors.len(), 1);
        let (url, err) = &report.errors[0];
        assert_eq!(url.as_str(), attacker_url);
        assert!(
            matches!(err, Error::PolicyViolation { .. }),
            "expected PolicyViolation for loopback IP, got {err:?}",
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

    /// Deliverer that succeeds on some inboxes and fails forever on
    /// others, notifying the test when the first success completes.
    /// Used by the P0-R2 regression test to distinguish the
    /// "retry-sleep holds permit" bug from the fixed behaviour.
    struct SplitDeliverer {
        ok_delivered: Notify,
        ok_deliver_at: Mutex<Option<std::time::Instant>>,
    }

    impl SplitDeliverer {
        fn new() -> Self {
            Self {
                ok_delivered: Notify::new(),
                ok_deliver_at: Mutex::new(None),
            }
        }
    }

    impl Deliverer for SplitDeliverer {
        #[allow(
            unknown_lints,
            clippy::unused_async_trait_impl,
            reason = "trait definition requires async but mock implementation has no await"
        )]
        async fn deliver(&self, _activity: &Value, inbox: &Url) -> Result<(), Error> {
            if inbox.as_str().contains("fail") {
                return Err(Error::Status {
                    url: inbox.clone(),
                    status: 503,
                });
            }
            *self.ok_deliver_at.lock().unwrap() = Some(std::time::Instant::now());
            self.ok_delivered.notify_waiters();
            Ok(())
        }
    }

    struct ArcSplit(Arc<SplitDeliverer>);
    impl Deliverer for ArcSplit {
        async fn deliver(&self, a: &Value, i: &Url) -> Result<(), Error> {
            self.0.deliver(a, i).await
        }
    }

    #[tokio::test]
    async fn retry_sleep_does_not_hold_delivery_permit() {
        // P0-R2 regression: a delivery that enters retry backoff
        // MUST release its semaphore permit across the sleep,
        // otherwise a trickle of transient failures would drain
        // `delivery_concurrency` to zero for the full backoff
        // window (5+ minutes under `RetryPolicy::mastodon`).
        //
        // Setup: `delivery_concurrency = 1`, retry delay = 400 ms.
        // We dispatch a job that fails forever, wait 50 ms for its
        // attempt-0 failure and the enqueue of attempt-1, then
        // dispatch a second job that succeeds. With the permit
        // correctly released during the sleep, the second job
        // delivers ~immediately. With the old bug (permit held),
        // it would wait up to ~400 ms.
        //
        // Assertion threshold = 200 ms: comfortably below 400 ms
        // but generous enough to tolerate scheduler noise on slow
        // CI.
        use std::time::Instant;

        let fail_actor = "https://example.com/users/fail";
        let ok_actor = "https://example.com/users/ok";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            fail_actor.to_owned(),
            actor_with_inbox(fail_actor, "https://example.com/fail-inbox"),
        );
        actors.insert(
            ok_actor.to_owned(),
            actor_with_inbox(ok_actor, "https://example.com/ok-inbox"),
        );

        let deliverer = Arc::new(SplitDeliverer::new());
        let policy = RetryPolicy {
            initial_delay: Duration::from_millis(400),
            max_delay: Duration::from_millis(400),
            multiplier: 1.0,
            max_retries: 5,
            // Deterministic delays keep the wall-clock-oriented
            // assertions below reproducible; jitter is exercised
            // by dedicated tests in `retry.rs`.
            jitter_fraction: 0.0,
        };
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .delivery_concurrency(1)
            .build()
            .shared();
        let outbox = Outbox::new(
            ArcSplit(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            policy,
            cfg,
        );

        // Enqueue the failing job first; its attempt-0 deliver
        // fails immediately with no network, so within 50 ms the
        // retry for attempt-1 is queued and the worker has entered
        // its 400 ms sleep.
        outbox
            .dispatch(
                json!({ "id": "https://sender.example/a/fail", "type": "Create" }),
                &[fail_actor.parse().unwrap()],
            )
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Measure ok latency from this point: if the bug is back,
        // the ok deliver blocks on the permit until the 400 ms
        // retry sleep elapses.
        let t_dispatch = Instant::now();
        outbox
            .dispatch(
                json!({ "id": "https://sender.example/a/ok", "type": "Create" }),
                &[ok_actor.parse().unwrap()],
            )
            .await;

        tokio::time::timeout(
            Duration::from_millis(350),
            deliverer.ok_delivered.notified(),
        )
        .await
        .expect("ok deliver must complete before the 400 ms retry sleep elapses");
        let ok_latency = deliverer
            .ok_deliver_at
            .lock()
            .unwrap()
            .expect("SplitDeliverer recorded the ok timestamp")
            - t_dispatch;
        assert!(
            ok_latency < Duration::from_millis(200),
            "ok deliver took {ok_latency:?}; suggests the retry sleep is \
             still holding the delivery permit",
        );
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

    /// Deliverer that parks each call on a per-call [`Notify`] so
    /// the test can hold jobs in-flight for as long as it likes.
    /// Used by the backpressure and graceful-shutdown tests to
    /// gate exactly when a deliver returns.
    struct GatedDeliverer {
        release: Arc<Notify>,
        started: Arc<AtomicUsize>,
        finished: Arc<AtomicUsize>,
    }

    impl Deliverer for GatedDeliverer {
        async fn deliver(&self, _a: &Value, _i: &Url) -> Result<(), Error> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            self.finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ArcGated(Arc<GatedDeliverer>);
    impl Deliverer for ArcGated {
        async fn deliver(&self, a: &Value, i: &Url) -> Result<(), Error> {
            self.0.deliver(a, i).await
        }
    }

    #[tokio::test]
    async fn outbox_uses_bounded_channel_sized_by_config() {
        // P1-N8 regression guard: the delivery channel MUST be a
        // bounded `mpsc::channel` sized by
        // `FederationConfig::delivery_queue_capacity`, not the
        // unbounded variant. We read `Sender::max_capacity` — a
        // method that **only exists on the bounded `Sender`** —
        // so any future revert to `unbounded_channel` would stop
        // compiling, and any mis-wired capacity would fail the
        // numeric assertion.
        //
        // Observing actual send-side backpressure in a test is
        // unreliable: the worker drains `rx` essentially as fast
        // as producers fill it, so a deliberately over-subscribed
        // burst is almost always absorbed without the sender
        // parking. This compile-time-plus-configuration check is
        // the robust substitute.
        let cap = 7_usize; // arbitrary distinct value
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .delivery_queue_capacity(cap)
            .build()
            .shared();
        let outbox = Outbox::new(
            ArcDeliverer(Arc::new(RecordingDeliverer::new(0))),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            cfg,
        );
        assert_eq!(outbox.tx.max_capacity(), cap);
    }

    #[tokio::test]
    async fn graceful_shutdown_exits_worker_cleanly() {
        // P1-N7 regression: `graceful_shutdown` must stop the
        // worker within the supplied deadline.
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let deliverer = Arc::new(GatedDeliverer {
            release: Arc::clone(&release),
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        });
        let outbox = Outbox::new(
            ArcGated(Arc::clone(&deliverer)),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            test_config(),
        );

        // Idle worker -- graceful_shutdown just returns quickly.
        outbox
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .expect("idle worker must exit within the deadline");

        // After graceful_shutdown the channel is closed; further
        // enqueue calls must surface `Error::OutboxShutdown`
        // (previously a silent tracing-only log).
        let post_shutdown = outbox
            .enqueue(
                json!({ "id": "after-shutdown", "type": "Create" }),
                "https://example.com/inbox/a".parse().unwrap(),
            )
            .await;
        assert!(
            matches!(post_shutdown, Err(Error::OutboxShutdown { .. })),
            "enqueue after graceful_shutdown must return OutboxShutdown, got {post_shutdown:?}",
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_drains_queued_jobs_before_exit() {
        // P1-N15 regression: `graceful_shutdown` MUST drain
        // already-queued jobs before exiting, not hard-kill them.
        //
        // Prior to the phase-1/2/3 worker refactor, `stop.notified()`
        // in the `biased` select immediately broke the loop the
        // instant shutdown was signalled — any jobs sitting in the
        // channel buffer (and any in-flight `run_one` that had
        // been spawned) were silently dropped. On a 1 000-follower
        // dispatch where the caller fires `graceful_shutdown(30s)`
        // alongside a SIGTERM handler, that translates into
        // hundreds of unsent activities.
        //
        // The fix is a three-phase worker:
        //   Phase 1: accept new jobs, honour `stop` (on stop, close rx).
        //   Phase 2: drain every remaining `rx.recv()` into `in_flight`.
        //   Phase 3: `join_next` all in-flight deliveries.
        // This test enqueues 5 gated jobs, calls `graceful_shutdown`
        // with a deadline large enough for every job to complete,
        // and asserts that all 5 `deliver` calls actually ran.
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let deliverer = Arc::new(GatedDeliverer {
            release: Arc::clone(&release),
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        });
        // `delivery_concurrency = 5` so every enqueued job starts
        // its `deliver` body and parks on `release.notified()` in
        // parallel — the test controls exactly when each finishes.
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .delivery_concurrency(5)
            .build()
            .shared();
        let outbox = Outbox::new(
            ArcGated(Arc::clone(&deliverer)),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            cfg,
        );

        for i in 0..5 {
            outbox
                .enqueue(
                    json!({ "id": format!("job-{i}"), "type": "Create" }),
                    format!("https://example.com/inbox/{i}").parse().unwrap(),
                )
                .await
                .expect("pre-shutdown enqueue must succeed");
        }
        // Wait until all 5 deliveries have actually entered
        // `deliver()` so we KNOW they are in flight, not still
        // sitting as unconsumed `DeliveryJob`s in the channel.
        wait_until_counter(&started, 5, Duration::from_secs(2)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            5,
            "all 5 jobs must have started before shutdown is requested",
        );

        // Request shutdown and *concurrently* release the gate so
        // the in-flight deliveries can finish. A correctly-draining
        // worker awaits `join_next` on the `JoinSet`, so it only
        // exits after all 5 `finished` counters have incremented.
        let shutdown_fut = outbox.graceful_shutdown(Duration::from_secs(5));
        let release_fut = async {
            // Small delay to ensure shutdown has entered the
            // drain/join phase before we flip the gate; releasing
            // too early would let the pre-shutdown path complete
            // and miss the regression this test guards.
            tokio::time::sleep(Duration::from_millis(20)).await;
            release.notify_waiters();
        };
        let (shutdown_result, ()) = tokio::join!(shutdown_fut, release_fut);
        shutdown_result.expect("graceful_shutdown must succeed within 5s");

        assert_eq!(
            finished.load(Ordering::SeqCst),
            5,
            "graceful_shutdown returned without draining every in-flight \
             job — phase-3 `join_next` regressed",
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_second_caller_waits_for_worker_exit() {
        // P1-N16 regression: a second `graceful_shutdown` caller
        // (arriving after the first caller has already taken the
        // `JoinHandle` out of the slot) must still BLOCK until the
        // worker actually exits, not return an immediate misleading
        // `Ok(())`.
        //
        // Before the `terminated` / `terminated_flag` pair was
        // added, the second caller's `slot.take()` produced `None`
        // and the function fell straight through to `Ok(())`, so a
        // SIGTERM handler that raced two shutdown requests could
        // plausibly `std::process::exit` while deliveries were
        // still in flight.
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let deliverer = Arc::new(GatedDeliverer {
            release: Arc::clone(&release),
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        });
        let outbox = Arc::new(Outbox::new(
            ArcGated(Arc::clone(&deliverer)),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            test_config(),
        ));
        outbox
            .enqueue(
                json!({ "id": "in-flight", "type": "Create" }),
                "https://example.com/inbox/a".parse().unwrap(),
            )
            .await
            .expect("pre-shutdown enqueue must succeed");
        // Wait for the deliverer to park on the gate.
        wait_until_counter(&started, 1, Duration::from_secs(2)).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);

        // Caller A starts shutdown but we simulate its cancellation
        // by manually stealing the handle (this is the scenario the
        // real code path hits when an outer `tokio::select!` picks
        // a sibling branch before Caller A's `await` resolves).
        let stolen_handle = outbox
            .shutdown
            .handle
            .lock()
            .unwrap()
            .take()
            .expect("handle present for caller A");
        // Caller A's side effect that DID run: the stop signal.
        outbox.shutdown.stop.notify_one();

        // Caller B comes in. Its `slot.take()` returns `None` so
        // it must fall into the `terminated` wait path. It must
        // not return before the worker's phase-3 epilogue fires.
        let outbox_b = Arc::clone(&outbox);
        let caller_b = tokio::spawn(async move {
            let start = std::time::Instant::now();
            outbox_b
                .graceful_shutdown(Duration::from_secs(5))
                .await
                .expect("second caller must also observe a clean exit");
            start.elapsed()
        });

        // Short sleep: if the bug is present, `caller_b` returns
        // immediately with an elapsed time on the order of a few
        // microseconds — while the worker is still parked on the
        // gate.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !caller_b.is_finished(),
            "second caller returned before worker exited — P1-N16 regressed",
        );

        // Now unblock the worker and also drain the stolen handle
        // so no tokio task leaks.
        release.notify_waiters();
        drop(tokio::time::timeout(Duration::from_secs(2), stolen_handle).await);
        let elapsed = tokio::time::timeout(Duration::from_secs(2), caller_b)
            .await
            .expect("second caller did not return within 2s after release")
            .expect("second caller task panicked");
        assert!(
            elapsed >= Duration::from_millis(100),
            "second caller returned in {elapsed:?}, not after the worker \
             actually finished — suspicious",
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_completes_in_flight_retries() {
        // P1-N22 regression: a delivery that fails on its first
        // attempt USED to emit its retry by `tx_for_retry.send()`.
        // But `graceful_shutdown` had already called `rx.close()`
        // by the time phase-3 was awaiting `run_one`, so every
        // retry `send` returned `Err` and was silently dropped —
        // the worker exited "gracefully" while quietly losing
        // half of the in-flight deliveries.
        //
        // The fix moved the retry loop **inside** `run_one`, so
        // the retry is just another `deliver()` call on the same
        // spawned task. Phase-3 `in_flight.join_next()` awaits
        // the entire retry loop, so the regression guard is:
        // enqueue a job whose first attempt fails, trigger
        // shutdown with a deadline that comfortably fits the
        // retry back-off, and assert the second attempt actually
        // ran (deliver was called twice — recorded in
        // `RecordingDeliverer::calls`).
        let alice_url = "https://example.com/users/alice";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );
        // Fail once, then succeed. `for_tests` back-off is 10ms.
        let deliverer = Arc::new(RecordingDeliverer::new(1));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            test_config(),
        );

        outbox
            .dispatch(
                json!({ "id": "https://example.com/a/retry", "type": "Create" }),
                &[alice_url.parse().unwrap()],
            )
            .await;

        // Wait for the first (failing) deliver call so we KNOW
        // the job is in its retry sleep when we request shutdown.
        wait_for_calls(&deliverer, 1, Duration::from_secs(2)).await;

        // Shutdown deadline is large relative to the 10ms back-off.
        // A correctly-draining worker finishes the retry well
        // inside this window; a regressing worker (channel-based
        // retry path) returns immediately with `calls.len() == 1`.
        outbox
            .graceful_shutdown(Duration::from_secs(5))
            .await
            .expect("graceful_shutdown must succeed within 5s");

        let calls_len = deliverer.calls.lock().unwrap().len();
        assert_eq!(
            calls_len, 2,
            "expected first attempt + retry to both run during drain, \
             got {calls_len} calls — P1-N22 regressed",
        );
    }

    #[tokio::test]
    async fn small_queue_does_not_livelock_with_failing_deliveries() {
        // P1-N23 regression: when `delivery_queue_capacity <
        // delivery_concurrency` and every job fails once, the old
        // channel-based retry path parked each run_one on
        // `tx_for_retry.send().await` **while still holding its
        // permit**. New incoming jobs then queued up behind the
        // exhausted permit pool and the system degraded from
        // parallel to sequential.
        //
        // With retries handled in-task, a backing-off run_one
        // RELEASES its permit before sleeping, so concurrency
        // is never lost. We configure the pathological shape
        // (queue 2, concurrency 4, 4 jobs that each fail once)
        // and assert the whole batch completes inside a budget
        // that the old implementation could not meet.
        let cfg = FederationConfig::builder()
            .signing_key(SigningKey::generate_ed25519())
            .key_id("https://sender.example/users/alice#key".parse().unwrap())
            .url_policy(UrlPolicy::permissive_for_tests())
            .delivery_concurrency(4)
            .delivery_queue_capacity(2)
            .build()
            .shared();
        // Fail once per (url, attempt) then succeed — four jobs
        // each hit the retry path exactly once.
        let deliverer = Arc::new(RecordingDeliverer::new(4));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            cfg,
        );

        let started = std::time::Instant::now();
        for i in 0..4 {
            outbox
                .enqueue(
                    json!({ "id": format!("livelock-{i}"), "type": "Create" }),
                    format!("https://example.com/inbox/{i}").parse().unwrap(),
                )
                .await
                .expect("enqueue must succeed despite small queue");
        }
        // Each of 4 jobs needs 2 deliver calls. With concurrency
        // 4 and a 10ms back-off we expect << 200ms steady-state;
        // the old livelock shape (permit pool drained, 1-at-a-time
        // throughput) would take >> 500ms. 2s is a generous
        // upper bound for CI jitter.
        wait_for_calls(&deliverer, 8, Duration::from_secs(2)).await;
        let elapsed = started.elapsed();

        outbox
            .graceful_shutdown(Duration::from_secs(5))
            .await
            .expect("clean shutdown expected");

        assert!(
            elapsed < Duration::from_secs(2),
            "small-queue batch took {elapsed:?} — livelock regressed",
        );
    }

    #[tokio::test]
    async fn dispatch_report_reflects_shutdown_rejections() {
        // P2-N25 regression: when a `dispatch` race with
        // `graceful_shutdown` causes every `enqueue_arc` to fail,
        // the report USED to claim `enqueued == inboxes.len()`
        // even though zero jobs were actually queued.
        //
        // The fix returns `Error::OutboxShutdown` from
        // `enqueue_arc` and makes `dispatch` count only the real
        // successes, pushing the rejected inboxes into
        // `DispatchReport.errors`.
        let alice_url = "https://example.com/users/alice";
        let bob_url = "https://example.com/users/bob";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );
        actors.insert(
            bob_url.into(),
            actor_with_inbox(bob_url, "https://example.com/users/bob/inbox"),
        );
        let outbox = Outbox::new(
            ArcDeliverer(Arc::new(RecordingDeliverer::new(0))),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            test_config(),
        );
        // Shut down BEFORE dispatch runs: every enqueue_arc
        // inside `dispatch` will see a closed channel.
        outbox
            .graceful_shutdown(Duration::from_secs(2))
            .await
            .expect("clean shutdown expected");

        let report = outbox
            .dispatch(
                json!({ "id": "https://example.com/a/shutdown-race", "type": "Create" }),
                &[alice_url.parse().unwrap(), bob_url.parse().unwrap()],
            )
            .await;
        assert_eq!(
            report.enqueued, 0,
            "dispatch must NOT claim successes when the worker is gone",
        );
        assert_eq!(
            report.errors.len(),
            2,
            "each rejected recipient must produce one error entry",
        );
        for (_, err) in &report.errors {
            assert!(
                matches!(err, Error::OutboxShutdown { .. }),
                "expected OutboxShutdown error, got {err:?}",
            );
        }
    }

    #[tokio::test]
    async fn dispatch_strips_bto_and_bcc_before_delivery() {
        // P0-N1 (sixth-round audit) regression: W3C ActivityPub
        // §6 Delivery is a MUST — "the server MUST remove the `bto`
        // and/or `bcc` properties, if they exist, from the
        // outgoing object". Prior to this regression guard,
        // `Outbox::dispatch` handed the unmodified activity JSON
        // straight to `serde_json::to_vec`, so any blind-recipient
        // actor in `bto` / `bcc` would have their identity leaked
        // to every (non-blind) recipient of the fan-out.
        //
        // We dispatch to a single actor, capture the activity the
        // deliverer sees on the wire, and assert BOTH the top-level
        // and the nested-object slots are gone.
        let alice_url = "https://example.com/users/alice";
        let mut actors = std::collections::HashMap::new();
        actors.insert(
            alice_url.into(),
            actor_with_inbox(alice_url, "https://example.com/users/alice/inbox"),
        );
        let deliverer = Arc::new(RecordingDeliverer::new(0));
        let outbox = Outbox::new(
            ArcDeliverer(Arc::clone(&deliverer)),
            StaticFetcher { actors },
            RetryPolicy::for_tests(),
            test_config(),
        );

        let activity_with_blind_recipients = json!({
            "id": "https://example.com/activities/leak",
            "type": "Create",
            "actor": alice_url,
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "bto": ["https://example.com/users/secret-blind-top"],
            "bcc": ["https://example.com/users/secret-blind-bottom"],
            "object": {
                "id": "https://example.com/notes/1",
                "type": "Note",
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "bto": ["https://example.com/users/secret-blind-obj-top"],
                "bcc": ["https://example.com/users/secret-blind-obj-bottom"],
                "content": "leak me not",
            },
        });

        outbox
            .dispatch(
                activity_with_blind_recipients,
                &[alice_url.parse().unwrap()],
            )
            .await;
        wait_for_calls(&deliverer, 1, Duration::from_secs(2)).await;

        // Snapshot the delivered activity and release the mutex
        // before asserting — holding the lock across the assertion
        // chain would trip `clippy::significant_drop_tightening`.
        let delivered: Value = deliverer.calls.lock().unwrap()[0].1.clone();
        assert!(
            delivered.get("bto").is_none(),
            "top-level `bto` MUST be stripped from the outgoing activity, \
             got {delivered:?}",
        );
        assert!(
            delivered.get("bcc").is_none(),
            "top-level `bcc` MUST be stripped from the outgoing activity, \
             got {delivered:?}",
        );
        let object = delivered.get("object").expect("object survives");
        assert!(
            object.get("bto").is_none(),
            "nested-object `bto` MUST be stripped, got {object:?}",
        );
        assert!(
            object.get("bcc").is_none(),
            "nested-object `bcc` MUST be stripped, got {object:?}",
        );
        // Public `to` MUST be preserved (the whole point of the
        // strip is to remove blind slots WITHOUT touching the
        // public addressing).
        assert!(
            delivered.get("to").is_some(),
            "public `to` must survive the strip",
        );
    }

    #[tokio::test]
    async fn dropping_last_outbox_clone_aborts_worker() {
        // P1-N10 + P2-N19 regression: when every [`Outbox`] clone
        // drops, the `ShutdownHandle` Arc's strong count goes to
        // zero, its `Drop` fires, the worker is signalled via
        // `stop.notify_one()`, and the worker task must actually
        // exit within a short deadline.
        //
        // Prior to the P1-N10 refactor the worker held an
        // `Arc<Inner>` containing the sole `tx`, so the channel
        // never closed and the worker leaked indefinitely.
        //
        // The earlier (P2-N19) version of this test only asserted
        // `Arc::strong_count == 1`, which is a *scheduling-order
        // proxy* — it said nothing about whether the worker task
        // had actually run its epilogue. We now steal the
        // `JoinHandle` **before** dropping the `Outbox`, then
        // directly `.await` the handle under a tight
        // `tokio::time::timeout`. The steal makes `Drop::drop`'s
        // `slot.take()` return `None` so its `abort()` branch is
        // skipped — meaning a pass here proves the worker exited
        // via the graceful `stop.notify_one()` path, NOT via the
        // belt-and-braces abort.
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let deliverer = Arc::new(GatedDeliverer {
            release: Arc::clone(&release),
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        });
        let outbox = Outbox::new(
            ArcGated(Arc::clone(&deliverer)),
            StaticFetcher {
                actors: std::collections::HashMap::new(),
            },
            RetryPolicy::for_tests(),
            test_config(),
        );

        // Steal the worker's JoinHandle so Drop::drop cannot abort
        // it; we want to observe the graceful-notify exit path
        // deterministically.
        let stolen_handle = outbox
            .shutdown
            .handle
            .lock()
            .unwrap()
            .take()
            .expect("worker handle should still be present");
        let terminated_flag = Arc::clone(&outbox.shutdown.terminated_flag);

        drop(outbox);

        // The worker MUST observe `stop.notify_one()` emitted by
        // ShutdownHandle::drop and exit within the deadline. 2s is
        // wildly generous for a worker that has no in-flight jobs.
        let join_result = tokio::time::timeout(Duration::from_secs(2), stolen_handle).await;
        assert!(
            join_result.is_ok(),
            "worker did not exit within 2s after last Outbox drop — \
             graceful-notify path regressed",
        );
        assert!(
            terminated_flag.load(Ordering::Acquire),
            "worker exited but did not mark `terminated_flag` true — \
             the phase-3 epilogue is not running",
        );

        let () = release.notify_waiters(); // unblock in-flight if any
    }
}
