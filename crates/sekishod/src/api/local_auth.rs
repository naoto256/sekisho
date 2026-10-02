//! Local authentication via Unix socket challenge-response.
//!
//! Flow:
//! 1. Client calls `POST /.sekisho/api/v1/auth/challenge` over HTTPS → receives a nonce
//! 2. Client connects to Unix socket, writes the nonce + newline
//! 3. Server verifies the nonce, generates a management session token, writes it back + newline
//! 4. Client uses the token as `Authorization: Bearer {token}` on HTTPS
//!
//! The Unix socket proves the caller runs with the daemon's exact effective UID.
//! The socket itself is NOT an HTTP server — it's a raw line protocol.

use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Upper bound on pending challenges. Each entry is ~100 B (base64 nonce
/// plus a timestamp), so 10_000 caps memory at ~1 MiB regardless of how
/// fast the public `/auth/challenge` endpoint is being hit. The endpoint
/// is also rate-limited, but the cap is the backstop.
const MAX_CHALLENGES: usize = 10_000;

/// In-memory store of pending challenges: nonce → expiry.
///
/// A bounded FIFO queue tracks insertion order so that when the cap is
/// reached we can evict the oldest pending challenge in O(1) without
/// having to scan the `HashMap`.
pub struct ChallengeStore {
    pending: Mutex<PendingChallenges>,
    /// Active management session tokens: token → expiry.
    sessions: Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>,
}

struct PendingChallenges {
    by_nonce: HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Insertion order of nonces still present in `by_nonce`. When a
    /// nonce is consumed or expires, its entry here becomes stale; we
    /// lazily discard stale entries while popping from the front.
    order: VecDeque<String>,
}

/// A nonce redemption prepared for delivery over the control socket.
///
/// The management token becomes committed only after [`Self::commit`].
/// Dropping an uncommitted delivery removes the token first, then puts
/// the nonce back with its original expiry when it is still live.
struct PreparedDelivery {
    store: Arc<ChallengeStore>,
    nonce: String,
    nonce_expiry: chrono::DateTime<chrono::Utc>,
    token: String,
    committed: bool,
}

impl PreparedDelivery {
    fn token(&self) -> &str {
        &self.token
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PreparedDelivery {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        self.store
            .rollback_prepared_delivery(&self.nonce, self.nonce_expiry, &self.token);
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(PendingChallenges {
                by_nonce: HashMap::new(),
                order: VecDeque::new(),
            }),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a new challenge nonce (valid for 60 seconds).
    ///
    /// When the store is at `MAX_CHALLENGES`, the oldest pending entry
    /// is evicted FIFO — including unexpired ones, so a sustained flood
    /// cannot permanently deny legitimate callers, it just forces them
    /// to retry within the nonce lifetime.
    pub fn issue(&self) -> String {
        let nonce: [u8; 32] = rand::rng().random();
        let nonce_str =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce);

        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now();
        // Drop expired entries first so we only evict live ones if we
        // really are at the cap.
        pending.by_nonce.retain(|_, expiry| *expiry > now);
        // Keep `order` aligned with the HashMap: discard leading entries
        // that are no longer live. This is amortized O(1).
        while let Some(front) = pending.order.front() {
            if pending.by_nonce.contains_key(front) {
                break;
            }
            pending.order.pop_front();
        }

        if pending.by_nonce.len() >= MAX_CHALLENGES {
            // FIFO evict. At the cap every entry is live, so this is a
            // genuine denial of the oldest pending caller.
            if let Some(oldest) = pending.order.pop_front() {
                pending.by_nonce.remove(&oldest);
                tracing::warn!(
                    cap = MAX_CHALLENGES,
                    "challenge store at capacity; evicting oldest pending challenge"
                );
            }
        }

        pending
            .by_nonce
            .insert(nonce_str.clone(), now + chrono::Duration::seconds(60));
        pending.order.push_back(nonce_str.clone());

        nonce_str
    }

    /// Prepare a valid nonce for control-socket delivery.
    ///
    /// The returned guard owns the rollback boundary until the complete
    /// token reply has been written to the peer.
    fn prepare_delivery(self: &Arc<Self>, nonce: &str) -> Option<PreparedDelivery> {
        let expiry = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.by_nonce.remove(nonce)?
        };
        if expiry <= chrono::Utc::now() {
            return None;
        }

        let token_bytes: [u8; 32] = rand::rng().random();
        let token = format!(
            "mgmt_{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                token_bytes
            )
        );

        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now();
        // Lazy GC: retain drops expired session tokens after each
        // prepared redemption. `validate_token` (below) performs no
        // cleanup, no background sweep runs, and no fixed cap is
        // enforced on this map. If redemptions stop, expired entries
        // linger until the next prepared redemption.
        sessions.retain(|_, exp| *exp > now);
        sessions.insert(token.clone(), now + chrono::Duration::hours(1));

        Some(PreparedDelivery {
            store: self.clone(),
            nonce: nonce.to_owned(),
            nonce_expiry: expiry,
            token,
            committed: false,
        })
    }

    /// Roll back an uncommitted control-socket delivery.
    ///
    /// The two mutexes are deliberately acquired in separate scopes:
    /// token removal must precede nonce restoration, while never
    /// holding them in the reverse of the preparation path.
    fn rollback_prepared_delivery(
        &self,
        nonce: &str,
        nonce_expiry: chrono::DateTime<chrono::Utc>,
        token: &str,
    ) {
        {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.remove(token);
        }

        if nonce_expiry <= chrono::Utc::now() {
            return;
        }

        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.by_nonce.contains_key(nonce) {
            return;
        }

        while let Some(front) = pending.order.front() {
            if pending.by_nonce.contains_key(front) {
                break;
            }
            pending.order.pop_front();
        }

        if pending.by_nonce.len() >= MAX_CHALLENGES {
            while let Some(oldest) = pending.order.pop_front() {
                if pending.by_nonce.remove(&oldest).is_some() {
                    tracing::warn!(
                        cap = MAX_CHALLENGES,
                        "challenge store at capacity while rolling back credential delivery; \
                         evicting oldest pending challenge"
                    );
                    break;
                }
            }
        }

        if !pending.order.iter().any(|entry| entry == nonce) {
            // If redemption temporarily removed the oldest nonce, an
            // intervening issue() may have discarded its stale queue
            // entry. Restoring it at the front preserves that age.
            pending.order.push_front(nonce.to_owned());
        }
        pending.by_nonce.insert(nonce.to_owned(), nonce_expiry);
    }

    #[cfg(test)]
    fn verify_and_issue_token(self: &Arc<Self>, nonce: &str) -> Option<String> {
        let delivery = self.prepare_delivery(nonce)?;
        let token = delivery.token().to_owned();
        delivery.commit();
        Some(token)
    }

    /// Check if a management session token is valid.
    pub fn validate_token(&self, token: &str) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(token)
            .map(|expiry| *expiry > chrono::Utc::now())
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_nonce
            .len()
    }

    #[cfg(test)]
    fn pending_expiry(&self, nonce: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_nonce
            .get(nonce)
            .copied()
    }

    #[cfg(test)]
    fn session_len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

// ---- HTTPS endpoint: issue challenge ----

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// Per-IP token-bucket rate limiter guarding the public
/// `/auth/challenge` endpoint. Each peer address gets its own bucket
/// of `BURST` tokens, refilled at `RATE_PER_SEC`. A process-wide
/// global bucket would let one flooding IP exhaust the budget for
/// every other caller; a per-IP map keeps the noisy neighbour
/// isolated.
///
/// Idle entries are GC'd on each `allow()` call: any bucket that
/// has been quiet for `IDLE_GC_SECS` seconds gets dropped, capping
/// memory under sustained scanner traffic. The cleanup is amortised:
/// the GC walk is inlined in `allow()` and only runs when the map
/// has crossed `GC_TRIGGER_SIZE` *and* the last GC was at least
/// `IDLE_GC_SECS` ago, so the hot path stays a single map lookup.
struct ChallengeRateLimiter {
    buckets: Mutex<RateLimitMap>,
}

struct RateLimitMap {
    by_ip: HashMap<std::net::IpAddr, (f64, std::time::Instant)>,
    last_gc: std::time::Instant,
}

impl ChallengeRateLimiter {
    const RATE_PER_SEC: f64 = 10.0;
    const BURST: f64 = 20.0;
    /// Drop buckets that have been quiet for this long. Two times the
    /// time it would take a sated bucket to refill from empty to BURST
    /// (BURST / RATE_PER_SEC = 2 s) — anything beyond that and the
    /// bucket is in steady state again, so re-creating it on the next
    /// hit costs nothing.
    const IDLE_GC_SECS: u64 = 60;
    /// Skip the GC walk until the map has at least this many entries.
    /// Below this size, retaining stale buckets is cheaper than the
    /// scan; above it the scan amortises across the entries it drops.
    const GC_TRIGGER_SIZE: usize = 256;

    fn new() -> Self {
        Self {
            buckets: Mutex::new(RateLimitMap {
                by_ip: HashMap::new(),
                last_gc: std::time::Instant::now(),
            }),
        }
    }

    /// Try to take one token for `peer`. Returns `true` on success,
    /// `false` when the bucket is empty (caller should reject with 429).
    /// `None` is treated as "unknown peer" and lumped into a single
    /// bucket — this happens for tests / non-TCP transports where
    /// `ConnectInfo` isn't populated; production traffic always has it.
    fn allow(&self, peer: Option<std::net::IpAddr>) -> bool {
        let key = peer.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let mut guard = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Amortised GC: the cost of a full HashMap scan is bounded by
        // GC_TRIGGER_SIZE entries, and we only pay it after IDLE_GC_SECS
        // of accumulating idle buckets. In quiet workloads the branch is
        // never taken.
        if guard.by_ip.len() >= Self::GC_TRIGGER_SIZE
            && now.duration_since(guard.last_gc).as_secs() >= Self::IDLE_GC_SECS
        {
            let cutoff = std::time::Duration::from_secs(Self::IDLE_GC_SECS);
            guard
                .by_ip
                .retain(|_, (_, last)| now.duration_since(*last) < cutoff);
            guard.last_gc = now;
        }

        let entry = guard.by_ip.entry(key).or_insert_with(|| (Self::BURST, now));
        let (ref mut tokens, ref mut last) = *entry;
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;
        *tokens = (*tokens + elapsed * Self::RATE_PER_SEC).min(Self::BURST);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

static CHALLENGE_RATE_LIMITER: std::sync::LazyLock<ChallengeRateLimiter> =
    std::sync::LazyLock::new(ChallengeRateLimiter::new);

/// `POST /.sekisho/api/v1/auth/challenge` — issue a nonce for local auth.
/// No API key required. Rate-limited per peer IP to cap the damage from
/// a flood of unauthenticated requests without letting one noisy peer
/// exhaust the budget for legitimate callers.
pub async fn challenge(
    axum::extract::Extension(challenge_store): axum::extract::Extension<Arc<ChallengeStore>>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Pull the peer IP from `ConnectInfo` if it was injected by the
    // listener; in test harnesses (and any setup that doesn't use
    // `into_make_service_with_connect_info`) this is absent and the
    // limiter falls back to a shared "unknown peer" bucket.
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    if !CHALLENGE_RATE_LIMITER.allow(peer) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }
    let nonce = challenge_store.issue();
    Json(serde_json::json!({ "nonce": nonce })).into_response()
}

// ---- Unix socket handler (raw line protocol, NOT HTTP) ----

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Return the effective UID of the current process. Used to compare
/// against peer credentials on the control socket so only processes
/// running as the daemon user can redeem challenges. On non-Unix
/// platforms this returns `None` and the UID check is skipped (the
/// socket itself is only created on Unix).
#[cfg(unix)]
fn daemon_uid() -> u32 {
    // SAFETY: `geteuid` is a plain syscall wrapper with no preconditions
    // and cannot fail per POSIX.
    unsafe { libc::geteuid() }
}

async fn handle_control_connection(stream: tokio::net::UnixStream, store: Arc<ChallengeStore>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Timeout: drop connections that don't send within 10 seconds.
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await;
    match read_result {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let nonce = line.trim();

    match store.prepare_delivery(nonce) {
        Some(delivery) => {
            let reply = format!("{}\n", delivery.token());
            match writer.write_all(reply.as_bytes()).await {
                Ok(()) => delivery.commit(),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "control socket: credential reply delivery failed"
                    );
                }
            }
        }
        None => {
            let _ = writer.write_all(b"error: invalid or expired nonce\n").await;
        }
    }
}

/// Serve the challenge-verify protocol on a Unix socket.
/// Each connection: read nonce line → verify → write token line (or "error\n").
///
/// The socket is created with mode `0660` and owned by the `sekisho` group,
/// but file-system permissions only gate who can `connect(2)`. We additionally
/// check `SO_PEERCRED` on each accepted connection and reject peers whose UID
/// is not the daemon's own, so membership in the `sekisho` group alone is not
/// enough to redeem a challenge for a management token.
pub async fn serve_control_socket(
    listener: tokio::net::UnixListener,
    store: Arc<ChallengeStore>,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
) {
    #[cfg(unix)]
    let expected_uid = daemon_uid();
    let mut shutdown = shutdown_ctl.subscribe();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.wait() => return,
            result = listener.accept() => result,
        };
        match accepted {
            Ok((stream, _addr)) => {
                #[cfg(unix)]
                {
                    match stream.peer_cred() {
                        Ok(cred) if cred.uid() == expected_uid => {}
                        Ok(cred) => {
                            tracing::warn!(
                                expected_uid,
                                peer_uid = cred.uid(),
                                peer_pid = ?cred.pid(),
                                "control socket: rejecting peer with mismatched UID"
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "control socket: could not read peer credentials; rejecting"
                            );
                            continue;
                        }
                    }
                }
                let store = store.clone();
                tokio::spawn(handle_control_connection(stream, store));
            }
            Err(e) => {
                tracing::warn!(error = %e, "control socket accept error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    async fn redeem_over_socket(store: Arc<ChallengeStore>, nonce: &str) -> String {
        let (server, mut client) = tokio::net::UnixStream::pair().expect("create socket pair");
        let task = tokio::spawn(handle_control_connection(server, store));

        client
            .write_all(format!("{nonce}\n").as_bytes())
            .await
            .expect("write nonce");
        let mut reader = BufReader::new(client);
        let mut reply = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reader.read_line(&mut reply),
        )
        .await
        .expect("credential reply timed out")
        .expect("read credential reply");
        task.await.expect("connection handler");
        reply
    }

    #[test]
    fn challenge_store_caps_at_max_entries() {
        let store = ChallengeStore::new();
        for _ in 0..MAX_CHALLENGES + 50 {
            let _ = store.issue();
        }
        assert_eq!(
            store.pending_len(),
            MAX_CHALLENGES,
            "pending nonces must never exceed the cap"
        );
    }

    #[test]
    fn challenge_store_evicts_oldest_on_overflow() {
        let store = Arc::new(ChallengeStore::new());
        // The very first nonce is the oldest — it must be the one evicted
        // when the cap is exceeded.
        let oldest = store.issue();
        for _ in 1..MAX_CHALLENGES {
            let _ = store.issue();
        }
        assert_eq!(store.pending_len(), MAX_CHALLENGES);
        // One more issue() should evict `oldest` FIFO.
        let _ = store.issue();
        assert_eq!(store.pending_len(), MAX_CHALLENGES);
        assert!(
            store.verify_and_issue_token(&oldest).is_none(),
            "oldest pending nonce must be evicted when the cap is exceeded"
        );
    }

    #[test]
    fn challenge_store_preserves_unexpired_after_consumption() {
        // Consuming a nonce leaves a stale entry in the order queue; the
        // next issue() must skip past it rather than mistake it for the
        // oldest live entry.
        let store = Arc::new(ChallengeStore::new());
        let a = store.issue();
        let b = store.issue();
        assert!(store.verify_and_issue_token(&a).is_some());
        // `b` should still be valid.
        assert!(store.verify_and_issue_token(&b).is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn credential_write_failure_rolls_back_and_allows_retry() {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let store = Arc::new(ChallengeStore::new());
        let nonce = store.issue();
        let (server, mut client) = StdUnixStream::pair().expect("create socket pair");
        std::io::Write::write_all(&mut client, format!("{nonce}\n").as_bytes())
            .expect("write nonce");
        client
            .shutdown(std::net::Shutdown::Both)
            .expect("close client socket");
        drop(client);
        server
            .set_nonblocking(true)
            .expect("set server nonblocking");
        let server = tokio::net::UnixStream::from_std(server).expect("adopt server socket");

        handle_control_connection(server, store.clone()).await;

        assert!(
            store.pending_len() == 1,
            "failed credential delivery did not restore pending nonce"
        );
        assert!(
            store.session_len() == 0,
            "failed credential delivery left an active session"
        );

        let reply = redeem_over_socket(store.clone(), &nonce).await;
        let token = reply.trim();
        assert!(
            token.starts_with("mgmt_"),
            "retry did not return a management token"
        );
        assert!(
            store.validate_token(token),
            "retry returned an inactive management token"
        );
    }

    #[tokio::test]
    async fn aborting_prepared_delivery_rolls_back() {
        let store = Arc::new(ChallengeStore::new());
        let nonce = store.issue();
        let task_store = store.clone();
        let task_nonce = nonce.clone();
        let (prepared_tx, prepared_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let delivery = task_store
                .prepare_delivery(&task_nonce)
                .expect("prepare delivery");
            prepared_tx.send(()).expect("signal prepared delivery");
            std::future::pending::<()>().await;
            drop(delivery);
        });

        prepared_rx.await.expect("prepared delivery signal");
        assert!(
            store.pending_len() == 0 && store.session_len() == 1,
            "prepared delivery did not own exactly one pending session"
        );
        task.abort();
        let error = task.await.expect_err("aborted task completed normally");
        assert!(
            error.is_cancelled(),
            "prepared delivery task was not cancelled"
        );
        assert!(
            store.pending_len() == 1 && store.session_len() == 0,
            "task cancellation did not roll back prepared delivery"
        );
    }

    #[tokio::test]
    async fn panicking_prepared_delivery_rolls_back() {
        let store = Arc::new(ChallengeStore::new());
        let nonce = store.issue();
        let task_store = store.clone();

        let task = tokio::spawn(async move {
            let _delivery = task_store
                .prepare_delivery(&nonce)
                .expect("prepare delivery");
            panic!("prepared delivery panic probe");
        });

        let error = task.await.expect_err("panicking task completed normally");
        assert!(error.is_panic(), "prepared delivery task did not panic");
        assert!(
            store.pending_len() == 1 && store.session_len() == 0,
            "panic unwind did not roll back prepared delivery"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_delivery_commits_once() {
        let store = Arc::new(ChallengeStore::new());
        let nonce = store.issue();

        let reply = redeem_over_socket(store.clone(), &nonce).await;
        let token = reply.trim();
        assert!(
            token.starts_with("mgmt_"),
            "successful delivery did not return a management token"
        );
        assert!(
            store.validate_token(token),
            "successful delivery returned an inactive token"
        );
        assert!(
            store.pending_len() == 0 && store.session_len() == 1,
            "successful delivery did not commit exactly one session"
        );

        let retry = redeem_over_socket(store.clone(), &nonce).await;
        assert!(
            retry == "error: invalid or expired nonce\n",
            "successful delivery allowed the nonce to be reused"
        );
        assert!(
            store.session_len() == 1,
            "nonce reuse changed the active session count"
        );
    }

    #[test]
    fn rollback_preserves_original_nonce_expiry() {
        let store = Arc::new(ChallengeStore::new());
        let nonce = store.issue();
        let original_expiry = store
            .pending_expiry(&nonce)
            .expect("issued nonce has expiry");

        let delivery = store.prepare_delivery(&nonce).expect("prepare delivery");
        drop(delivery);

        let restored_expiry = store
            .pending_expiry(&nonce)
            .expect("rollback restored nonce");
        assert!(
            restored_expiry == original_expiry,
            "rollback changed the nonce expiry"
        );
        assert!(
            store.session_len() == 0,
            "ordinary guard drop left an active session"
        );

        let expired_nonce = store.issue();
        let mut expired_delivery = store
            .prepare_delivery(&expired_nonce)
            .expect("prepare expiring delivery");
        expired_delivery.nonce_expiry = chrono::Utc::now() - chrono::Duration::milliseconds(1);
        drop(expired_delivery);
        assert!(
            store.pending_expiry(&expired_nonce).is_none(),
            "rollback restored an expired nonce"
        );
        assert!(
            store.session_len() == 0,
            "expired rollback left an active session"
        );
    }

    #[test]
    fn rate_limiter_isolates_per_ip() {
        // Core property: one flooding peer must not exhaust another
        // peer's budget. Drain ip_a's bucket completely, then verify
        // ip_b still has its full BURST available.
        let limiter = ChallengeRateLimiter::new();
        let ip_a = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        for i in 0..(ChallengeRateLimiter::BURST as u32) {
            assert!(
                limiter.allow(Some(ip_a)),
                "ip_a should still have tokens at iteration {i}"
            );
        }
        assert!(
            !limiter.allow(Some(ip_a)),
            "ip_a's bucket should be empty after BURST consumed"
        );
        assert!(
            limiter.allow(Some(ip_b)),
            "ip_b must still have its own untouched bucket"
        );
    }

    #[test]
    fn rate_limiter_unknown_peer_falls_into_shared_bucket() {
        // `None` peer (test harness, missing ConnectInfo) must not
        // panic and must rate-limit against a shared bucket so that an
        // attacker can't bypass the limiter by stripping the peer
        // address.
        let limiter = ChallengeRateLimiter::new();
        for _ in 0..(ChallengeRateLimiter::BURST as u32) {
            assert!(limiter.allow(None));
        }
        assert!(
            !limiter.allow(None),
            "shared bucket for unknown peers must drain like any other"
        );
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        // After draining, time-passing should let the next call through
        // again. Use the limiter's own clock by burning a real sleep —
        // shorter than RATE_PER_SEC's reciprocal so we get exactly one
        // refilled token.
        let limiter = ChallengeRateLimiter::new();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 3));
        for _ in 0..(ChallengeRateLimiter::BURST as u32) {
            assert!(limiter.allow(Some(ip)));
        }
        assert!(!limiter.allow(Some(ip)));
        // Sleep a touch over 1 / RATE_PER_SEC seconds to let one token
        // accumulate. 200 ms is well above the ~100 ms refill interval.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            limiter.allow(Some(ip)),
            "bucket must refill at RATE_PER_SEC over time"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_socket_stops_when_shutdown_precedes_subscription() {
        let socket_path = std::path::Path::new("/tmp").join(format!(
            "sekishod-control-shutdown-{}-{}.sock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let ctl = Arc::new(crate::shutdown::ShutdownController::new());
        ctl.signal();

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            serve_control_socket(listener, Arc::new(ChallengeStore::new()), ctl),
        )
        .await
        .expect("pre-signalled control listener did not stop");

        std::fs::remove_file(socket_path).unwrap();
    }
}
