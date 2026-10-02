//! Coherent, process-local route generations.
//!
//! A generation is built once from one database statement and published as
//! one pointer. Requests never probe the database. Route-client pools, load
//! balancing counters, compiled route data, and stable admission budgets are
//! therefore observed from the same route version.

use crate::error::Error;
use crate::models::route::Route;
use crate::proxy::{RouteClientCache, upstream::LoadBalancer};
use crate::store::{Store, route_cache::RouteCache};
use axum::http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

const LAST_KNOWN_GOOD: Duration = Duration::from_secs(30);
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);

/// Everything one matched request needs, taken from a single published
/// generation.
///
/// Bundled rather than looked up piecemeal so that the route, its HTTP client
/// cache, its load-balancer cursor, its compiled rewrite and its admission
/// permit all come from the *same* generation. Fetching them separately would
/// leave a window in which a republish lands between two lookups and the
/// request is served with a regex compiled for a route it is no longer using.
pub(crate) struct RouteSelection {
    pub(crate) route: Arc<Route>,
    pub(crate) clients: Arc<RouteClientCache>,
    pub(crate) load_balancer: Arc<LoadBalancer>,
    pub(crate) rewrite: Option<regex::Regex>,
    admission: RouteAdmission,
}

impl RouteSelection {
    /// Hand the admission permit to the caller, who must keep it alive for as
    /// long as the response body streams.
    ///
    /// Takes `&mut self` and leaves `Ready(None)` behind so a permit cannot be
    /// yielded twice — a second call returns "no permit" rather than a second
    /// claim on the same slot. A rejected admission surfaces here as 503,
    /// deferred to this point so route matching itself stays infallible.
    pub(crate) fn take_permit(&mut self) -> Result<Option<OwnedSemaphorePermit>, StatusCode> {
        match std::mem::replace(&mut self.admission, RouteAdmission::Ready(None)) {
            RouteAdmission::Ready(permit) => Ok(permit),
            RouteAdmission::Rejected => Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }
}

enum RouteAdmission {
    Ready(Option<OwnedSemaphorePermit>),
    Rejected,
}

#[cfg(test)]
struct AdmissionPause {
    entered: std::sync::Barrier,
    release: std::sync::Barrier,
}

struct Generation {
    version: u64,
    routes: RouteCache,
    clients: Arc<RouteClientCache>,
    load_balancer: Arc<LoadBalancer>,
    budgets: HashMap<Uuid, Arc<RouteBudget>>,
    rewrites: HashMap<Uuid, regex::Regex>,
}

enum Publication {
    Initial,
    Ready(Arc<Generation>),
    RefreshPending,
    DatabaseError {
        previous: Option<Arc<Generation>>,
        since: Instant,
    },
    Invalid,
}

fn published_generation(publication: &Publication) -> Result<&Arc<Generation>, StatusCode> {
    match publication {
        Publication::Ready(generation) => Ok(generation),
        Publication::DatabaseError {
            previous: Some(generation),
            since,
        } if since.elapsed() < LAST_KNOWN_GOOD => Ok(generation),
        Publication::Initial
        | Publication::RefreshPending
        | Publication::DatabaseError { .. }
        | Publication::Invalid => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

struct BudgetState {
    limit: usize,
    debt: usize,
}

struct RouteBudget {
    semaphore: Arc<Semaphore>,
    state: Mutex<BudgetState>,
}

impl RouteBudget {
    fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            state: Mutex::new(BudgetState { limit, debt: 0 }),
        }
    }

    fn set_limit(&self, limit: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if limit < state.limit {
            let reduction = state.limit - limit;
            let forgotten = self.semaphore.forget_permits(reduction);
            state.debt = state.debt.saturating_add(reduction - forgotten);
        } else if limit > state.limit {
            let increase = limit - state.limit;
            let cancelled = increase.min(state.debt);
            state.debt -= cancelled;
            if increase > cancelled {
                self.semaphore.add_permits(increase - cancelled);
            }
        }
        state.limit = limit;
    }

    fn try_acquire(self: &Arc<Self>) -> Result<OwnedSemaphorePermit, StatusCode> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.debt > 0 {
            let forgotten = self.semaphore.forget_permits(state.debt);
            state.debt -= forgotten;
        }
        if state.debt > 0 || state.limit == 0 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
}

struct BudgetRegistry {
    active: HashMap<Uuid, Arc<RouteBudget>>,
    retired: HashMap<Uuid, Arc<RouteBudget>>,
}

impl BudgetRegistry {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
            retired: HashMap::new(),
        }
    }

    fn reconcile(&mut self, routes: &[Route]) -> HashMap<Uuid, Arc<RouteBudget>> {
        let mut next = HashMap::new();
        let mut active_ids = HashSet::new();
        for route in routes {
            if !route.enabled {
                continue;
            }
            let Some(limit) = route.concurrency_limit else {
                continue;
            };
            active_ids.insert(route.id);
            let budget = self
                .active
                .remove(&route.id)
                .or_else(|| self.retired.remove(&route.id))
                .unwrap_or_else(|| Arc::new(RouteBudget::new(limit as usize)));
            budget.set_limit(limit as usize);
            next.insert(route.id, Arc::clone(&budget));
            self.active.insert(route.id, budget);
        }
        for (id, budget) in self.active.drain().collect::<Vec<_>>() {
            if active_ids.contains(&id) {
                self.active.insert(id, budget);
            } else {
                self.retired.insert(id, budget);
            }
        }
        self.retired
            .retain(|_, budget| Arc::strong_count(budget) > 1);
        next
    }
}

/// Owner of the published route snapshot and of the observer task that keeps
/// it current.
///
/// Writers do not rebuild; they bump `ticket` and wake the observer, so
/// management latency is never coupled to snapshot construction and a burst of
/// edits collapses into one rebuild. `budgets` outlives any single generation
/// because a per-route concurrency limit has to keep counting across a
/// republish — a rebuild that reset the counters would briefly let a route
/// exceed its cap. Retired budgets are dropped once nothing holds them.
pub(crate) struct RouteGeneration {
    store: Store,
    publication: RwLock<Publication>,
    budgets: Mutex<BudgetRegistry>,
    ticket: std::sync::atomic::AtomicU64,
    notify: Notify,
    #[cfg(test)]
    admission_pause: Mutex<Option<Arc<AdmissionPause>>>,
    #[cfg(test)]
    observer_spawns: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    observer_iterations: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    observer_iteration_started: Notify,
}

impl RouteGeneration {
    pub(crate) fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store,
            publication: RwLock::new(Publication::Initial),
            budgets: Mutex::new(BudgetRegistry::new()),
            ticket: std::sync::atomic::AtomicU64::new(0),
            notify: Notify::new(),
            #[cfg(test)]
            admission_pause: Mutex::new(None),
            #[cfg(test)]
            observer_spawns: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            observer_iterations: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            observer_iteration_started: Notify::new(),
        })
    }

    #[cfg(test)]
    pub(crate) async fn new_for_test(store: Store) -> Arc<Self> {
        let generation = Self::new(store);
        generation.observe_and_publish().await;
        generation
    }

    #[cfg(test)]
    pub(crate) fn new_ready_empty_for_test(store: Store) -> Arc<Self> {
        let generation = Self::new(store);
        let routes = RouteCache::new();
        routes.load(Vec::new()).unwrap();
        *generation
            .publication
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Publication::Ready(Arc::new(Generation {
            version: 0,
            routes,
            clients: Arc::new(RouteClientCache::new()),
            load_balancer: Arc::new(LoadBalancer::new()),
            budgets: HashMap::new(),
            rewrites: HashMap::new(),
        }));
        generation
    }

    #[cfg(test)]
    fn elapse_database_error_for_test(&self, elapsed: Duration) {
        let mut publication = self.publication.write().unwrap_or_else(|e| e.into_inner());
        if let Publication::DatabaseError { since, .. } = &mut *publication {
            *since -= elapsed;
        } else {
            panic!("database error state required");
        }
    }

    #[cfg(test)]
    fn current_weak_for_test(&self) -> std::sync::Weak<Generation> {
        let publication = self.publication.read().unwrap_or_else(|e| e.into_inner());
        let Publication::Ready(generation) = &*publication else {
            panic!("ready generation required");
        };
        Arc::downgrade(generation)
    }

    #[cfg(test)]
    pub(crate) fn database_error_for_test(&self) {
        let ticket = self.ticket.load(std::sync::atomic::Ordering::SeqCst);
        self.publish_observation(
            ticket,
            Err(Error::ServiceUnavailable("test observation failure".into())),
        );
    }

    pub(crate) fn spawn(self: &Arc<Self>, shutdown: &Arc<crate::shutdown::ShutdownController>) {
        #[cfg(test)]
        self.observer_spawns
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let this = Arc::clone(self);
        let mut shutdown_signal = shutdown.subscribe();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_signal.wait() => return,
                    _ = async {
                        #[cfg(test)]
                        {
                            this.observer_iterations
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            this.observer_iteration_started.notify_waiters();
                        }
                        this.observe_and_publish().await;
                    } => {}
                }
                tokio::select! {
                    _ = shutdown_signal.wait() => return,
                    _ = this.notify.notified() => {},
                    _ = tokio::time::sleep(OBSERVATION_INTERVAL) => {},
                }
            }
        });
        shutdown.track_task(handle);
    }

    /// Withdraw the current generation before a successful local CRUD
    /// response can be observed. The background observer owns publication;
    /// the management handler does not wait for its database read to finish.
    pub(crate) fn request_refresh(&self) {
        let mut publication = self.publication.write().unwrap_or_else(|e| e.into_inner());
        self.ticket
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *publication = Publication::RefreshPending;
        drop(publication);
        self.notify.notify_one();
    }

    pub(crate) fn is_ready(&self) -> bool {
        matches!(
            &*self.publication.read().unwrap_or_else(|e| e.into_inner()),
            Publication::Ready(_)
        )
    }

    pub(crate) fn find(
        &self,
        hostname: &str,
        request_path: &str,
    ) -> Result<Option<RouteSelection>, StatusCode> {
        let state = self.publication.read().unwrap_or_else(|e| e.into_inner());
        let generation = published_generation(&state)?;
        let route = generation
            .routes
            .get(hostname, request_path)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let Some(route) = route else {
            return Ok(None);
        };
        #[cfg(test)]
        self.pause_admission_for_test();
        let admission = match generation.budgets.get(&route.id) {
            Some(budget) => match budget.try_acquire() {
                Ok(permit) => RouteAdmission::Ready(Some(permit)),
                Err(_) => RouteAdmission::Rejected,
            },
            None => RouteAdmission::Ready(None),
        };
        Ok(Some(RouteSelection {
            admission,
            rewrite: generation.rewrites.get(&route.id).cloned(),
            route,
            clients: Arc::clone(&generation.clients),
            load_balancer: Arc::clone(&generation.load_balancer),
        }))
    }

    /// Resolve an authority to a published route hostname for the cleartext
    /// listener without path matching, admission, or a per-request DB read.
    pub(crate) fn redirect_host(
        &self,
        host: &crate::identity::CanonicalHost,
    ) -> Result<Option<String>, StatusCode> {
        let state = self.publication.read().unwrap_or_else(|e| e.into_inner());
        published_generation(&state)?
            .routes
            .redirect_host(host)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    #[cfg(test)]
    fn pause_next_admission_for_test(&self) -> Arc<AdmissionPause> {
        let pause = Arc::new(AdmissionPause {
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        *self
            .admission_pause
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&pause));
        pause
    }

    #[cfg(test)]
    fn pause_admission_for_test(&self) {
        let pause = self
            .admission_pause
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(pause) = pause {
            pause.entered.wait();
            pause.release.wait();
        }
    }

    #[cfg(test)]
    pub(crate) fn observer_counts_for_test(&self) -> (usize, usize) {
        (
            self.observer_spawns
                .load(std::sync::atomic::Ordering::SeqCst),
            self.observer_iterations
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_observer_iteration_for_test(&self) {
        while self
            .observer_iterations
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            self.observer_iteration_started.notified().await;
        }
    }

    async fn observe_and_publish(&self) {
        let ticket = self.ticket.load(std::sync::atomic::Ordering::SeqCst);
        let observed = self.store.observe_routes().await;
        self.publish_observation(ticket, observed);
    }

    fn publish_observation(
        &self,
        ticket: u64,
        observed: crate::error::Result<crate::store::route::RouteObservation>,
    ) {
        if self.ticket.load(std::sync::atomic::Ordering::SeqCst) != ticket {
            self.notify.notify_one();
            return;
        }
        match observed {
            Ok(observation) => {
                let reusable = {
                    let publication = self.publication.read().unwrap_or_else(|e| e.into_inner());
                    match &*publication {
                        Publication::Ready(current) if current.version == observation.version => {
                            return;
                        }
                        Publication::DatabaseError {
                            previous: Some(previous),
                            ..
                        } if previous.version == observation.version => Some(Arc::clone(previous)),
                        _ => None,
                    }
                };
                if let Some(previous) = reusable {
                    let mut publication =
                        self.publication.write().unwrap_or_else(|e| e.into_inner());
                    if self.ticket.load(std::sync::atomic::Ordering::SeqCst) == ticket {
                        *publication = Publication::Ready(previous);
                    }
                    return;
                }
                let rewrites = match observation
                    .routes
                    .iter()
                    .filter(|route| route.enabled)
                    .filter_map(|route| {
                        route
                            .regex_rewrite_pattern
                            .as_deref()
                            .map(|pattern| (route.id, pattern))
                    })
                    .map(|(id, pattern)| regex::Regex::new(pattern).map(|regex| (id, regex)))
                    .collect::<Result<HashMap<_, _>, _>>()
                {
                    Ok(rewrites) => rewrites,
                    Err(_) => {
                        let mut publication =
                            self.publication.write().unwrap_or_else(|e| e.into_inner());
                        if self.ticket.load(std::sync::atomic::Ordering::SeqCst) == ticket {
                            *publication = Publication::Invalid;
                        }
                        return;
                    }
                };
                let routes = RouteCache::new();
                if routes.load(observation.routes.clone()).is_err() {
                    let mut publication =
                        self.publication.write().unwrap_or_else(|e| e.into_inner());
                    if self.ticket.load(std::sync::atomic::Ordering::SeqCst) == ticket {
                        *publication = Publication::Invalid;
                    }
                    return;
                }
                let mut publication = self.publication.write().unwrap_or_else(|e| e.into_inner());
                if self.ticket.load(std::sync::atomic::Ordering::SeqCst) != ticket {
                    return;
                }
                let budgets = self
                    .budgets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .reconcile(&observation.routes);
                *publication = Publication::Ready(Arc::new(Generation {
                    version: observation.version,
                    routes,
                    clients: Arc::new(RouteClientCache::new()),
                    load_balancer: Arc::new(LoadBalancer::new()),
                    budgets,
                    rewrites,
                }));
            }
            Err(error) if is_database_observation_error(&error) => {
                let mut publication = self.publication.write().unwrap_or_else(|e| e.into_inner());
                if self.ticket.load(std::sync::atomic::Ordering::SeqCst) != ticket {
                    return;
                }
                let replacement = match &*publication {
                    Publication::DatabaseError { previous, since } => Publication::DatabaseError {
                        previous: previous.clone(),
                        since: *since,
                    },
                    Publication::Ready(previous) => Publication::DatabaseError {
                        previous: Some(Arc::clone(previous)),
                        since: Instant::now(),
                    },
                    Publication::Initial | Publication::RefreshPending | Publication::Invalid => {
                        Publication::DatabaseError {
                            previous: None,
                            since: Instant::now(),
                        }
                    }
                };
                *publication = replacement;
            }
            Err(_) => {
                let mut publication = self.publication.write().unwrap_or_else(|e| e.into_inner());
                if self.ticket.load(std::sync::atomic::Ordering::SeqCst) == ticket {
                    *publication = Publication::Invalid;
                }
            }
        }
    }
}

fn is_database_observation_error(error: &Error) -> bool {
    matches!(error, Error::Database(_) | Error::ServiceUnavailable(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_host(authority: &str) -> crate::identity::CanonicalHost {
        crate::identity::CanonicalHost::from_authority(authority)
            .unwrap()
            .0
    }

    fn route() -> Route {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "name": "app",
            "from": "https://app.example",
            "to": ["http://127.0.0.1:9"],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap()
    }

    fn take_permit(selection: &mut RouteSelection) -> Option<OwnedSemaphorePermit> {
        selection.take_permit().expect("route admitted")
    }

    async fn publish_limit(
        store: &Store,
        generation: &RouteGeneration,
        route_id: Uuid,
        limit: usize,
    ) {
        store
            .update_route(route_id, serde_json::json!({"concurrency_limit": limit}))
            .await
            .unwrap();
        generation.observe_and_publish().await;
    }

    #[test]
    fn decreasing_budget_drains_returned_permits_and_zero_admits_none() {
        let budget = Arc::new(RouteBudget::new(2));
        let first = budget.try_acquire().unwrap();
        let second = budget.try_acquire().unwrap();
        budget.set_limit(0);
        drop(first);
        assert!(budget.try_acquire().is_err());
        drop(second);
        assert!(budget.try_acquire().is_err());
        budget.set_limit(1);
        let admitted = budget.try_acquire().unwrap();
        assert!(budget.try_acquire().is_err());
        drop(admitted);
        assert!(budget.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn production_selection_preserves_debt_across_limit_changes_and_permit_drops() {
        let store = Store::new_for_test("sqlite::memory:", [47; 32], None)
            .await
            .unwrap();
        let mut configured = route();
        configured.concurrency_limit = Some(3);
        store.create_route(&configured).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;

        let mut first = generation.find("app.example", "/").unwrap().unwrap();
        let mut second = generation.find("app.example", "/").unwrap().unwrap();
        let first_permit = take_permit(&mut first).unwrap();
        let second_permit = take_permit(&mut second).unwrap();

        // 3 -> 1 with two active permits creates one unit of debt. The first
        // returned permit repays it; no request may use that return as spare
        // capacity while the other old permit remains active.
        publish_limit(&store, &generation, configured.id, 1).await;
        let mut rejected = generation.find("app.example", "/").unwrap().unwrap();
        assert!(rejected.take_permit().is_err());
        drop(first_permit);
        let mut still_rejected = generation.find("app.example", "/").unwrap().unwrap();
        assert!(still_rejected.take_permit().is_err());
        drop(second_permit);
        let mut admitted = generation.find("app.example", "/").unwrap().unwrap();
        let admitted_permit = take_permit(&mut admitted).unwrap();

        publish_limit(&store, &generation, configured.id, 0).await;
        drop(admitted_permit);
        let mut zero = generation.find("app.example", "/").unwrap().unwrap();
        assert!(zero.take_permit().is_err(), "Some(0) must admit no request");

        // Raising while debt is outstanding cancels debt before adding any
        // capacity. Three pre-existing permits still fill a raised limit of
        // three until one of them is returned.
        publish_limit(&store, &generation, configured.id, 3).await;
        let mut a = generation.find("app.example", "/").unwrap().unwrap();
        let mut b = generation.find("app.example", "/").unwrap().unwrap();
        let mut c = generation.find("app.example", "/").unwrap().unwrap();
        let a_permit = take_permit(&mut a).unwrap();
        let b_permit = take_permit(&mut b).unwrap();
        let c_permit = take_permit(&mut c).unwrap();
        publish_limit(&store, &generation, configured.id, 1).await;
        publish_limit(&store, &generation, configured.id, 3).await;
        let mut full = generation.find("app.example", "/").unwrap().unwrap();
        assert!(full.take_permit().is_err());
        drop(a_permit);
        let mut after_drop = generation.find("app.example", "/").unwrap().unwrap();
        assert!(take_permit(&mut after_drop).is_some());
        drop(b_permit);
        drop(c_permit);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_admission_and_publication_have_one_total_order() {
        let store = Store::new_for_test("sqlite::memory:", [48; 32], None)
            .await
            .unwrap();
        let mut configured = route();
        configured.concurrency_limit = Some(1);
        store.create_route(&configured).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;
        let mut active = generation.find("app.example", "/").unwrap().unwrap();
        let active_permit = take_permit(&mut active).unwrap();

        store
            .update_route(configured.id, serde_json::json!({"concurrency_limit": 3}))
            .await
            .unwrap();
        let ticket = generation.ticket.load(std::sync::atomic::Ordering::SeqCst);
        let observed = store.observe_routes().await;

        let pause = generation.pause_next_admission_for_test();
        let lookup_generation = Arc::clone(&generation);
        let lookup = std::thread::spawn(move || {
            let mut selection = lookup_generation.find("app.example", "/").unwrap().unwrap();
            selection.take_permit()
        });
        pause.entered.wait();
        assert!(
            generation.publication.try_write().is_err(),
            "route match and admission did not retain the publication read guard"
        );
        pause.release.wait();
        assert!(
            lookup.join().unwrap().is_err(),
            "a full limit=1 generation admitted before the limit=3 publication"
        );

        generation.publish_observation(ticket, observed);
        let mut second = generation.find("app.example", "/").unwrap().unwrap();
        let mut third = generation.find("app.example", "/").unwrap().unwrap();
        let mut fourth = generation.find("app.example", "/").unwrap().unwrap();
        let second_permit = take_permit(&mut second).unwrap();
        let third_permit = take_permit(&mut third).unwrap();
        assert!(fourth.take_permit().is_err());
        drop(active_permit);
        drop(second_permit);
        drop(third_permit);
    }

    #[tokio::test]
    async fn database_error_lkg_does_not_extend_and_expires_at_thirty_seconds() {
        let store = Store::new_for_test("sqlite::memory:", [41; 32], None)
            .await
            .unwrap();
        store.create_route(&route()).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;
        assert!(generation.find("app.example", "/").unwrap().is_some());

        store.sqlite_pool().close().await;
        generation.observe_and_publish().await;
        assert!(!generation.is_ready());
        assert!(generation.find("app.example", "/").unwrap().is_some());
        assert_eq!(
            generation
                .redirect_host(&canonical_host("APP.EXAMPLE:80"))
                .unwrap(),
            Some("app.example".into())
        );
        generation.elapse_database_error_for_test(Duration::from_secs(10));
        generation.observe_and_publish().await;
        generation.elapse_database_error_for_test(Duration::from_secs(20));
        assert!(matches!(
            generation.find("app.example", "/"),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
        assert!(matches!(
            generation.redirect_host(&canonical_host("app.example")),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }

    #[tokio::test]
    async fn invalid_snapshot_withdraws_previous_generation_without_grace() {
        let store = Store::new_for_test("sqlite::memory:", [42; 32], None)
            .await
            .unwrap();
        let route = route();
        store.create_route(&route).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;
        assert!(generation.find("app.example", "/").unwrap().is_some());

        sqlx::query("UPDATE routes SET data = '{' WHERE id = ?")
            .bind(route.id)
            .execute(store.sqlite_pool())
            .await
            .unwrap();
        generation.observe_and_publish().await;
        assert!(matches!(
            generation.find("app.example", "/"),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
        assert!(matches!(
            generation.redirect_host(&canonical_host("app.example")),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }

    #[tokio::test]
    async fn disabled_invalid_route_does_not_invalidate_enabled_generation() {
        let store = Store::new_for_test("sqlite::memory:", [46; 32], None)
            .await
            .unwrap();
        let valid = route();
        let mut disabled = route();
        disabled.name = "disabled-invalid".into();
        disabled.from = "not a url".into();
        disabled.enabled = false;
        disabled.regex_rewrite_pattern = Some("(".into());
        disabled.regex_rewrite_substitution = Some("/replacement".into());
        store.create_route(&disabled).await.unwrap();
        store.create_route(&valid).await.unwrap();

        let generation = RouteGeneration::new_for_test(store).await;
        assert!(generation.find("app.example", "/").unwrap().is_some());
    }

    #[tokio::test]
    async fn local_refresh_withdraws_before_observation_completes() {
        let store = Store::new_for_test("sqlite::memory:", [43; 32], None)
            .await
            .unwrap();
        store.create_route(&route()).await.unwrap();
        let generation = RouteGeneration::new_for_test(store).await;
        assert!(generation.find("app.example", "/").unwrap().is_some());
        generation.request_refresh();
        assert!(matches!(
            generation.find("app.example", "/"),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
        assert!(matches!(
            generation.redirect_host(&canonical_host("app.example")),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }

    #[tokio::test]
    async fn redirect_host_tracks_enabled_route_publication_without_store_reads() {
        let store = Store::new_for_test("sqlite::memory:", [49; 32], None)
            .await
            .unwrap();
        let configured = route();
        let generation = RouteGeneration::new(store.clone());

        assert!(matches!(
            generation.redirect_host(&canonical_host("app.example")),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));

        store.create_route(&configured).await.unwrap();
        generation.observe_and_publish().await;
        assert_eq!(
            generation
                .redirect_host(&canonical_host("APP.EXAMPLE:80"))
                .unwrap(),
            Some("app.example".into())
        );

        store.delete_route(configured.id).await.unwrap();
        generation.observe_and_publish().await;
        assert_eq!(
            generation
                .redirect_host(&canonical_host("app.example"))
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn completed_stale_observation_cannot_overwrite_local_withdrawal() {
        let store = Store::new_for_test("sqlite::memory:", [45; 32], None)
            .await
            .unwrap();
        store.create_route(&route()).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;

        // Capture the exact result and ticket an observer held before the
        // local writer withdrew publication. Publishing that completed stale
        // result must not resurrect the old generation.
        let stale_ticket = generation.ticket.load(std::sync::atomic::Ordering::SeqCst);
        let stale_observation = store.observe_routes().await;
        generation.request_refresh();
        generation.publish_observation(stale_ticket, stale_observation);

        assert!(matches!(
            generation.find("app.example", "/"),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }

    #[tokio::test]
    async fn selection_and_permit_do_not_retain_whole_generation() {
        let store = Store::new_for_test("sqlite::memory:", [44; 32], None)
            .await
            .unwrap();
        let mut first = route();
        first.concurrency_limit = Some(1);
        store.create_route(&first).await.unwrap();
        let generation = RouteGeneration::new_for_test(store.clone()).await;
        let weak = generation.current_weak_for_test();
        let mut selection = generation.find("app.example", "/").unwrap().expect("route");
        let permit = selection.take_permit().unwrap().expect("limited route");

        store
            .update_route(first.id, serde_json::json!({"timeout_ms": 1234}))
            .await
            .unwrap();
        generation.request_refresh();
        generation.observe_and_publish().await;
        assert!(weak.upgrade().is_none());
        drop(selection);
        drop(permit);
    }
}
