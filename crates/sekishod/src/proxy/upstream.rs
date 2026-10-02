//! Upstream selection for routes with more than one backend.
//!
//! Round-robin uses a per-route cursor owned by one published route
//! generation. Random selection is a memoryless uniform draw with replacement:
//! it keeps no cursor, does not acquire the round-robin lock, and may select the
//! same backend on consecutive requests. Both strategies are node-local. There
//! is no health checking, so an unhealthy backend remains eligible until the
//! route configuration changes.

use crate::models::route::LoadBalancing;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Per-route state for round-robin selection.
///
/// Owned by a route generation rather than by the process: publishing a route
/// change builds a new balancer, so a cursor can never be applied to an
/// upstream list it was not counting against. That is also why a stale route's
/// entry needs no eviction — the whole map goes with the generation.
///
/// A `std::sync::Mutex` and not an async one: the critical section is a
/// modulo and an increment, so the lock is never held across an await and
/// contention costs less than a task reschedule would. Random selection
/// bypasses this state and lock entirely.
pub struct LoadBalancer {
    counters: Mutex<HashMap<Uuid, usize>>,
}

impl LoadBalancer {
    /// Start with no round-robin cursors; Random never creates one.
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn select(&self, route_id: Uuid, num_upstreams: usize, strategy: &LoadBalancing) -> usize {
        self.select_with_random_index(route_id, num_upstreams, strategy, |upper| {
            rand::rng().random_range(0..upper)
        })
    }

    fn select_with_random_index(
        &self,
        route_id: Uuid,
        num_upstreams: usize,
        strategy: &LoadBalancing,
        random_index: impl FnOnce(usize) -> usize,
    ) -> usize {
        if num_upstreams <= 1 {
            return 0;
        }

        match strategy {
            LoadBalancing::RoundRobin => self.select_round_robin(route_id, num_upstreams),
            LoadBalancing::Random => random_index(num_upstreams),
        }
    }

    /// Counter keyed by `route_id`, held by one published route generation.
    /// A coherent route change builds a new load balancer, so counters never
    /// mix upstream sets from different versions. No cross-node fairness is
    /// provided by this method.
    // Recover from a poisoned lock instead of propagating the panic: the
    // guarded state is only a round-robin counter, so refusing to serve the
    // route would be worse than a temporarily uneven spread.
    fn select_round_robin(&self, route_id: Uuid, num_upstreams: usize) -> usize {
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        let counter = counters.entry(route_id).or_insert(0);
        let index = *counter % num_upstreams;
        *counter = counter.wrapping_add(1);
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route::LoadBalancing;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn seeded_random_sequence(route_id: Uuid, seed: u64, len: usize) -> Vec<usize> {
        let balancer = LoadBalancer::new();
        let mut rng = StdRng::seed_from_u64(seed);
        (0..len)
            .map(|_| {
                balancer.select_with_random_index(route_id, 4, &LoadBalancing::Random, |upper| {
                    rng.random_range(0..upper)
                })
            })
            .collect()
    }

    #[test]
    fn t1_zero_and_one_upstream_do_not_consult_state_or_randomness() {
        let balancer = LoadBalancer::new();
        let route_id = Uuid::new_v4();

        for strategy in [LoadBalancing::RoundRobin, LoadBalancing::Random] {
            assert_eq!(
                balancer.select_with_random_index(route_id, 0, &strategy, |_| panic!()),
                0
            );
            assert_eq!(
                balancer.select_with_random_index(route_id, 1, &strategy, |_| panic!()),
                0
            );
        }
        assert!(balancer.counters.lock().unwrap().is_empty());
    }

    #[test]
    fn t2_seeded_random_selection_is_reproducible_and_in_range() {
        let route_id = Uuid::new_v4();
        let first = seeded_random_sequence(route_id, 0x5e_1e_c7, 512);
        let second = seeded_random_sequence(route_id, 0x5e_1e_c7, 512);

        assert_eq!(first, second);
        assert!(first.iter().all(|index| *index < 4));
    }

    #[test]
    fn t3_seeded_random_selection_is_uniform() {
        let balancer = LoadBalancer::new();
        let route_id = Uuid::new_v4();
        let mut rng = StdRng::seed_from_u64(0x5117_5eed);
        let mut counts = [0usize; 4];
        const DRAWS: usize = 40_000;

        for _ in 0..DRAWS {
            let index = balancer.select_with_random_index(
                route_id,
                counts.len(),
                &LoadBalancing::Random,
                |upper| rng.random_range(0..upper),
            );
            counts[index] += 1;
        }

        let expected = DRAWS / counts.len();
        let tolerance = expected / 20;
        for count in counts {
            assert!(count.abs_diff(expected) <= tolerance, "counts={counts:?}");
        }
    }

    #[test]
    fn t4_random_selection_is_memoryless_and_route_independent() {
        let first = seeded_random_sequence(Uuid::new_v4(), 0xfeed_ba5e, 512);
        let second = seeded_random_sequence(Uuid::new_v4(), 0xfeed_ba5e, 512);

        assert_eq!(first, second);
        assert!(first.windows(2).any(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn t5_random_selection_never_creates_or_advances_a_round_robin_counter() {
        let balancer = LoadBalancer::new();
        let route_id = Uuid::new_v4();

        for _ in 0..128 {
            assert!(balancer.select(route_id, 3, &LoadBalancing::Random) < 3);
        }
        assert!(balancer.counters.lock().unwrap().is_empty());

        assert_eq!(balancer.select(route_id, 3, &LoadBalancing::RoundRobin), 0);
        balancer.select(route_id, 3, &LoadBalancing::Random);
        assert_eq!(balancer.select(route_id, 3, &LoadBalancing::RoundRobin), 1);
    }

    #[test]
    fn t6_round_robin_remains_cyclic_route_local_and_generation_local() {
        let balancer = LoadBalancer::new();
        let first_route = Uuid::new_v4();
        let second_route = Uuid::new_v4();
        let select = |route_id| balancer.select(route_id, 3, &LoadBalancing::RoundRobin);

        assert_eq!(
            [
                select(first_route),
                select(first_route),
                select(first_route),
                select(first_route),
            ],
            [0, 1, 2, 0]
        );
        assert_eq!(select(second_route), 0);

        let next_generation = LoadBalancer::new();
        assert_eq!(
            next_generation.select(first_route, 3, &LoadBalancing::RoundRobin),
            0
        );
    }
}
