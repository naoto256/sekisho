//! Shared pagination shape for list endpoints.
//!
//! Paginated list endpoints accept `?limit=...&offset=...` and respond with
//! `{ items, limit, offset, has_more }`. Store queries fetch one probe row
//! beyond the public limit; handlers remove that row before responding.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

pub fn normalize(q: PageQuery) -> (i64, i64) {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = q.offset.unwrap_or(0).max(0);
    (limit, offset)
}

/// Wrap an already-paged slice into the standard response shape.
/// Callers that page at the store layer (e.g. sessions) use this directly.
pub fn wrap<T: Serialize>(
    items: &[T],
    limit: i64,
    offset: i64,
    has_more: bool,
) -> serde_json::Value {
    serde_json::json!({
        "items": items,
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
    })
}

/// Remove the store's lookahead row and report whether it was present.
pub fn remove_probe<T>(items: &mut Vec<T>, limit: i64) -> bool {
    let has_more = items.len() > limit as usize;
    items.truncate(limit as usize);
    has_more
}

#[cfg(test)]
mod tests {
    use super::{PageQuery, normalize, remove_probe};

    #[test]
    fn normalize_preserves_the_public_default_and_bounds() {
        assert_eq!(
            normalize(PageQuery {
                limit: None,
                offset: None,
            }),
            (100, 0)
        );
        assert_eq!(
            normalize(PageQuery {
                limit: Some(1_001),
                offset: Some(-1),
            }),
            (1_000, 0)
        );
        assert_eq!(
            normalize(PageQuery {
                limit: Some(0),
                offset: Some(7),
            }),
            (1, 7)
        );
    }

    #[test]
    fn remove_probe_distinguishes_an_exact_page_from_a_lookahead_row() {
        let mut exact = vec![1, 2];
        assert!(!remove_probe(&mut exact, 2));
        assert_eq!(exact, [1, 2]);

        let mut with_probe = vec![1, 2, 3];
        assert!(remove_probe(&mut with_probe, 2));
        assert_eq!(with_probe, [1, 2]);
    }
}
