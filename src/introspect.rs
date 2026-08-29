//! annai's kanshou surface — the citizen shape's introspection half.
//!
//! Same doctrine as `sentinela`'s, and for the same reason: a resolver that
//! can only be read through its logs is a resolver whose answers you cannot
//! check. **Every answer carries `answered_at_unix_ms`**, so a reading cannot
//! be mistaken for a fresher one than it is — the receipt that motivated
//! sentinela's surface applies unchanged.
//!
//! ★ The counters are the point of difference. A stub resolver's whole
//! behaviour is the SPLIT between answered-locally and forwarded, and that
//! ratio is invisible from outside: a table that silently stopped loading
//! still resolves everything, just slower and via the upstream, with no error
//! anywhere. `local` falling to zero while `forwarded` climbs is the only
//! signal that the registry broke — which is precisely the shape of the
//! seatd defect (a thing working for the wrong reason, reporting nothing).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kanshou::{Introspect, Query as KQuery, QueryError, QueryResult};

use crate::table::Table;

/// Live counters plus the table, as the daemon's askable state.
pub struct AnnaiIntrospect {
    table: Table,
    local: AtomicU64,
    forwarded: AtomicU64,
    refused: AtomicU64,
    started_unix_ms: u64,
    now: fn() -> u64,
}

impl AnnaiIntrospect {
    #[must_use]
    pub fn new(table: Table, started_unix_ms: u64, now: fn() -> u64) -> Arc<Self> {
        Arc::new(Self {
            table,
            local: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            started_unix_ms,
            now,
        })
    }

    /// Record one query answered from the local table.
    pub fn count_local(&self) {
        self.local.fetch_add(1, Ordering::Relaxed);
    }
    /// Record one query sent upstream.
    pub fn count_forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }
    /// Record one malformed message refused at the wire.
    pub fn count_refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }
}

impl Introspect for AnnaiIntrospect {
    fn query(&self, q: &KQuery) -> QueryResult {
        let now = (self.now)();
        let path: Vec<&str> = q.path.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["table"] => Ok(serde_json::json!({
                // ★ The denominator lives INSIDE the answer. A table that
                // stopped loading reports names: 0 rather than being absent,
                // so "the registry broke" is readable rather than inferable.
                "names": self.table.len(),
                "empty": self.table.is_empty(),
                "answered_at_unix_ms": now,
            })),
            ["counters"] => {
                let local = self.local.load(Ordering::Relaxed);
                let forwarded = self.forwarded.load(Ordering::Relaxed);
                Ok(serde_json::json!({
                    "local": local,
                    "forwarded": forwarded,
                    "refused": self.refused.load(Ordering::Relaxed),
                    // The ratio is the health signal; computed here so every
                    // consumer reads the same definition of it.
                    // ★ The ratio as an EXACT rational, not a float. The f64
                    // form loses precision above 2^53 queries, and a resolver
                    // on a busy node reaches that in months -- at which point
                    // the health signal silently degrades rather than
                    // erroring. Numerator and denominator are both already
                    // integers here; handing them over keeps the definition
                    // single-sourced without inventing a lossy step.
                    "local_share": if local + forwarded == 0 {
                        // Null, not 0.0: zero reads as "everything forwarded",
                        // which is a real and alarming state. No data is not
                        // the same finding as bad data.
                        serde_json::Value::Null
                    } else {
                        serde_json::json!({ "of": local, "in": local + forwarded })
                    },
                    "answered_at_unix_ms": now,
                }))
            }
            ["uptime"] => Ok(serde_json::json!({
                "started_unix_ms": self.started_unix_ms,
                "age_ms": now.saturating_sub(self.started_unix_ms),
                "answered_at_unix_ms": now,
            })),
            _ => Err(QueryError::UnknownField {
                field: q.path.join("."),
            }),
        }
    }

    fn schema(&self) -> &'static [&'static str] {
        &["table", "counters", "uptime"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Name;

    fn fixed_now() -> u64 {
        5_000
    }

    fn subject() -> Arc<AnnaiIntrospect> {
        let mut t = Table::new();
        t.insert(Name::from_host("rio"), "10.0.0.1".parse().expect("ip"));
        AnnaiIntrospect::new(t, 1_000, fixed_now)
    }

    #[test]
    fn the_table_size_is_reported_as_a_denominator() {
        let v = subject().query(&KQuery::field(["table"])).expect("ok");
        assert_eq!(v["names"], 1);
        assert_eq!(v["empty"], false);
    }

    #[test]
    fn an_empty_table_reports_zero_rather_than_being_absent() {
        // A registry that stopped loading must be READABLE, not inferable
        // from a missing field — the seatd shape, where a thing works for the
        // wrong reason and reports nothing.
        let i = AnnaiIntrospect::new(Table::new(), 1_000, fixed_now);
        let v = i.query(&KQuery::field(["table"])).expect("ok");
        assert_eq!(v["names"], 0);
        assert_eq!(v["empty"], true);
    }

    #[test]
    fn the_local_share_is_null_before_any_query_not_zero() {
        // Zero would read as "everything forwarded", which is a real and
        // alarming state. No data is not the same finding as bad data.
        let v = subject().query(&KQuery::field(["counters"])).expect("ok");
        assert!(v["local_share"].is_null());
    }

    #[test]
    fn the_counters_move() {
        let i = subject();
        i.count_local();
        i.count_local();
        i.count_forwarded();
        i.count_refused();
        let v = i.query(&KQuery::field(["counters"])).expect("ok");
        assert_eq!(v["local"], 2);
        assert_eq!(v["forwarded"], 1);
        assert_eq!(v["refused"], 1);
        // Exact, not a float comparison — the ratio is a rational.
        assert_eq!(v["local_share"]["of"], 2);
        assert_eq!(v["local_share"]["in"], 3);
    }

    #[test]
    fn every_answer_carries_when_it_was_answered() {
        let i = subject();
        for leaf in i.schema() {
            let v = i.query(&KQuery::field(leaf.split('.'))).expect("ok");
            assert_eq!(v["answered_at_unix_ms"], 5_000, "leaf {leaf}");
        }
    }

    #[test]
    fn every_advertised_leaf_answers() {
        let i = subject();
        for leaf in i.schema() {
            assert!(i.query(&KQuery::field(leaf.split('.'))).is_ok(), "{leaf}");
        }
    }

    #[test]
    fn an_unknown_leaf_is_refused_by_name() {
        let e = subject()
            .query(&KQuery::field(["nope"]))
            .expect_err("refuse");
        assert_eq!(
            e,
            QueryError::UnknownField {
                field: "nope".into()
            }
        );
    }
}
