//! What to do with a parsed query: answer it, or forward it.
//!
//! ── ★ THERE IS NO `NxDomain` VARIANT, AND THAT IS THE DESIGN ───────────
//!
//! annai is a **stub resolver**: it holds a small table of fleet names and
//! forwards everything else. It is authoritative for nothing.
//!
//! The catastrophic bug for a program in that position is answering "this
//! name does not exist" for a name it simply does not hold — because from the
//! client's side an authoritative NXDOMAIN is indistinguishable from the truth,
//! and it is CACHED. One such answer takes a name off the network for the
//! whole TTL, for every process on the host, and the resolver looks healthy
//! throughout.
//!
//! So [`Decision`] has no way to express it. A table miss is [`Decision::Forward`]
//! and there is no other arm it could reach — not a runtime guard, not a
//! default branch someone can invert later, but an enum with the variant
//! absent. TIER: truly-unrepresentable for this layer (the type admits no such
//! value); a future authoritative mode would be a DIFFERENT type, not a fourth
//! arm here.
//!
//! ── ★ AND AN UNIMPLEMENTED QTYPE FORWARDS, TOO ─────────────────────────
//!
//! The same trap wearing different clothes: `rio` is in the table with an A
//! record, a client asks for `MX rio`, and a resolver that keys only on the
//! NAME answers "no MX" authoritatively. The name matched; the type did not.
//! [`Decision::of`] matches on BOTH, so a known name with an unheld type
//! forwards rather than being denied.

use std::net::IpAddr;

use crate::measured::{Freshness, Measured};
use crate::table::Table;
use crate::wire::{QType, Query};

/// What annai does with one query. Two arms, deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Answer locally with these addresses. Never empty — see [`Decision::of`].
    Answer(Vec<IpAddr>),
    /// Send it upstream. The only outcome for anything not held locally.
    Forward,
    Measured(Vec<IpAddr>),
    Fallback(Vec<IpAddr>),
    Explain(Vec<String>),
}

impl Decision {
    /// Decide one query against the table.
    #[must_use]
    pub fn of(table: &Table, q: &Query) -> Self {
        let want_v4 = match q.qtype {
            QType::A => true,
            QType::Aaaa => false,
            // ★ Not a catch-all that could later swallow a type we DO answer:
            // every locally-answerable type is named above, so adding one is a
            // compile-time match arm rather than a silent behaviour change.
            QType::Txt | QType::Other(_) => return Self::Forward,
        };

        let addrs: Vec<IpAddr> = table
            .lookup(&q.name)
            .iter()
            .copied()
            .filter(|a| a.is_ipv4() == want_v4)
            .collect();

        // ★ AN EMPTY MATCH IS A FORWARD, NOT AN EMPTY ANSWER. A name held
        // with only an A record, asked for AAAA, must not be answered "yes
        // this name exists and has no IPv6" — that is a NODATA reply, which
        // is cached exactly like NXDOMAIN and suppresses the upstream's real
        // answer. This is why `Answer` is never constructed empty.
        if addrs.is_empty() {
            Self::Forward
        } else {
            Self::Answer(addrs)
        }
    }

    #[must_use]
    pub fn resolve(table: &Table, measured: &Measured, q: &Query, now_ms: u64) -> Self {
        if measured.candidates.of(&q.name).is_none() {
            return Self::of(table, q);
        }
        let want_v4 = match q.qtype {
            QType::A => true,
            QType::Aaaa => false,
            QType::Txt => {
                return match measured.explain(&q.name, now_ms) {
                    Some(why) if !why.is_empty() => Self::Explain(why),
                    _ => Self::Forward,
                };
            }
            QType::Other(_) => return Self::Forward,
        };
        let chosen: Option<Vec<IpAddr>> = measured.with(now_ms, |fresh| match fresh {
            Freshness::Fresh(a) => a.names.get(q.name.as_str()).map(|n| {
                n.order
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv4() == want_v4)
                    .take(2)
                    .collect()
            }),
            _ => None,
        });
        match chosen {
            Some(addrs) if !addrs.is_empty() => Self::Measured(addrs),
            _ => match Self::of(table, q) {
                Self::Answer(addrs) => Self::Fallback(addrs),
                other => other,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Name;

    fn table() -> Table {
        let mut t = Table::new();
        t.insert(Name::from_host("rio"), "192.0.2.66".parse().expect("ip"));
        t.insert(
            Name::from_host("rio.example.net"),
            "192.0.2.66".parse().expect("ip"),
        );
        t.insert(Name::from_host("v6only"), "fd00::1".parse().expect("ip"));
        t
    }

    fn q(name: &str, qtype: QType) -> Query {
        Query {
            id: 1,
            name: Name::from_host(name),
            qtype,
        }
    }

    #[test]
    fn a_held_name_is_answered_locally() {
        assert_eq!(
            Decision::of(&table(), &q("rio", QType::A)),
            Decision::Answer(vec!["192.0.2.66".parse().expect("ip")])
        );
    }

    #[test]
    fn an_unheld_name_forwards_and_cannot_be_denied() {
        // The decision type has no NXDOMAIN arm, so this cannot regress into
        // one without changing the enum — which a reviewer would see.
        assert_eq!(
            Decision::of(&table(), &q("nixos.org", QType::A)),
            Decision::Forward
        );
    }

    #[test]
    fn a_held_name_with_an_unheld_type_forwards_rather_than_denying() {
        // `rio` IS in the table, but with no MX. Keying on the name alone
        // would answer "no MX for rio" authoritatively and break mail.
        assert_eq!(
            Decision::of(&table(), &q("rio", QType::Other(15))),
            Decision::Forward
        );
    }

    #[test]
    fn an_ipv4_only_name_asked_for_ipv6_forwards_rather_than_returning_nodata() {
        // NODATA is cached like NXDOMAIN and suppresses the upstream answer.
        assert_eq!(
            Decision::of(&table(), &q("rio", QType::Aaaa)),
            Decision::Forward
        );
    }

    #[test]
    fn the_families_do_not_cross() {
        assert_eq!(
            Decision::of(&table(), &q("v6only", QType::Aaaa)),
            Decision::Answer(vec!["fd00::1".parse().expect("ip")])
        );
        assert_eq!(
            Decision::of(&table(), &q("v6only", QType::A)),
            Decision::Forward
        );
    }

    #[test]
    fn an_answer_is_never_empty() {
        // Pins the invariant `Decision::of` maintains, so a future edit that
        // returns `Answer(vec![])` fails here rather than in production as a
        // cached NODATA.
        for name in ["rio", "v6only", "nixos.org", "rio.example.net"] {
            for t in [QType::A, QType::Aaaa, QType::Txt, QType::Other(15)] {
                if let Decision::Answer(a) = Decision::of(&table(), &q(name, t)) {
                    assert!(!a.is_empty(), "{name} {t:?} produced an empty Answer");
                }
            }
        }
    }

    #[test]
    fn lookup_is_case_insensitive_end_to_end() {
        assert_eq!(
            Decision::of(&table(), &q("RIO.Example.Net", QType::A)),
            Decision::Answer(vec!["192.0.2.66".parse().expect("ip")])
        );
    }

    mod measured {
        use super::*;
        use crate::measured::{Answers, Candidates, Measured};

        fn m() -> std::sync::Arc<Measured> {
            let raw = serde_yaml::from_str(
                "cid.pleme.internal:\n  - { addr: 192.168.60.138, path: lan, rung: 1, port: 22 }\n  - { addr: 100.104.30.81, path: ts, rung: 2, port: 22 }\n",
            )
            .expect("parse");
            Measured::new(
                Candidates::from_config(&raw),
                Some("ryn".into()),
                10_000,
                5,
                Some("/nonexistent".into()),
            )
        }

        fn t() -> Table {
            let mut t = Table::new();
            t.insert(
                Name::from_host("cid.pleme.internal"),
                "100.104.30.81".parse().expect("ip"),
            );
            t.insert(Name::from_host("rio"), "192.0.2.66".parse().expect("ip"));
            t
        }

        fn answers(at_ms: u64, order: &[&str]) -> Answers {
            Answers {
                at_ms,
                from: "ryn".into(),
                names: [(
                    "cid.pleme.internal".to_owned(),
                    crate::measured::NamedAnswer {
                        order: order.iter().map(|a| a.parse().expect("ip")).collect(),
                        why: vec!["path=lan chosen=yes".into()],
                    },
                )]
                .into(),
            }
        }

        #[test]
        fn fresh_answers_choose_the_order() {
            let m = m();
            m.store(answers(1_000, &["192.168.60.138", "100.104.30.81"]));
            assert_eq!(
                Decision::resolve(&t(), &m, &q("cid.pleme.internal", QType::A), 2_000),
                Decision::Measured(vec![
                    "192.168.60.138".parse().expect("ip"),
                    "100.104.30.81".parse().expect("ip")
                ])
            );
        }

        #[test]
        fn stale_answers_fall_back_to_the_static_table() {
            let m = m();
            m.store(answers(1_000, &["192.168.60.138"]));
            assert_eq!(
                Decision::resolve(&t(), &m, &q("cid.pleme.internal", QType::A), 20_000),
                Decision::Fallback(vec!["100.104.30.81".parse().expect("ip")])
            );
        }

        #[test]
        fn no_answers_yet_is_the_static_table_never_a_refusal() {
            assert_eq!(
                Decision::resolve(&t(), &m(), &q("cid.pleme.internal", QType::A), 0),
                Decision::Fallback(vec!["100.104.30.81".parse().expect("ip")])
            );
        }

        #[test]
        fn a_name_without_candidates_is_the_table_as_before() {
            assert_eq!(
                Decision::resolve(&t(), &m(), &q("rio", QType::A), 0),
                Decision::Answer(vec!["192.0.2.66".parse().expect("ip")])
            );
            assert_eq!(
                Decision::resolve(&t(), &m(), &q("rio", QType::Txt), 0),
                Decision::Forward
            );
        }

        #[test]
        fn txt_explains_a_candidate_name() {
            let m = m();
            m.store(answers(1_000, &["192.168.60.138"]));
            assert_eq!(
                Decision::resolve(&t(), &m, &q("cid.pleme.internal", QType::Txt), 1_000),
                Decision::Explain(vec!["path=lan chosen=yes".into()])
            );
        }

        #[test]
        fn a_family_with_no_measured_address_falls_back_rather_than_answering_empty() {
            let m = m();
            m.store(answers(1_000, &["192.168.60.138"]));
            assert_eq!(
                Decision::resolve(&t(), &m, &q("cid.pleme.internal", QType::Aaaa), 1_000),
                Decision::Forward
            );
        }
    }
}
