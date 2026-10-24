//! Tying it together: decide, forward, answer.
//!
//! ── ★ THE THIRD INSTANCE OF THE SAME FAILURE CLASS ─────────────────────
//!
//! [`decide`](crate::decide) has no `NxDomain` because a name annai does not
//! HOLD must not be reported as a name that does not EXIST. This module faces
//! the same trap from the other side: when the **upstream is unreachable**,
//! the honest answer is `SERVFAIL` (RCODE 2), never `NXDOMAIN` (RCODE 3).
//!
//! The difference is entirely in how long the damage lasts. `SERVFAIL` is a
//! transient error a resolver retries; `NXDOMAIN` is a *fact about the world*
//! that clients and downstream caches store for the negative TTL. Answering
//! NXDOMAIN because a UDP send failed converts a five-second network blip into
//! minutes of "that host does not exist" for every process on the machine —
//! and the resolver reports nothing wrong, because from its side it answered.
//!
//! So [`Rcode`] has no `NxDomain` variant either. annai never mints one; the
//! only NXDOMAIN a client can receive through annai is one the upstream
//! actually sent, relayed verbatim in bytes annai does not author.

use std::sync::Arc;

use crate::decide::Decision;
use crate::introspect::AnnaiIntrospect;
use crate::measured::Measured;
use crate::table::Table;
use crate::wire::{Query, Record, WireError, encode_records, encode_response};

#[must_use]
pub fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The response codes annai itself can mint.
///
/// ★ There is no `NxDomain`. See the module docs: annai is authoritative for
/// nothing, so a name's non-existence is never annai's finding to report. An
/// upstream's NXDOMAIN reaches the client as relayed bytes, not as a value
/// constructed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    /// The message could not be parsed. RFC 1035 RCODE 1.
    FormatError,
    /// We could not reach the upstream. RCODE 2 — transient, retried, and
    /// crucially NOT cached as a fact about the name.
    ServFail,
}

impl Rcode {
    #[must_use]
    pub fn wire(self) -> u16 {
        match self {
            Self::FormatError => 1,
            Self::ServFail => 2,
        }
    }
}

/// What annai sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Bytes annai authored from its own table.
    Local(Vec<u8>),
    /// Bytes the upstream authored, relayed unmodified.
    ///
    /// ★ Unmodified is load-bearing: rewriting a forwarded answer would make
    /// annai the author of a claim it did not verify, and any bug in the
    /// rewrite would be indistinguishable from upstream misbehaviour.
    Relayed(Vec<u8>),
    /// An error annai minted. Never NXDOMAIN.
    Error { rcode: Rcode, id: u16 },
}

/// Why a forward failed. Every variant is transient by construction — there is
/// no "the name does not exist" arm, because that is not a forwarding outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// No upstream answered within the budget.
    Timeout,
    /// The socket layer refused or failed.
    Unreachable(String),
    /// Every configured upstream was tried and none answered.
    NoUpstreamConfigured,
}

/// The side-effecting seam: sending a query to an upstream and getting bytes.
///
/// ★ One method, so the whole resolve path is testable with a fake that never
/// touches a socket — the fleet's mockable-`Environment` shape.
pub trait Upstream: Send + Sync {
    /// Forward the raw query and return the raw response.
    ///
    /// # Errors
    /// Any [`ForwardError`]; all are transient and none assert non-existence.
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError>;
}

/// The resolver: table, upstream, counters.
pub struct Resolver<U: Upstream> {
    table: Table,
    upstream: U,
    counters: Arc<AnnaiIntrospect>,
    measured: Arc<Measured>,
    now: fn() -> u64,
}

impl<U: Upstream> Resolver<U> {
    #[must_use]
    pub fn new(table: Table, upstream: U, counters: Arc<AnnaiIntrospect>) -> Self {
        Self {
            table,
            upstream,
            counters,
            measured: Measured::off(),
            now: system_now_ms,
        }
    }

    #[must_use]
    pub fn with_measured(mut self, measured: Arc<Measured>, now: fn() -> u64) -> Self {
        self.measured = measured;
        self.now = now;
        self
    }

    /// Handle one datagram. The whole decision path, socket-free.
    #[must_use]
    pub fn handle(&self, packet: &[u8]) -> Reply {
        let q = match Query::parse(packet) {
            Ok(q) => q,
            Err(e) => {
                self.counters.count_refused();
                // ★ A MALFORMED PACKET IS NEVER FORWARDED. Relaying garbage
                // upstream would make annai a reflector: an attacker sends us
                // one bad datagram and we spend a query against a resolver
                // that will rate-limit US for it. Refuse locally.
                //
                // The id is best-effort: if we could not even read the header
                // there is nothing to echo, and 0 is the honest answer.
                let id = if packet.len() >= 2 {
                    u16::from_be_bytes([packet[0], packet[1]])
                } else {
                    0
                };
                debug_assert!(matches!(
                    e,
                    WireError::Truncated { .. }
                        | WireError::NonDecreasingPointer { .. }
                        | WireError::JumpBudgetExhausted
                        | WireError::LabelTooLong { .. }
                        | WireError::NameTooLong
                        | WireError::ShortHeader { .. }
                        | WireError::NoQuestion
                ));
                return Reply::Error {
                    rcode: Rcode::FormatError,
                    id,
                };
            }
        };

        let rd = packet.get(2).is_some_and(|b| b & 0x01 != 0);
        let ttl = self.measured.ttl;
        let addr_records = |addrs: Vec<std::net::IpAddr>| -> Vec<Record> {
            addrs.into_iter().map(Record::Addr).collect()
        };
        match Decision::resolve(&self.table, &self.measured, &q, (self.now)()) {
            Decision::Answer(addrs) => {
                self.counters.count_local();
                Reply::Local(encode_response(&q, &addrs, rd))
            }
            Decision::Measured(addrs) => {
                self.counters.count_local();
                self.counters.count_measured();
                Reply::Local(encode_records(&q, &addr_records(addrs), ttl, rd))
            }
            Decision::Fallback(addrs) => {
                self.counters.count_local();
                self.counters.count_stale();
                Reply::Local(encode_records(&q, &addr_records(addrs), ttl, rd))
            }
            Decision::Explain(lines) => {
                self.counters.count_local();
                let records: Vec<Record> = lines.into_iter().map(Record::Txt).collect();
                Reply::Local(encode_records(&q, &records, ttl, rd))
            }
            Decision::Forward => {
                self.counters.count_forwarded();
                match self.upstream.forward(packet) {
                    Ok(bytes) => Reply::Relayed(bytes),
                    // ★ SERVFAIL, NEVER NXDOMAIN. A dead upstream is not
                    // evidence about a name. `Rcode` has no NXDOMAIN variant,
                    // so this cannot regress into one without changing a type.
                    Err(_) => Reply::Error {
                        rcode: Rcode::ServFail,
                        id: q.id,
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Name;
    use kanshou::{Introspect, Query as KQuery};

    struct Dead;
    impl Upstream for Dead {
        fn forward(&self, _: &[u8]) -> Result<Vec<u8>, ForwardError> {
            Err(ForwardError::Timeout)
        }
    }
    struct Echo(Vec<u8>);
    impl Upstream for Echo {
        fn forward(&self, _: &[u8]) -> Result<Vec<u8>, ForwardError> {
            Ok(self.0.clone())
        }
    }
    /// Records whether it was called at all — for the no-reflection test.
    struct Spy(std::sync::atomic::AtomicUsize);
    impl Upstream for Spy {
        fn forward(&self, _: &[u8]) -> Result<Vec<u8>, ForwardError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(vec![0, 0])
        }
    }

    fn counters() -> Arc<AnnaiIntrospect> {
        AnnaiIntrospect::new(Table::new(), 0, || 1)
    }

    fn table() -> Table {
        let mut t = Table::new();
        t.insert(Name::from_host("rio"), "10.0.0.1".parse().expect("ip"));
        t
    }

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            v.push(u8::try_from(label.len()).expect("len"));
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    #[test]
    fn a_dead_upstream_is_servfail_never_nxdomain() {
        // THE test. NXDOMAIN is cached as a fact about the world; SERVFAIL is
        // a transient error. Answering the former for a network blip takes a
        // host off the network for the negative TTL, for every process, while
        // the resolver reports nothing wrong.
        let r = Resolver::new(table(), Dead, counters());
        assert_eq!(
            r.handle(&query_bytes("nixos.org", 1)),
            Reply::Error {
                rcode: Rcode::ServFail,
                id: 0x1234
            }
        );
        assert_eq!(Rcode::ServFail.wire(), 2, "RCODE 2, not 3");
    }

    #[test]
    fn a_malformed_packet_is_never_forwarded() {
        // Relaying garbage would make annai a reflector: one bad datagram in,
        // one real upstream query out, and the upstream rate-limits US.
        let spy = Spy(std::sync::atomic::AtomicUsize::new(0));
        let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&[0xC0, 0x0C]); // the self-pointer
        let r = Resolver::new(table(), spy, counters());
        assert!(matches!(
            r.handle(&buf),
            Reply::Error {
                rcode: Rcode::FormatError,
                ..
            }
        ));
        assert_eq!(
            r.upstream.0.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a malformed packet reached the upstream"
        );
    }

    #[test]
    fn a_held_name_is_answered_locally_without_touching_the_upstream() {
        let spy = Spy(std::sync::atomic::AtomicUsize::new(0));
        let r = Resolver::new(table(), spy, counters());
        assert!(matches!(r.handle(&query_bytes("rio", 1)), Reply::Local(_)));
        assert_eq!(r.upstream.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn a_forwarded_answer_is_relayed_unmodified() {
        // Rewriting would make annai the author of a claim it did not verify.
        let upstream_bytes = vec![9, 9, 9, 9, 1, 2, 3];
        let r = Resolver::new(table(), Echo(upstream_bytes.clone()), counters());
        assert_eq!(
            r.handle(&query_bytes("nixos.org", 1)),
            Reply::Relayed(upstream_bytes)
        );
    }

    #[test]
    fn the_counters_reflect_the_split() {
        let c = counters();
        let r = Resolver::new(table(), Echo(vec![0, 0]), Arc::clone(&c));
        let _ = r.handle(&query_bytes("rio", 1));
        let _ = r.handle(&query_bytes("nixos.org", 1));
        let _ = r.handle(&[0x00]);
        let v = c.query(&KQuery::field(["counters"])).expect("ok");
        assert_eq!(v["local"], 1);
        assert_eq!(v["forwarded"], 1);
        assert_eq!(v["refused"], 1);
    }

    #[test]
    fn an_unimplemented_qtype_forwards_rather_than_being_denied() {
        let r = Resolver::new(table(), Echo(vec![7, 7]), counters());
        // MX for a name we DO hold — the name matches, the type does not.
        assert_eq!(
            r.handle(&query_bytes("rio", 15)),
            Reply::Relayed(vec![7, 7])
        );
    }

    #[test]
    fn there_is_no_way_to_mint_an_nxdomain() {
        // A structural assertion rather than a behavioural one: the enum has
        // two arms and neither is NXDOMAIN, so no code path can produce one.
        // If someone adds the variant, this stops compiling and they must
        // read the module docs to proceed.
        fn exhaustive(r: Rcode) -> u16 {
            match r {
                Rcode::FormatError => 1,
                Rcode::ServFail => 2,
            }
        }
        assert_eq!(exhaustive(Rcode::ServFail), 2);
    }
}

// ── THE REAL UPSTREAM ──────────────────────────────────────────────────

/// How long to wait on one upstream before trying the next.
///
/// ★ Two seconds, chosen against the CLIENT's patience rather than the
/// network's: glibc's resolver gives up around five, so a budget that lets us
/// try all four upstreams serially would time the client out before we
/// finished trying. Four × 2s exceeds that, which is why [`UdpUpstream`] stops
/// at the first answer and the budget is per-upstream, not total.
pub const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The largest reply annai accepts over UDP.
///
/// ★ 4096, not 512. RFC 1035's 512 predates EDNS0; modern resolvers routinely
/// send larger, and truncating at 512 would silently drop valid answers.
pub const MAX_REPLY: usize = 4096;

/// Forwards over UDP to the configured upstreams, in order.
pub struct UdpUpstream {
    addrs: Vec<std::net::SocketAddr>,
}

impl UdpUpstream {
    /// Build from configured strings; a bare IP gets `:53`.
    ///
    /// ★ An unparseable upstream is SKIPPED with a warning rather than being
    /// fatal — one typo in a four-entry list must not leave the node with no
    /// resolution at all. If ALL of them fail to parse the list is empty, and
    /// `forward` then reports `NoUpstreamConfigured`, which is a distinct and
    /// nameable state rather than a silent hang.
    #[must_use]
    pub fn new(upstreams: &[String]) -> Self {
        let mut addrs = Vec::new();
        for u in upstreams {
            let with_port = if u.contains(':') && !u.contains("::") {
                u.clone()
            } else if u.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{u}]:53")
            } else {
                format!("{u}:53")
            };
            match with_port.parse::<std::net::SocketAddr>() {
                Ok(a) => addrs.push(a),
                Err(_) => eprintln!("annai: upstream `{u}` is not an address — skipping it"),
            }
        }
        Self { addrs }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

impl Upstream for UdpUpstream {
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError> {
        if self.addrs.is_empty() {
            return Err(ForwardError::NoUpstreamConfigured);
        }
        let mut last = ForwardError::Timeout;
        for addr in &self.addrs {
            // A fresh ephemeral socket per query: binding one long-lived
            // socket would make the source port predictable across queries,
            // which is half of a cache-poisoning attack. The kernel randomizes
            // an ephemeral bind.
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let sock = match std::net::UdpSocket::bind(bind) {
                Ok(s) => s,
                Err(e) => {
                    last = ForwardError::Unreachable(e.to_string());
                    continue;
                }
            };
            if sock.set_read_timeout(Some(UPSTREAM_TIMEOUT)).is_err() {
                last = ForwardError::Unreachable("could not set a read timeout".into());
                continue;
            }
            if let Err(e) = sock.send_to(query, addr) {
                last = ForwardError::Unreachable(e.to_string());
                continue;
            }
            let mut buf = vec![0u8; MAX_REPLY];
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from == *addr => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                // ★ A reply from an address we did not ask is DISCARDED, not
                // relayed. Accepting it is the off-path spoofing window: an
                // attacker who guesses the port answers before the real
                // upstream and we would cache their answer.
                Ok(_) => last = ForwardError::Unreachable("reply from an unexpected source".into()),
                Err(_) => last = ForwardError::Timeout,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod upstream_tests {
    use super::*;

    #[test]
    fn a_bare_ip_gets_the_dns_port() {
        let u = UdpUpstream::new(&["1.1.1.1".to_owned()]);
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn one_bad_upstream_does_not_discard_the_good_ones() {
        let u = UdpUpstream::new(&["1.1.1.1".to_owned(), "not-an-ip".to_owned()]);
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn no_parseable_upstream_is_a_named_state_not_a_hang() {
        let u = UdpUpstream::new(&["nope".to_owned()]);
        assert!(u.is_empty());
        assert_eq!(u.forward(&[0, 0]), Err(ForwardError::NoUpstreamConfigured));
    }

    #[test]
    fn an_ipv6_upstream_is_bracketed() {
        assert_eq!(
            UdpUpstream::new(&["2606:4700:4700::1111".to_owned()]).len(),
            1
        );
    }

    #[test]
    fn an_explicit_port_is_respected() {
        assert_eq!(UdpUpstream::new(&["1.1.1.1:5353".to_owned()]).len(), 1);
    }
}
