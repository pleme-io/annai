//! annai (案内) — "showing the way". The fleet stub resolver.
//!
//! ── WHY THIS EXISTS ────────────────────────────────────────────────────
//!
//! `theory/NATURALIZE-NIXOS.md` costed replacing `dnsmasq` as "REIMPLEMENT,
//! RFC 1035", which prices an authoritative DNS server and reads as months.
//! Measured on plo 2026-08-28, dnsmasq's entire configuration is eight lines
//! with no `dhcp-range` anywhere, and what it does is:
//!
//! 1. answer from a local table,
//! 2. forward everything else to four upstreams,
//! 3. cache.
//!
//! And the local table is already ours — the live `/etc/hosts` entry is
//! `pleme.fleetDns`'s output shape verbatim, `aliasSuffix` included. So the
//! artifact needed is a **stub resolver over a registry pleme-io generates**,
//! not a DNS server.
//!
//! ── THE TWO INVARIANTS, BOTH STRUCTURAL ────────────────────────────────
//!
//! - **A compression pointer must move strictly backward, within a budget**
//!   ([`wire`]). Otherwise a 14-byte packet sent to an open UDP port hangs the
//!   parser forever — the oldest denial-of-service in DNS, reachable before authentication
//!   because there is none.
//! - **There is no `NxDomain`** ([`decide`]). A stub resolver that answers
//!   "no such name" for a name it merely does not hold takes that name off the
//!   network for the whole cached TTL, for every process on the host, while
//!   looking healthy. The variant is absent from the type rather than guarded.
//!
//! ── STATUS ─────────────────────────────────────────────────────────────
//!
//! **The decision core, tested. Not a daemon and not deployed.** There is no
//! socket, no upstream client, and no cache here yet; `Decision::Forward` names
//! the outcome without performing it. Wiring it as `pleme.fleetDns.mode =
//! "annai"` is the next step and is a separate, reviewable change — plo's
//! dnsmasq is that machine's ONLY resolver, so the cutover deserves its own
//! measurement rather than riding in on a library commit.

pub mod config;
pub mod decide;
pub mod introspect;
pub mod serve;
pub mod table;
pub mod wire;

pub use decide::Decision;
pub use table::Table;
pub use wire::{Name, QType, Query, WireError};
