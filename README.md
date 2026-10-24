# annai (案内)

> "Showing the way." The fleet stub resolver: answer from a typed name table,
> forward everything else.

## Status

`annaid` serves DNS over UDP: it answers from a typed name table and forwards
everything else to its upstreams. It runs beside dnsmasq for `pleme.internal`
on nodes with `pleme.fleetDns.zoneResolver` on (nix repo,
`docs/locality-dns.md`).

### Measured answers (locality DNS, phase 3)

| config field | meaning |
|---|---|
| `candidates` | per name: each candidate `{ addr, path: lan\|ts\|pub, rung, port, probe: tcp\|nix-cache, reach: { <from-node>: up\|down\|unknown } }` |
| `answers` | the file a prober writes (`{ at_ms, from, names: { <name>: { order, why } } }`); unset = measurement off |
| `node` | this node; answers written by another node are never used |
| `stale_after_ms` | default 10000; older answers fall back to the static table |
| `measured_ttl` | default 5; TTL of measured, fallback and TXT answers |

- A/AAAA for a candidate name: the first two addresses of the prober's order
  when the answers are fresh, else the static table (`names`, or the name's
  `ts` candidates). A dead prober gives the static answer, never no answer.
- TXT for a candidate name: one string per candidate, the prober's `why`, or
  the declared verdicts and the reason the answers are not used.
- kanshou: `paths` (candidates, answers, freshness) and `counters.measured`,
  `counters.stale_answers`.

## Why

`theory/NATURALIZE-NIXOS.md` costed replacing dnsmasq as REIMPLEMENT against
RFC 1035 — the price of an authoritative DNS server, read as months. Measured
on plo 2026-08-28, dnsmasq's whole configuration is eight lines with no
`dhcp-range` anywhere, and what it does is: answer from a local table, forward
the rest to four upstreams, cache.

The local table is already ours. The live `/etc/hosts` entry is

```
192.0.2.66  rio.example.net rio.station.example.net rio rio.ts
```

which is `pleme.fleetDns`'s output shape verbatim, `aliasSuffix = "ts"`
included. So what is missing is a stub resolver over a registry pleme-io
already generates.

## The two invariants, both structural

**A compression pointer must move strictly backward, within a budget.**
RFC 1035 §4.1.4 lets a name reference an earlier offset — including its own.
A parser that follows pointers unbounded hangs forever on a 14-byte packet
sent to an open UDP port, before any authentication, because there is none.
Backward-only and a budget are each insufficient alone: backward-only still
admits N/2 distinct jumps (quadratic), and a budget alone still admits forward
jumps that walk the parser past validated bytes.

**There is no `NxDomain` variant.** A stub resolver is authoritative for
nothing. Answering "no such name" for a name it merely does not hold takes
that name off the network for the whole cached TTL, for every process on the
host, while the resolver looks healthy throughout. The variant is absent from
the type rather than guarded by a branch someone can later invert. A table
miss, an unimplemented QTYPE, and a family mismatch all reach `Forward` — the
last of these because an empty answer is NODATA, which caches exactly like
NXDOMAIN and suppresses the upstream's real reply.
