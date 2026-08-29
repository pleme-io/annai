# annai (案内)

> "Showing the way." The fleet stub resolver: answer from a typed name table,
> forward everything else.

## Status — decision core only, NOT a daemon, NOT deployed

There is no socket, no upstream client and no cache here. `Decision::Forward`
names the outcome without performing it. This crate is the tested core that
re-scopes replacing `dnsmasq` from "reimplement RFC 1035" to something
finishable.

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

## Next

Wire as `pleme.fleetDns.mode = "annai"` — the module's own comment already
invites the variant, and `mode = "none"` is documented as "a local dnsmasq of
its own". That cutover is a separate, reviewable change: plo's dnsmasq is that
machine's ONLY resolver.
