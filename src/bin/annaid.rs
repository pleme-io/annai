//! annaid — the annai daemon.
//!
//! Loads its typed config, builds the name table from the fleet registry,
//! publishes a kanshou surface, and serves DNS over UDP.
//!
//! Deployed by the nix repo's `pleme.fleetDns` (`zoneResolver` beside dnsmasq,
//! or `annai` mode as the node's only resolver).

use std::sync::Arc;

use annai::config;
use annai::introspect::AnnaiIntrospect;
use annai::serve::{Reply, Resolver, UdpUpstream};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn main() -> std::process::ExitCode {
    // ★ ARGV BEFORE ANYTHING. This daemon ignored `--help` entirely: the flag
    // fell through, config loaded, the daemon started, and the operator's
    // question became a running process. Measured 2026-08-29 across all three
    // of annaid/jikokud/nanorid — convergence, not copying: a daemon whose
    // whole surface is a shikumi tier ends up with no argument parser at all.
    //
    // The gate answers --help/--version and REFUSES an unknown argument
    // (exit 2, naming it) before any config load, socket bind or side effect.
    // Refusing an unknown argument matters here because a resolver that
    // silently ignored `--port 5353` would bind 53 while the operator believed
    // otherwise — and on a stub resolver that is a fleet-wide DNS outage.
    let cli = shikumi::daemon::DaemonCli {
        name: "annaid",
        version: env!("CARGO_PKG_VERSION"),
        summary: "the fleet stub resolver — answer from a typed name table, forward the rest",
        tier_env: "ANNAI_TIER",
    };
    if let Some(code) = cli.classify(std::env::args().skip(1)).resolve() {
        return code;
    }

    let cfg = config::load();
    let table = cfg.table();

    let Some(listen) = cfg.listen.clone() else {
        // The bare tier binds nothing. Starting anyway and serving no one
        // would be a daemon that looks healthy and answers nothing.
        eprintln!("annai: no `listen` configured (bare tier) — nothing to serve, exiting");
        return std::process::ExitCode::FAILURE;
    };

    let socket = match std::net::UdpSocket::bind(&listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("annai: cannot bind {listen}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let measured = cfg.measured();
    annai::measured::watch(&measured);
    let counters =
        AnnaiIntrospect::with_paths(table.clone(), Arc::clone(&measured), now_ms(), now_ms);
    match kanshou::Server::spawn_sidecar("annai", Arc::clone(&counters)) {
        Some(p) => eprintln!("annai: introspection live at {}", p.display()),
        None => eprintln!("annai: introspection unavailable — resolution still works"),
    }

    let upstream = UdpUpstream::new(&cfg.upstreams);
    if upstream.is_empty() {
        // Deliberately a warning, not a refusal: a node whose table covers
        // everything it asks for is a legitimate, if unusual, configuration.
        eprintln!("annai: no usable upstream — only names in the table will resolve");
    }
    let resolver = Resolver::new(table, upstream, counters).with_measured(measured, now_ms);

    eprintln!("annai: listening on {listen}");
    let mut buf = vec![0u8; annai::serve::MAX_REPLY];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let out = match resolver.handle(&buf[..n]) {
            Reply::Local(b) | Reply::Relayed(b) => b,
            Reply::Error { rcode, id } => {
                let mut e = Vec::with_capacity(12);
                e.extend_from_slice(&id.to_be_bytes());
                e.extend_from_slice(&(0x8080 | rcode.wire()).to_be_bytes());
                e.extend_from_slice(&[0; 8]);
                e
            }
        };
        let _ = socket.send_to(&out, from);
    }
}
