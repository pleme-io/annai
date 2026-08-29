//! annaid — the annai daemon.
//!
//! Loads its typed config, builds the name table from the fleet registry,
//! publishes a kanshou surface, and serves DNS over UDP.
//!
//! ★ NOT DEPLOYED ANYWHERE. On a node where annai is the only resolver, the
//! cutover takes that machine's entire name resolution with it, so it is a
//! deliberate separate change gated on its own measurement — see the crate
//! docs and `theory/NATURALIZE-NIXOS.md`.

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

    let counters = AnnaiIntrospect::new(table.clone(), now_ms(), now_ms);
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
    let resolver = Resolver::new(table, upstream, counters);

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
