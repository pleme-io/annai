//! annai's typed configuration — the citizen shape's config half.
//!
//! Same three tiers, same fallback doctrine, same `deny_unknown_fields` as
//! `mukae` and `sentinela`. Nothing here is novel, which is the point: the
//! fourth citizen inherits the shape rather than inventing one.
//!
//! ── ★ A BROKEN CONFIG MUST NOT COST YOU DNS ────────────────────────────
//!
//! mukae's rule ("a broken config must not cost you the seat") transfers with
//! its reasoning intact and arguably harder: on a node where annai is the only
//! resolver, refusing to start over a yaml typo takes the machine off the
//! network entirely — including the path you would use to fix it.

use serde::{Deserialize, Serialize};

/// The upstreams annai forwards to when a name is not held locally.
///
/// ★ The prescribed set is the four dnsmasq was measured using on plo, in its
/// order. Not a preference — matching the incumbent exactly is what makes the
/// cutover a delta of zero, and a differing resolver set would make any behaviour
/// change ambiguous between "annai is wrong" and "we changed upstreams".
pub const PRESCRIBED_UPSTREAMS: [&str; 4] = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnnaiConfig {
    /// Where to listen. Loopback only by default.
    ///
    /// ★ A resolver bound to 0.0.0.0 is an open resolver, which is a
    /// reflection-amplification source the moment it is reachable. The floor
    /// binds nothing and the prescription binds loopback; reaching the
    /// network is a decision someone writes down.
    pub listen: Option<String>,
    /// Upstreams, in order.
    pub upstreams: Vec<String>,
    /// TTL for answers served from the local table.
    pub local_ttl: u32,
    /// The names annai answers for: name → addresses.
    ///
    /// ★ Fed from `pleme.fleetDns`'s typed registry by the Nix module, NOT
    /// parsed back out of `/etc/hosts`. That file is a PROJECTION of the same
    /// registry; consuming it would make annai a reader of its own output's
    /// sibling and re-derive a fact the fleet already holds typed. dnsmasq
    /// read `/etc/hosts` because nothing could hand it a registry — annai can
    /// be handed one.
    pub names: std::collections::BTreeMap<String, Vec<String>>,
    pub candidates: std::collections::BTreeMap<String, Vec<crate::measured::Candidate>>,
    pub answers: Option<String>,
    pub node: Option<String>,
    pub stale_after_ms: u64,
    pub measured_ttl: u32,
}

impl AnnaiConfig {
    /// Tier 0 — binds nothing, forwards nowhere.
    #[must_use]
    pub fn bare() -> Self {
        Self {
            listen: None,
            upstreams: Vec::new(),
            local_ttl: 0,
            names: std::collections::BTreeMap::new(),
            candidates: std::collections::BTreeMap::new(),
            answers: None,
            node: None,
            stale_after_ms: crate::measured::DEFAULT_STALE_AFTER_MS,
            measured_ttl: crate::measured::DEFAULT_MEASURED_TTL,
        }
    }

    /// Tier 1 — nothing safely detectable. Reading the host's existing
    /// `/etc/resolv.conf` for upstreams would be a loop on a node where annai
    /// IS the nameserver in that file.
    #[must_use]
    pub fn discovered() -> Self {
        Self::bare()
    }

    /// Tier 2 — the fleet prescription: loopback, dnsmasq's own upstreams.
    #[must_use]
    pub fn prescribed() -> Self {
        Self {
            listen: Some("127.0.0.1:53".into()),
            upstreams: PRESCRIBED_UPSTREAMS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            local_ttl: crate::wire::LOCAL_TTL,
            // ★ EMPTY, and that is correct rather than lazy. The prescribed
            // tier is what a node gets with no site configuration, and
            // inventing fleet names here would bake one fleet's registry into
            // the binary. An empty table forwards everything, which is a
            // working resolver -- just not a fleet-aware one.
            names: std::collections::BTreeMap::new(),
            candidates: std::collections::BTreeMap::new(),
            answers: None,
            node: None,
            stale_after_ms: crate::measured::DEFAULT_STALE_AFTER_MS,
            measured_ttl: crate::measured::DEFAULT_MEASURED_TTL,
        }
    }
}

impl Default for AnnaiConfig {
    fn default() -> Self {
        Self::prescribed()
    }
}

impl AnnaiConfig {
    /// Build the lookup table this config describes.
    ///
    /// ★ An unparseable address is SKIPPED with a warning, not fatal. A typo
    /// in one fleet name must not take out resolution for every other name on
    /// the node -- the same fallback reasoning as `load()`, one level down.
    #[must_use]
    pub fn table(&self) -> crate::table::Table {
        let mut t = crate::table::Table::new();
        for (name, addrs) in &self.names {
            for a in addrs {
                match a.parse() {
                    Ok(ip) => t.insert(crate::wire::Name::from_host(name), ip),
                    Err(_) => eprintln!(
                        "annai: `{name}` has an unparseable address `{a}` — skipping that entry, the rest still resolve"
                    ),
                }
            }
        }
        for (name, cs) in &self.candidates {
            if self.names.contains_key(name) {
                continue;
            }
            for c in cs
                .iter()
                .filter(|c| c.path == crate::measured::PathKind::Ts)
            {
                t.insert(crate::wire::Name::from_host(name), c.addr);
            }
        }
        t
    }

    #[must_use]
    pub fn measured(&self) -> std::sync::Arc<crate::measured::Measured> {
        crate::measured::Measured::new(
            crate::measured::Candidates::from_config(&self.candidates),
            self.node.clone(),
            self.stale_after_ms,
            self.measured_ttl,
            self.answers.as_ref().map(std::path::PathBuf::from),
        )
    }
}

impl shikumi::TieredConfig for AnnaiConfig {
    fn bare() -> Self {
        Self::bare()
    }
    fn discovered() -> Self {
        Self::discovered()
    }
    fn prescribed_default() -> Self {
        Self::prescribed()
    }
}

/// Load through shikumi's discovery chain. Never fails — see the module docs.
#[must_use]
pub fn load() -> AnnaiConfig {
    let Ok(path) = shikumi::ConfigDiscovery::new("annai")
        .env_override("ANNAI_CONFIG")
        .discover()
    else {
        return AnnaiConfig::prescribed();
    };
    // ── ★ THE FIELD-OVERRIDE PREFIX MUST NOT CONTAIN THE DISCOVERY VAR ──
    // `ANNAI_OPT_`, not `ANNAI_`, and this is a bug fix rather than a taste.
    //
    // shikumi's env layer maps `<PREFIX><FIELD>` onto fields. With the prefix
    // `ANNAI_`, the discovery variable `ANNAI_CONFIG` is itself read as a
    // field named `config` -- which does not exist, so `deny_unknown_fields`
    // refuses the whole load and the daemon silently falls back to prescribed
    // defaults. The documented way to point annai at a config file was
    // therefore the one way to guarantee it ignored it.
    //
    // FOUND BY RUNNING IT, not by reading it: the first `dig` against the
    // daemon timed out because it had fallen back and tried to bind :53.
    //
    // ★ THE SAME COLLISION IS PRESENT IN `omoya` (OMOYA_CONFIG / OMOYA_) AND
    // `mukae` (MUKAE_CONFIG / MUKAE_), which is where this idiom was copied
    // from. Both are latent -- they break only when someone actually uses the
    // documented override -- and both are recorded in
    // theory/NATURALIZE-NIXOS.md rather than fixed here, because changing an
    // env-var contract on the login manager is its own reviewable change.
    match shikumi::ConfigStore::<AnnaiConfig>::load(&path, "ANNAI_OPT_") {
        Ok(store) => AnnaiConfig::clone(&store.get()),
        Err(e) => {
            eprintln!(
                "annai: config at {} could not be loaded ({e}) — using prescribed defaults so the node keeps resolving",
                path.display()
            );
            AnnaiConfig::prescribed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prescribed_upstreams_match_the_incumbent_exactly() {
        // A differing set would make any post-cutover behaviour change
        // ambiguous between "annai is wrong" and "we changed upstreams".
        assert_eq!(
            AnnaiConfig::prescribed().upstreams,
            vec!["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
        );
    }

    #[test]
    fn the_floor_binds_nothing() {
        assert!(AnnaiConfig::bare().listen.is_none());
    }

    #[test]
    fn the_prescription_binds_loopback_never_the_world() {
        // An open resolver is a reflection-amplification source.
        let l = AnnaiConfig::prescribed().listen.expect("listen");
        assert!(l.starts_with("127.0.0.1"), "{l}");
    }

    #[test]
    fn default_is_the_prescribed_tier_not_the_floor() {
        assert_eq!(AnnaiConfig::default(), AnnaiConfig::prescribed());
    }

    #[test]
    fn a_typo_is_rejected_rather_than_ignored() {
        assert!(serde_yaml::from_str::<AnnaiConfig>("upstream: [1.1.1.1]\n").is_err());
    }

    #[test]
    fn the_table_is_built_from_the_typed_registry() {
        let c: AnnaiConfig =
            serde_yaml::from_str("names:\n  rio: [\"10.0.0.1\", \"fd00::1\"]\n").expect("parse");
        assert_eq!(c.table().len(), 1);
        assert_eq!(
            c.table().lookup(&crate::wire::Name::from_host("rio")).len(),
            2
        );
    }

    #[test]
    fn one_bad_address_does_not_take_out_the_whole_table() {
        // A typo in one fleet name must not cost resolution for every other.
        let c: AnnaiConfig =
            serde_yaml::from_str("names:\n  rio: [\"10.0.0.1\"]\n  broken: [\"not-an-ip\"]\n")
                .expect("parse");
        let t = c.table();
        assert_eq!(t.lookup(&crate::wire::Name::from_host("rio")).len(), 1);
        assert!(t.lookup(&crate::wire::Name::from_host("broken")).is_empty());
    }

    #[test]
    fn the_prescribed_table_is_empty_rather_than_baking_in_a_fleet() {
        assert!(AnnaiConfig::prescribed().names.is_empty());
    }

    #[test]
    fn the_config_round_trips() {
        let c = AnnaiConfig::prescribed();
        let s = serde_yaml::to_string(&c).expect("ser");
        assert_eq!(serde_yaml::from_str::<AnnaiConfig>(&s).expect("de"), c);
    }

    #[test]
    fn candidates_parse_and_a_candidate_only_name_falls_back_to_its_tailnet_address() {
        let c: AnnaiConfig = serde_yaml::from_str(
            "node: ryn\nanswers: /var/run/annai/answers.json\ncandidates:\n  cid.pleme.internal:\n    - { addr: 192.168.60.138, path: lan, rung: 1, port: 22, reach: { ryn: up, cid: down } }\n    - { addr: 100.104.30.81, path: ts, rung: 2, port: 22 }\n  cache-darwin.pleme.internal:\n    - { addr: 192.168.60.138, path: lan, rung: 1, port: 5001, probe: nix-cache }\n",
        )
        .expect("parse");
        assert_eq!(c.stale_after_ms, 10_000);
        assert_eq!(c.measured_ttl, 5);
        let t = c.table();
        assert_eq!(
            t.lookup(&crate::wire::Name::from_host("cid.pleme.internal")),
            &["100.104.30.81".parse::<std::net::IpAddr>().expect("ip")]
        );
        assert!(
            t.lookup(&crate::wire::Name::from_host("cache-darwin.pleme.internal"))
                .is_empty()
        );
        assert_eq!(c.measured().candidates.len(), 2);
    }

    #[test]
    fn a_config_without_candidates_still_parses_as_before() {
        let c: AnnaiConfig =
            serde_yaml::from_str("names:\n  rio: [\"10.0.0.1\"]\n").expect("parse");
        assert!(c.candidates.is_empty());
        assert!(c.answers.is_none());
    }
}
