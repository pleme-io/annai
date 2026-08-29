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
}

impl AnnaiConfig {
    /// Tier 0 — binds nothing, forwards nowhere.
    #[must_use]
    pub fn bare() -> Self {
        Self { listen: None, upstreams: Vec::new(), local_ttl: 0 }
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
            upstreams: PRESCRIBED_UPSTREAMS.iter().map(|s| (*s).to_owned()).collect(),
            local_ttl: crate::wire::LOCAL_TTL,
        }
    }
}

impl Default for AnnaiConfig {
    fn default() -> Self {
        Self::prescribed()
    }
}

impl shikumi::TieredConfig for AnnaiConfig {
    fn bare() -> Self { Self::bare() }
    fn discovered() -> Self { Self::discovered() }
    fn prescribed_default() -> Self { Self::prescribed() }
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
    match shikumi::ConfigStore::<AnnaiConfig>::load(&path, "ANNAI_") {
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
    fn the_config_round_trips() {
        let c = AnnaiConfig::prescribed();
        let s = serde_yaml::to_string(&c).expect("ser");
        assert_eq!(serde_yaml::from_str::<AnnaiConfig>(&s).expect("de"), c);
    }
}
