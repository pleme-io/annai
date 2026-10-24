use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::wire::Name;

pub const DEFAULT_STALE_AFTER_MS: u64 = 10_000;
pub const DEFAULT_MEASURED_TTL: u32 = 5;
pub const POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Lan,
    Ts,
    Pub,
}

impl PathKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Ts => "ts",
            Self::Pub => "pub",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Probe {
    Tcp,
    NixCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Up,
    Down,
    Unknown,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub addr: IpAddr,
    pub path: PathKind,
    pub rung: u8,
    pub port: u16,
    #[serde(default = "tcp")]
    pub probe: Probe,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reach: BTreeMap<String, Verdict>,
}

fn tcp() -> Probe {
    Probe::Tcp
}

impl Candidate {
    #[must_use]
    pub fn declared_from(&self, node: Option<&str>) -> Verdict {
        node.and_then(|n| self.reach.get(n).copied())
            .unwrap_or(Verdict::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedAnswer {
    pub order: Vec<IpAddr>,
    #[serde(default)]
    pub why: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answers {
    pub at_ms: u64,
    pub from: String,
    pub names: BTreeMap<String, NamedAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness<'a> {
    Fresh(&'a Answers),
    Stale { age_ms: u64 },
    WrongNode { from: String },
    Absent,
    Off,
}

impl Freshness<'_> {
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Fresh(_) => "fresh".into(),
            Self::Stale { age_ms } => format!("answers stale ({age_ms} ms old)"),
            Self::WrongNode { from } => format!("answers written by {from}, not this node"),
            Self::Absent => "no answers file yet".into(),
            Self::Off => "measurement off".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    by_name: BTreeMap<Name, Vec<Candidate>>,
}

impl Candidates {
    #[must_use]
    pub fn from_config(raw: &BTreeMap<String, Vec<Candidate>>) -> Self {
        let mut by_name = BTreeMap::new();
        for (name, cs) in raw {
            let mut cs = cs.clone();
            cs.sort_by_key(|c| c.rung);
            by_name.insert(Name::from_host(name), cs);
        }
        Self { by_name }
    }

    #[must_use]
    pub fn of(&self, name: &Name) -> Option<&[Candidate]> {
        self.by_name.get(name).map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Name, &Vec<Candidate>)> {
        self.by_name.iter()
    }
}

#[derive(Debug)]
pub struct Measured {
    pub candidates: Candidates,
    pub node: Option<String>,
    pub stale_after_ms: u64,
    pub ttl: u32,
    pub source: Option<PathBuf>,
    loaded: RwLock<Option<Answers>>,
}

impl Measured {
    #[must_use]
    pub fn new(
        candidates: Candidates,
        node: Option<String>,
        stale_after_ms: u64,
        ttl: u32,
        source: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            candidates,
            node,
            stale_after_ms,
            ttl,
            source,
            loaded: RwLock::new(None),
        })
    }

    #[must_use]
    pub fn off() -> Arc<Self> {
        Self::new(
            Candidates::default(),
            None,
            DEFAULT_STALE_AFTER_MS,
            DEFAULT_MEASURED_TTL,
            None,
        )
    }

    pub fn store(&self, answers: Answers) {
        if let Ok(mut slot) = self.loaded.write() {
            *slot = Some(answers);
        }
    }

    pub fn with<T>(&self, now_ms: u64, f: impl FnOnce(Freshness<'_>) -> T) -> T {
        if self.source.is_none() {
            return f(Freshness::Off);
        }
        let Ok(slot) = self.loaded.read() else {
            return f(Freshness::Absent);
        };
        let Some(a) = slot.as_ref() else {
            return f(Freshness::Absent);
        };
        if let Some(node) = &self.node
            && &a.from != node
        {
            return f(Freshness::WrongNode {
                from: a.from.clone(),
            });
        }
        let age_ms = now_ms.abs_diff(a.at_ms);
        if age_ms > self.stale_after_ms {
            return f(Freshness::Stale { age_ms });
        }
        f(Freshness::Fresh(a))
    }

    #[must_use]
    pub fn explain(&self, name: &Name, now_ms: u64) -> Option<Vec<String>> {
        let cs = self.candidates.of(name)?;
        Some(self.with(now_ms, |fresh| {
            if let Freshness::Fresh(a) = &fresh
                && let Some(n) = a.names.get(name.as_str())
                && !n.why.is_empty()
            {
                return n.why.clone();
            }
            let reason = fresh.reason();
            cs.iter()
                .map(|c| {
                    format!(
                        "path={} addr={} verdict={} chosen=no reason=\"{}; static table answers\"",
                        c.path.as_str(),
                        c.addr,
                        c.declared_from(self.node.as_deref()).as_str(),
                        reason
                    )
                })
                .collect()
        }))
    }

    #[must_use]
    pub fn paths(&self, now_ms: u64) -> serde_json::Value {
        self.with(now_ms, |fresh| {
            let state = match &fresh {
                Freshness::Fresh(_) => "fresh",
                Freshness::Stale { .. } => "stale",
                Freshness::WrongNode { .. } => "wrong-node",
                Freshness::Absent => "absent",
                Freshness::Off => "off",
            };
            let names: serde_json::Map<String, serde_json::Value> = self
                .candidates
                .iter()
                .map(|(name, cs)| {
                    let answer = match &fresh {
                        Freshness::Fresh(a) => a.names.get(name.as_str()).cloned(),
                        _ => None,
                    };
                    (
                        name.as_str().to_owned(),
                        serde_json::json!({ "candidates": cs, "answer": answer }),
                    )
                })
                .collect();
            serde_json::json!({
                "state": state,
                "reason": fresh.reason(),
                "node": self.node,
                "source": self.source,
                "stale_after_ms": self.stale_after_ms,
                "at_ms": match &fresh { Freshness::Fresh(a) => Some(a.at_ms), _ => None },
                "names": names,
                "answered_at_unix_ms": now_ms,
            })
        })
    }
}

pub fn watch(measured: &Arc<Measured>) {
    let Some(path) = measured.source.clone() else {
        return;
    };
    let m = Arc::clone(measured);
    std::thread::spawn(move || {
        let mut seen: Option<SystemTime> = None;
        loop {
            if let Ok(mtime) = std::fs::metadata(&path).and_then(|md| md.modified())
                && seen != Some(mtime)
            {
                seen = Some(mtime);
                match std::fs::read(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| serde_json::from_slice::<Answers>(&b).map_err(|e| e.to_string()))
                {
                    Ok(a) => m.store(a),
                    Err(e) => eprintln!(
                        "annai: answers at {} unreadable ({e}); keeping the last good one",
                        path.display()
                    ),
                }
            }
            std::thread::sleep(POLL);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid() -> BTreeMap<String, Vec<Candidate>> {
        serde_yaml::from_str(
            "cid.pleme.internal:\n  - { addr: 100.104.30.81, path: ts, rung: 2, port: 22 }\n  - { addr: 192.168.60.138, path: lan, rung: 1, port: 22, reach: { ryn: up } }\n",
        )
        .expect("parse")
    }

    fn answers(at_ms: u64, from: &str) -> Answers {
        serde_json::from_str(&format!(
            "{{\"at_ms\": {at_ms}, \"from\": \"{from}\", \"names\": {{\"cid.pleme.internal\": {{\"order\": [\"192.168.60.138\", \"100.104.30.81\"], \"why\": [\"path=lan chosen=yes reason=\\\"rung 1\\\"\"]}}}}}}"
        ))
        .expect("parse")
    }

    fn measured(node: Option<&str>) -> Arc<Measured> {
        Measured::new(
            Candidates::from_config(&cid()),
            node.map(str::to_owned),
            10_000,
            5,
            Some(PathBuf::from("/nonexistent")),
        )
    }

    #[test]
    fn candidates_are_held_in_rung_order() {
        let c = Candidates::from_config(&cid());
        let cs = c.of(&Name::from_host("CID.pleme.internal.")).expect("held");
        assert_eq!(cs[0].path, PathKind::Lan);
        assert_eq!(cs[1].path, PathKind::Ts);
    }

    #[test]
    fn an_unknown_candidate_field_is_refused() {
        assert!(
            serde_yaml::from_str::<Candidate>(
                "{ addr: 10.0.0.1, path: lan, rung: 1, port: 22, speed: 9 }"
            )
            .is_err()
        );
    }

    #[test]
    fn reach_is_per_direction() {
        let c = Candidates::from_config(&cid());
        let lan = &c.of(&Name::from_host("cid.pleme.internal")).expect("held")[0];
        assert_eq!(lan.declared_from(Some("ryn")), Verdict::Up);
        assert_eq!(lan.declared_from(Some("cid")), Verdict::Unknown);
        assert_eq!(lan.declared_from(None), Verdict::Unknown);
    }

    #[test]
    fn fresh_answers_are_fresh_and_old_ones_are_stale() {
        let m = measured(Some("ryn"));
        m.store(answers(1_000, "ryn"));
        assert!(m.with(5_000, |f| matches!(f, Freshness::Fresh(_))));
        assert!(m.with(11_001, |f| f == Freshness::Stale { age_ms: 10_001 }));
    }

    #[test]
    fn answers_from_another_node_are_never_used() {
        let m = measured(Some("cid"));
        m.store(answers(1_000, "ryn"));
        assert!(m.with(1_000, |f| matches!(f, Freshness::WrongNode { .. })));
    }

    #[test]
    fn no_source_is_off_and_no_file_is_absent() {
        assert!(Measured::off().with(0, |f| f == Freshness::Off));
        assert!(measured(None).with(0, |f| f == Freshness::Absent));
    }

    #[test]
    fn the_explanation_is_the_probers_when_fresh() {
        let m = measured(Some("ryn"));
        m.store(answers(1_000, "ryn"));
        let why = m
            .explain(&Name::from_host("cid.pleme.internal"), 2_000)
            .expect("held");
        assert_eq!(
            why,
            vec!["path=lan chosen=yes reason=\"rung 1\"".to_owned()]
        );
    }

    #[test]
    fn a_stale_explanation_names_why_and_lists_every_candidate() {
        let m = measured(Some("ryn"));
        m.store(answers(1_000, "ryn"));
        let why = m
            .explain(&Name::from_host("cid.pleme.internal"), 60_000)
            .expect("held");
        assert_eq!(why.len(), 2);
        assert!(
            why[0].contains("path=lan")
                && why[0].contains("verdict=up")
                && why[0].contains("stale"),
            "{why:?}"
        );
        assert!(
            m.explain(&Name::from_host("rio.pleme.internal"), 0)
                .is_none()
        );
    }

    #[test]
    fn the_paths_view_carries_its_state_and_denominator() {
        let m = measured(Some("ryn"));
        let v = m.paths(0);
        assert_eq!(v["state"], "absent");
        assert_eq!(v["names"].as_object().expect("map").len(), 1);
        m.store(answers(0, "ryn"));
        assert_eq!(m.paths(1).as_object().expect("map")["state"], "fresh");
    }

    #[test]
    fn the_watcher_loads_a_written_file() {
        let dir = std::env::temp_dir().join(format!("annai-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("answers.json");
        std::fs::write(&path, serde_json::to_vec(&answers(7, "ryn")).expect("ser")).expect("write");
        let m = Measured::new(
            Candidates::from_config(&cid()),
            Some("ryn".into()),
            10_000,
            5,
            Some(path.clone()),
        );
        watch(&m);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !m.with(7, |f| matches!(f, Freshness::Fresh(_))) {
            assert!(
                std::time::Instant::now() < deadline,
                "the watcher never loaded the file"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
