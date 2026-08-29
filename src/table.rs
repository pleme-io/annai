//! The local name table — the fleet registry, as a lookup.
//!
//! ★ Deliberately NOT a parser for `/etc/hosts`. The table is fed from
//! `pleme.fleetDns`'s typed registry, which is where fleet names are already
//! declared; parsing the rendered file back would make annai a consumer of a
//! projection rather than of the source, and re-derive a fact the fleet
//! already holds typed. The `/etc/hosts` shape is what dnsmasq had to read
//! because it could not be handed a registry — annai can.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::wire::Name;

/// Names annai answers for. Empty is a valid table: every query forwards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    entries: BTreeMap<Name, Vec<IpAddr>>,
}

impl Table {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one address for a name. A name may hold several, across families.
    pub fn insert(&mut self, name: Name, addr: IpAddr) {
        let slot = self.entries.entry(name).or_default();
        if !slot.contains(&addr) {
            slot.push(addr);
        }
    }

    /// Every address held for a name; empty when the name is not held.
    #[must_use]
    pub fn lookup(&self, name: &Name) -> &[IpAddr] {
        self.entries.get(name).map_or(&[], Vec::as_slice)
    }

    /// How many names the table holds — the denominator for a health answer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_can_hold_both_families() {
        let mut t = Table::new();
        let n = Name::from_host("rio");
        t.insert(n.clone(), "10.0.0.1".parse().expect("ip"));
        t.insert(n.clone(), "fd00::1".parse().expect("ip"));
        assert_eq!(t.lookup(&n).len(), 2);
    }

    #[test]
    fn inserting_the_same_address_twice_does_not_duplicate_it() {
        // A duplicated address would be answered twice in one response, which
        // is legal and useless, and makes a registry glitch invisible.
        let mut t = Table::new();
        let n = Name::from_host("rio");
        t.insert(n.clone(), "10.0.0.1".parse().expect("ip"));
        t.insert(n.clone(), "10.0.0.1".parse().expect("ip"));
        assert_eq!(t.lookup(&n).len(), 1);
    }

    #[test]
    fn an_absent_name_yields_an_empty_slice_not_a_panic() {
        assert!(Table::new().lookup(&Name::from_host("nope")).is_empty());
    }

    #[test]
    fn an_empty_table_is_valid_and_forwards_everything() {
        // A node with no fleet names is a normal node, not a broken one.
        assert!(Table::new().is_empty());
        assert_eq!(Table::new().len(), 0);
    }
}
