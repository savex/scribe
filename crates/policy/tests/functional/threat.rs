//! Threat lists: the three formats, subdomains, CIDR networks, bad lines.

use std::net::IpAddr;

use scribe_policy::threat::LoadReport;
use scribe_policy::{ThreatFormat, ThreatSet};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn domains_cover_their_subdomains_only() {
    let mut set = ThreatSet::default();
    let report = set.load(
        ThreatFormat::Domains,
        "# comment\nEvil.Example.NET.\n\nbad..name\nbad name\n",
    );
    assert_eq!(
        report,
        LoadReport {
            added: 1,
            skipped: 2
        }
    );
    assert!(set.matches_host("evil.example.net"));
    assert!(set.matches_host("cdn.evil.example.net"));
    assert!(!set.matches_host("example.net"));
    assert!(!set.matches_host("notevil.example.net"));
}

#[test]
fn hosts_files_skip_localhost_and_the_ip() {
    let mut set = ThreatSet::default();
    let text = "127.0.0.1 localhost\n::1 localhost.localdomain\n0.0.0.0 ads.example.com tracker.example.net # two\nnot-an-ip bad.example.com\n";
    let report = set.load(ThreatFormat::Hosts, text);
    assert_eq!(
        report,
        LoadReport {
            added: 1,
            skipped: 3
        }
    );
    assert!(set.matches_host("ads.example.com"));
    assert!(set.matches_host("tracker.example.net"));
    assert!(!set.matches_host("bad.example.com"));
    assert!(!set.matches_ip(ip("0.0.0.0")));
    assert_eq!(set.len(), 2);
}

#[test]
fn ip_lists_take_addresses_and_networks() {
    let mut set = ThreatSet::default();
    let report = set.load(
        ThreatFormat::Ips,
        "198.51.100.66\n203.0.113.0/24\n2001:db8:bad::/48\n10.0.0.0/33\nnope\n",
    );
    assert_eq!(
        report,
        LoadReport {
            added: 3,
            skipped: 2
        }
    );
    assert!(set.matches_ip(ip("198.51.100.66")));
    assert!(!set.matches_ip(ip("198.51.100.67")));
    assert!(set.matches_ip(ip("203.0.113.200")));
    assert!(!set.matches_ip(ip("203.0.114.1")));
    assert!(set.matches_ip(ip("2001:db8:bad:1::5")));
    assert!(!set.matches_ip(ip("2001:db8:bae::1")));
    assert!(!set.matches_host("198.51.100.66"));
}

#[test]
fn an_empty_set_matches_nothing() {
    let set = ThreatSet::default();
    assert!(set.is_empty());
    assert!(!set.matches_host("evil.example.net"));
    assert!(!set.matches_ip(ip("0.0.0.0")));
    let mut all = ThreatSet::default();
    assert!(all.add_ip("0.0.0.0/0"));
    assert!(all.matches_ip(ip("192.0.2.1")));
    assert!(!all.matches_ip(ip("2001:db8::1")));
}
