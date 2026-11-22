#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use scribe_enrich::dns::{parse_response, DnsCache, Record};

fuzz_target!(|data: &[u8]| {
    let Ok(response) = parse_response(data) else {
        return;
    };
    let mut cache = DnsCache::default();
    let named = cache.observe(&response);
    assert!(named <= response.answers.len());
    for answer in &response.answers {
        let ip: IpAddr = match answer.record {
            Record::A(v4) => v4.into(),
            Record::Aaaa(v6) => v6.into(),
            Record::Cname(_) => continue,
        };
        if let Some(name) = cache.lookup(&ip) {
            assert!(name.len() <= 253 && !name.ends_with('.'), "bad cached name {name:?}");
            assert_eq!(name, name.to_ascii_lowercase());
        }
    }
});
