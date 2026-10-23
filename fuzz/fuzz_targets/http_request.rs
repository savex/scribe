#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_enrich::http::parse_request_url;

fuzz_target!(|data: &[u8]| {
    if let Some(url) = parse_request_url(data) {
        assert!(url.starts_with("http://"));
    }
});
