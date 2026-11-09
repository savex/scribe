#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_module_url::parse::request_url;

fuzz_target!(|data: &[u8]| {
    if let Some(url) = request_url(data) {
        assert!(url.starts_with("http://"));
        assert!(!url.contains('@'), "user info is never kept: {url}");
    }
});
