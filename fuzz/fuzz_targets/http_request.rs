#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_module_url::parse::request_url;

fuzz_target!(|data: &[u8]| {
    if let Some(url) = request_url(data) {
        let rest = url.strip_prefix("http://").expect("URLs start with http://");
        // User info lives only in the authority; an `@` in the path or query is ordinary data.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        assert!(!authority.is_empty(), "no host: {url}");
        assert!(!authority.contains('@'), "user info is never kept: {url}");
    }
});
