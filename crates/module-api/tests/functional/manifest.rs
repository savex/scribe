//! Functional tests for `scribe_module_api` (moved from `src/manifest.rs`).

use scribe_module_api::*;

fn url() -> Manifest {
    let mut m = Manifest::new("url", 1, "URL tracking");
    m.records.push(RecordKind {
        name: "url.request",
        schema: 1,
    });
    m.metrics.push("url.requests");
    m.calls.push(Call {
        name: "list",
        access: Access::Read,
    });
    m.needs.payload = true;
    m
}

#[test]
fn a_good_manifest_passes() {
    let m = url();
    m.validate().unwrap();
    assert_eq!(m.record("url.request").unwrap().schema, 1);
    assert!(m.record("url.other").is_none());
    assert_eq!(m.call("list").unwrap().access, Access::Read);
    assert!(m.call("purge").is_none());
}

#[test]
fn naming_rules_are_enforced() {
    type Change = Box<dyn Fn(&mut Manifest)>;
    let cases: Vec<(Change, &str)> = vec![
        (Box::new(|m| m.id = "Url"), "id must match"),
        (Box::new(|m| m.id = ""), "id must match"),
        (Box::new(|m| m.version = 0), "version must be at least 1"),
        (
            Box::new(|m| m.records[0].name = "request"),
            "'request' must be named 'url.<name>'",
        ),
        (
            Box::new(|m| m.metrics[0] = "kperf.x"),
            "'kperf.x' must be named 'url.<name>'",
        ),
        (
            Box::new(|m| m.metrics[0] = "url.request"),
            "'url.request' is declared twice",
        ),
        (
            Box::new(|m| m.records[0].schema = 0),
            "needs a schema version",
        ),
        (
            Box::new(|m| m.calls[0].name = "List"),
            "call 'List' must match",
        ),
        (
            Box::new(|m| {
                m.calls.push(Call {
                    name: "list",
                    access: Access::Control,
                })
            }),
            "call 'list' is declared twice",
        ),
    ];
    for (change, expected) in cases {
        let mut m = url();
        change(&mut m);
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains(expected), "{err} vs {expected}");
    }
}
