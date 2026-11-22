//! The shipped config and the built-in modules are consistent.

use scribe_core::platform::Os;
use scribe_daemon::config::{parse, Config, Context, Source};
use scribe_daemon::modules;

#[test]
fn shipped_file_equals_built_in_defaults() {
    let text = std::fs::read_to_string(scribe_tests::shipped_config()).unwrap();
    let ctx = Context {
        os: Os::Linux,
        storage_kinds: vec!["sqlite", "postgres"],
        modules: modules::builtin(),
    };
    let parsed =
        parse(&text, &Source::File("scribe.toml".into()), &ctx).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed, Config::default());
}

#[test]
fn built_in_modules_match_their_manifests() {
    let built = modules::builtin();
    assert!(
        built.iter().any(|m| m.id == "url"),
        "the url module is built in"
    );
    for spec in built {
        let module = (spec.make)();
        assert_eq!(module.manifest().id, spec.id);
        module.manifest().validate().unwrap();
    }
}
