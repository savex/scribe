use scribe_module_conformance::{run_module_suite, BadConfig, ModuleCase};
use scribe_module_url::UrlModule;

#[test]
fn url_module_conforms() {
    let mut case = ModuleCase::new(|| Box::new(UrlModule::default()));
    case.config =
        "mode = \"learn\"\n[modules]\nenabled = [\"url\"]\n[modules.url]\nquery = \"strip\"\n";
    case.reload = Some((
        "[modules.url]\nquery = \"full\"\n",
        scribe_module_api::Reload::Live,
    ));
    case.bad_configs = vec![
        BadConfig {
            text: "[modules.url]\nquery = \"everything\"\n",
            line: 2,
            contains: "unknown variant `everything`",
        },
        BadConfig {
            text: "[modules.url]\nquery = \"strip\"\nqueries = 1\n",
            line: 3,
            contains: "unknown field `queries`",
        },
        BadConfig {
            text: "[privacy]\nurl_query = \"full\"\n\n[modules.url]\nquery = \"strip\"\n",
            line: 2,
            contains: "disagree",
        },
    ];
    run_module_suite(&case).unwrap();
}
