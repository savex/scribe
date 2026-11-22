use std::io;
use std::path::{Path, PathBuf};

use scribe_core::platform::{DefaultPaths, Os};
use scribe_core::{HumanDuration, Mode, SizeLimit};
use scribe_storage_api::EventKind;

use super::*;

const SHIPPED: &str = include_str!("../../../../config/scribe.toml");

fn ctx() -> Context {
    Context {
        os: Os::Linux,
        storage_kinds: vec!["sqlite", "postgres"],
        // The URL module is a dev-dependency, so these tests don't depend on the `url` feature.
        modules: vec![crate::modules::ModuleSpec {
            id: scribe_module_url::ID,
            make: || Box::new(scribe_module_url::UrlModule::default()),
        }],
    }
}

fn file() -> Source {
    Source::File(PathBuf::from("scribe.toml"))
}

fn parse_ok(text: &str) -> Config {
    parse(text, &file(), &ctx()).unwrap_or_else(|e| panic!("{e}"))
}

fn parse_err(text: &str) -> ConfigError {
    parse(text, &file(), &ctx()).expect_err("config should be rejected")
}

/// Fixed host: 16 GiB RAM, 100 GiB volumes.
struct FakeHost;

impl SystemFacts for FakeHost {
    fn total_memory(&self) -> io::Result<u64> {
        Ok(16 << 30)
    }

    fn volume_total(&self, _path: &Path) -> io::Result<u64> {
        Ok(100 << 30)
    }
}

struct BrokenHost;

impl SystemFacts for BrokenHost {
    fn total_memory(&self) -> io::Result<u64> {
        Err(io::Error::other("no sysctl"))
    }

    fn volume_total(&self, _path: &Path) -> io::Result<u64> {
        Err(io::Error::other("no statvfs"))
    }
}

fn linux_defaults() -> DefaultPaths {
    DefaultPaths::for_os(Os::Linux, Path::new("/usr/bin/scribed"))
}

fn resolve_text(text: &str) -> Settings {
    resolve(parse_ok(text), file(), &linux_defaults(), &FakeHost).unwrap()
}

// ─── Errors with line numbers ───────────────────────────────────────────────

/// (config text, expected message part, expected line)
const BAD: &[(&str, &str, usize)] = &[
    ("mode = \"learn\"\ncolour = \"blue\"\n", "unknown field `colour`", 2),
    ("mode = \"paranoid\"\n", "unknown variant `paranoid`", 1),
    ("version = 2\n", "unsupported config version 2", 1),
    ("data_dir = \"relative/dir\"\n", "data_dir must be an absolute path", 1),
    ("[policy]\nthen = \"learn\"\n", "unknown variant `learn`", 2),
    ("[policy]\ndedupe_window = \"10x\"\n", "invalid duration \"10x\"", 2),
    ("[policy]\ndedupe_window = \"0s\"\n", "must be greater than zero", 2),
    ("[policy]\nthreshold = 101\n", "must be between 0 and 100", 2),
    ("[policy.scores]\nraw_ip = -5\n", "must be between 0 and 100", 2),
    ("[policy.usual_ports]\ntcp = [80, 0]\n", "nonzero", 2),
    ("[policy.entropy]\nmin_bits_per_char = 9.0\n", "min_bits_per_char 9 is out of range", 2),
    (
        "[[policy.threat_lists]]\nname = \"x\"\nformat = \"domains\"\n",
        "needs exactly one of `path` or `url`",
        1,
    ),
    (
        "[[policy.threat_lists]]\nname = \"x\"\nurl = \"ftp://x\"\nformat = \"ips\"\n",
        "url must start with https://",
        1,
    ),
    (
        "[[policy.threat_lists]]\nname = \"x\"\npath = \"a.txt\"\nformat = \"ips\"\nrefresh = \"1h\"\n",
        "`refresh` only applies to a `url`",
        1,
    ),
    ("[privacy]\nurl_query = \"everything\"\n", "unknown variant `everything`", 2),
    ("[storage.state]\nkind = \"mysql\"\npath = \"x\"\n", "unknown variant `mysql`", 2),
    ("[storage.state]\nkind = \"sqlite\"\n", "sqlite needs `path`", 1),
    (
        "[storage.state]\npath = \"s.db\"\nurl = \"postgres://x\"\n",
        "`url` is not an option of sqlite",
        1,
    ),
    ("[storage.state]\nkind = \"postgres\"\n", "postgres needs `url`", 1),
    (
        "[storage.state]\nkind = \"postgres\"\nurl = \"postgres://u:pw@db/s\"\n",
        "must not contain a password",
        1,
    ),
    (
        "[storage.state]\nkind = \"postgres\"\nurl = \"mysql://db\"\n",
        "url must start with postgres://",
        1,
    ),
    ("[storage.cache]\nmax_memory = \"32MB\"\n", "use binary units (MiB)", 2),
    ("[storage.spool]\nmax_size = \"150%\"\n", "invalid percentage \"150%\"", 2),
    ("[storage.buffer]\nmax_events = 0\n", "nonzero", 2),
    (
        "[[storage.sinks]]\nname = \"a\"\npath = \"a.db\"\n\n[[storage.sinks]]\nname = \"a\"\npath = \"b.db\"\n",
        "sink name \"a\" is used twice",
        5,
    ),
    ("[[storage.sinks]]\nname = \" \"\npath = \"a.db\"\n", "sink name must not be empty", 1),
    ("[[storage.sinks]]\npath = \"a.db\"\n", "missing field `name`", 1),
    (
        "[[storage.sinks]]\nname = \"a\"\nevents = [\"dns\"]\npath = \"a.db\"\n",
        "unknown event kind \"dns\" in sink \"a\": known kinds are flow, alert, audit, metric, url.request",
        3,
    ),
    (
        "[[storage.sinks]]\nname = \"a\"\npath = \"a.db\"\nevents = [\"flow\", \"url.reqest\"]\n",
        "unknown event kind \"url.reqest\"",
        4,
    ),
    (
        "[modules]\nenabled = [\"url\", \"kperf\"]\n",
        "module \"kperf\" is not built into this scribed (built: url); rebuild with `--features kperf`",
        2,
    ),
    ("[modules]\nenabled = [\"url\", \"url\"]\n", "listed twice", 2),
    ("[modules]\nenabled = \"url\"\n", "must be a list of module ids", 1),
    ("[modules]\nurl = 3\n", "`modules.url` must be a table", 1),
    ("\n[modules.kperf]\nx = 1\n", "[modules.kperf]: no module \"kperf\"", 2),
    ("[modules.url]\nquery = \"everything\"\n", "module url: unknown variant `everything`", 2),
    ("[modules.url]\n\nqueries = 1\n", "module url: unknown field `queries`", 3),
    (
        "[privacy]\nurl_query = \"full\"\n[modules.url]\nquery = \"strip\"\n",
        "module url: `modules.url.query` (strip) and the deprecated `privacy.url_query` (full) disagree",
        2,
    ),
    ("[log]\nmax_size = \"5%\"\n", "must be an absolute size", 2),
    ("[log]\nlevel = \"loud\"\n", "unknown variant `loud`", 2),
    ("mode = \n", "", 1),
];

mod functional {
    use super::*;

    #[test]
    fn empty_file_equals_built_in_defaults() {
        assert_eq!(parse_ok(""), Config::default());
    }

    #[test]
    fn default_values_match_the_spec() {
        let c = Config::default();
        assert_eq!(c.mode, Mode::Learn);
        assert_eq!(c.policy.threshold, Score(50));
        assert_eq!(c.policy.dedupe_window, HumanDuration::from_secs(600));
        assert_eq!(c.privacy.url_query, None);
        assert_eq!(c.modules.enabled.get_ref(), &["url"]);
        assert_eq!(
            c.modules.sections["url"].get_ref()["query"].as_str(),
            Some("redact_values")
        );
        assert_eq!(c.storage.cache.max_memory, SizeLimit::mib(32));
        assert_eq!(c.storage.spool.min_free_disk, SizeLimit::Percent(5.0));
        assert_eq!(*c.log.output.get_ref(), LogOutput::File);
        assert_eq!(c.storage.sinks.len(), 1);
    }

    #[test]
    fn partial_tables_keep_other_defaults() {
        let c = parse_ok("[policy]\nthreshold = 70\n[storage.cache]\nmax_hosts = 10\n");
        assert_eq!(c.policy.threshold, Score(70));
        assert_eq!(c.policy.scores, Scores::default());
        assert_eq!(c.storage.cache.max_hosts.get(), 10);
        assert_eq!(c.storage.cache.max_memory, SizeLimit::mib(32));
    }

    #[test]
    fn accepts_a_full_custom_config() {
        let c = parse_ok(
            r#"
        mode = "caution"
        profile = "work"
        data_dir = "/srv/scribe"

        [policy]
        learn_for = "7d"
        then = "alert"

        [[policy.threat_lists]]
        name = "local"
        path = "threats/domains.txt"
        format = "domains"

        [[policy.threat_lists]]
        name = "urlhaus"
        url = "https://urlhaus.abuse.ch/downloads/hostfile/"
        format = "hosts"
        refresh = "24h"

        [privacy]
        url_query = "path_only"

        [storage.state]
        kind = "postgres"
        url = "postgres://scribe@db.internal:5432/scribe"
        credentials = "keychain:scribe-postgres"

        [[storage.sinks]]
        name = "local-history"
        path = "events.db"
        retention = ""

        [[storage.sinks]]
        name = "central"
        kind = "postgres"
        url = "postgres://scribe@db.internal/scribe"
        events = ["flow", "alert"]

        [log]
        level = "debug"
        format = "json"
        output = "both"
        file = ""
        rotate = "size"
        max_size = "10MiB"
        keep = 3
        "#,
        );
        assert_eq!(c.mode, Mode::Caution);
        assert_eq!(
            c.policy.learn_for,
            Some(HumanDuration::from_secs(7 * 86_400))
        );
        assert_eq!(Mode::from(c.policy.then), Mode::Alert);
        assert_eq!(c.policy.threat_lists.len(), 2);
        assert_eq!(
            c.privacy.url_query.as_ref().map(|q| *q.get_ref()),
            Some(UrlQuery::PathOnly)
        );
        assert_eq!(c.storage.state.get_ref().kind, StorageKind::Postgres);
        assert_eq!(c.storage.sinks[0].get_ref().retention, None);
        let events: Vec<_> = c.storage.sinks[1]
            .get_ref()
            .events
            .iter()
            .map(|e| e.get_ref().as_str())
            .collect();
        assert_eq!(events, ["flow", "alert"]);
        assert_eq!(c.log.level, LogLevel::Debug);
    }

    #[test]
    fn rejects_bad_configs_with_their_line() {
        for (text, message, line) in BAD {
            let err = parse_err(text);
            assert!(
                err.message.contains(message),
                "for {text:?}: expected {message:?} in {:?}",
                err.message
            );
            assert_eq!(err.line, Some(*line), "line for {text:?}: {err}");
            assert!(err.column.is_some());
        }
    }

    #[test]
    fn error_display_names_file_and_position() {
        let err = parse_err("mode = \"learn\"\ncolour = 1\n");
        let shown = err.to_string();
        assert!(
            shown.starts_with("scribe.toml, line 2, column 1: "),
            "{shown}"
        );
    }

    #[test]
    fn storage_kind_must_be_built_in() {
        let only_sqlite = Context {
            os: Os::Linux,
            storage_kinds: vec!["sqlite"],
            modules: vec![],
        };
        let text = "[storage.state]\nkind = \"postgres\"\nurl = \"postgres://db/s\"\n";
        let err = parse(text, &file(), &only_sqlite).unwrap_err();
        assert!(
            err.message
                .contains("not built into this scribed (built: sqlite)"),
            "{err}"
        );
        assert!(err.message.contains("--features postgres"), "{err}");
    }

    #[test]
    fn system_log_is_not_offered_on_windows_yet() {
        let windows = Context {
            os: Os::Windows,
            storage_kinds: vec!["sqlite"],
            modules: vec![],
        };
        for output in ["system", "both"] {
            let text = format!("[log]\noutput = \"{output}\"\n");
            let err = parse(&text, &file(), &windows).unwrap_err();
            assert!(
                err.message.contains("not available on Windows yet"),
                "{err}"
            );
            assert_eq!(err.line, Some(2));
        }
        assert!(parse("[log]\noutput = \"system\"\n", &file(), &ctx()).is_ok());
    }

    #[test]
    fn built_in_errors_have_no_position() {
        let err = ConfigError::at(&Source::BuiltIn, "", 0..0, "oops");
        assert_eq!(err.line, None);
        assert_eq!(err.to_string(), "built-in defaults: oops");
    }

    // ─── Finding the file ───────────────────────────────────────────────────────

    #[test]
    fn discovery_order() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("flag.toml");
        let env = dir.path().join("env.toml");
        let default = dir.path().join("default.toml");
        for p in [&flag, &env, &default] {
            std::fs::write(p, "").unwrap();
        }

        let found = discover(Some(&flag), Some(env.clone().into()), &default).unwrap();
        assert_eq!(found, Source::File(flag.clone()));
        let found = discover(None, Some(env.clone().into()), &default).unwrap();
        assert_eq!(found, Source::File(env.clone()));
        let found = discover(None, Some("".into()), &default).unwrap();
        assert_eq!(
            found,
            Source::File(default.clone()),
            "empty SCRIBE_CONFIG is ignored"
        );
        let found = discover(None, None, &default).unwrap();
        assert_eq!(found, Source::File(default));
        let found = discover(None, None, &dir.path().join("missing.toml")).unwrap();
        assert_eq!(found, Source::BuiltIn);
    }

    #[test]
    fn named_files_must_exist() {
        let missing = Path::new("/nonexistent/scribe.toml");
        let err = discover(Some(missing), None, missing).unwrap_err();
        assert!(err.message.contains("named by --config"), "{err}");
        let err = discover(None, Some(missing.into()), missing).unwrap_err();
        assert!(err.message.contains("named by SCRIBE_CONFIG"), "{err}");
    }

    #[test]
    fn loads_files_and_built_in_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scribe.toml");
        std::fs::write(&path, "profile = \"home\"\n").unwrap();
        let (config, text) = load(&Source::File(path), &ctx()).unwrap();
        assert_eq!(config.profile, "home");
        assert_eq!(text, "profile = \"home\"\n");

        let (config, text) = load(&Source::BuiltIn, &ctx()).unwrap();
        assert_eq!(config, Config::default());
        assert!(text.is_empty());

        let err = load(&Source::File(dir.path().join("nope.toml")), &ctx()).unwrap_err();
        assert!(err.message.contains("cannot read config file"), "{err}");
    }

    // ─── Resolving ──────────────────────────────────────────────────────────────

    #[test]
    fn resolves_paths_against_data_dir() {
        let s = resolve_text("");
        assert_eq!(s.data_dir, Path::new("/var/lib/scribe"));
        assert_eq!(s.storage.state.kind, "sqlite");
        assert_eq!(s.storage.state.options["path"], "/var/lib/scribe/state.db");
        assert_eq!(
            s.storage.sinks[0].backend.options["path"],
            "/var/lib/scribe/events.db"
        );
        assert_eq!(s.limits.spool_dir, Path::new("/var/lib/scribe/spool"));
        assert_eq!(
            s.log.file.as_deref(),
            Some(Path::new("/var/log/scribe/scribed.log"))
        );

        let s = resolve_text(
        "data_dir = \"/srv/s\"\n[storage.state]\npath = \"/abs/state.db\"\n[log]\nfile = \"logs/d.log\"\n",
    );
        assert_eq!(s.storage.state.options["path"], "/abs/state.db");
        assert_eq!(s.log.file.as_deref(), Some(Path::new("/srv/s/logs/d.log")));
    }

    #[test]
    fn empty_log_file_means_stderr() {
        assert_eq!(resolve_text("[log]\nfile = \"\"\n").log.file, None);
    }

    #[test]
    fn resolves_limits() {
        let s = resolve_text("");
        assert_eq!(s.limits.cache_hosts, 50_000);
        assert_eq!(s.limits.cache_memory, 32 << 20);
        assert_eq!(s.limits.buffer_memory, 32 << 20);
        assert_eq!(s.limits.spool_max_size, 512 << 20);
        assert_eq!(
            s.limits.spool_min_free,
            (100u64 << 30) / 20,
            "5% of 100 GiB"
        );
        assert_eq!(s.notes.len(), 1, "{:?}", s.notes);
        assert!(s.notes[0].contains("storage.spool.min_free_disk = 5% of a 100 GiB volume"));

        let s = resolve_text(
            "[storage.cache]\nmax_memory = \"1%\"\n[storage.spool]\nmin_free_disk = \"1GiB\"\n",
        );
        assert_eq!(
            s.limits.cache_memory,
            ((16u64 << 30) as f64 * 0.01).round() as u64
        );
        assert_eq!(s.limits.spool_min_free, 1 << 30);
        assert!(s.notes[0].contains("of 16 GiB RAM"), "{:?}", s.notes);
    }

    #[test]
    fn percentages_need_host_facts() {
        let config = parse_ok("[storage.buffer]\nmax_memory = \"2%\"\n");
        let err = resolve(config, file(), &linux_defaults(), &BrokenHost).unwrap_err();
        assert!(err.message.contains("cannot read total memory"), "{err}");

        let err = resolve(Config::default(), file(), &linux_defaults(), &BrokenHost).unwrap_err();
        assert!(
            err.message.contains("volume holding /var/lib/scribe/spool"),
            "{err}"
        );

        let absolute = parse_ok("[storage.spool]\nmin_free_disk = \"1GiB\"\n");
        assert!(resolve(absolute, file(), &linux_defaults(), &BrokenHost).is_ok());
    }

    #[test]
    fn converts_sinks_for_the_storage_manager() {
        let s = resolve_text(
        "[[storage.sinks]]\nname = \"alerts\"\npath = \"alerts.db\"\nevents = [\"alert\"]\nretention = \"\"\nbatch_max_events = 10\nbatch_max_wait = \"5s\"\n",
    );
        let sink = &s.storage.sinks[0];
        assert_eq!(sink.name, "alerts");
        assert_eq!(sink.events, vec![EventKind::Alert]);
        assert_eq!(sink.retention, None);
        assert_eq!(sink.batch_max_events, 10);
        assert_eq!(sink.batch_max_wait.as_secs(), 5);
        assert!(sink.accepts(&EventKind::Alert) && !sink.accepts(&EventKind::Flow));
    }

    #[test]
    fn effective_config_is_absolute_and_reloads() {
        let s = resolve_text(
            "[[policy.threat_lists]]\nname = \"l\"\npath = \"t.txt\"\nformat = \"domains\"\n",
        );
        let toml_text = s.effective_toml();
        assert!(toml_text.starts_with("# Effective scribed configuration (source: scribe.toml)"));
        assert!(
            toml_text.contains("data_dir = \"/var/lib/scribe\""),
            "{toml_text}"
        );
        assert!(
            toml_text.contains("/var/lib/scribe/state.db"),
            "{toml_text}"
        );
        assert!(toml_text.contains("/var/lib/scribe/t.txt"), "{toml_text}");
        assert!(
            toml_text.contains("# storage.spool.min_free_disk = 5%"),
            "{toml_text}"
        );

        let reloaded = parse_ok(&toml_text);
        assert_eq!(reloaded, s.effective());
        let again = resolve(reloaded, file(), &linux_defaults(), &FakeHost).unwrap();
        assert_eq!(again.storage.state.options, s.storage.state.options);
        assert_eq!(again.limits, s.limits);
    }

    #[test]
    fn summary_hides_credentials() {
        let s = resolve_text(
        "[storage.state]\nkind = \"postgres\"\nurl = \"postgres://scribe@db/s\"\ncredentials = \"keychain:pg\"\n",
    );
        let summary = s.summary().join("\n");
        assert!(
            summary
                .contains("state store: postgres credentials=<secret> url=postgres://scribe@db/s"),
            "{summary}"
        );
        assert!(!summary.contains("keychain:pg"));
        assert!(summary.contains("mode: learn, profile: default"));
    }

    #[test]
    fn context_lists_built_kinds() {
        let c = context();
        assert_eq!(c.os, Os::current());
        assert!(c.storage_kinds.contains(&"sqlite"));
        assert_eq!(
            c.modules.iter().any(|m| m.id == "url"),
            cfg!(feature = "url")
        );
    }

    // ─── Modules ────────────────────────────────────────────────────────────────

    #[test]
    fn sinks_may_subscribe_to_module_kinds() {
        let s = resolve_text(
        "[[storage.sinks]]\nname = \"urls\"\npath = \"u.db\"\nevents = [\"url.request\", \"metric\"]\n",
    );
        assert_eq!(
            s.storage.sinks[0].events,
            vec![EventKind::parse("url.request").unwrap(), EventKind::Metric]
        );
    }

    #[test]
    fn modules_can_be_switched_off() {
        let c = parse_ok("[modules]\nenabled = []\n");
        assert!(c.modules.enabled.get_ref().is_empty());
        // With the URL module off, its record kind is unknown to sinks.
        let err = parse_err("[modules]\nenabled = []\n[[storage.sinks]]\nname = \"a\"\npath = \"a.db\"\nevents = [\"url.request\"]\n");
        assert!(
            err.message
                .contains("known kinds are flow, alert, audit, metric"),
            "{err}"
        );
        // A section for a built module that is switched off is fine.
        parse_ok("[modules]\nenabled = []\n[modules.url]\nquery = \"strip\"\n");
    }

    #[test]
    fn the_default_module_list_tolerates_builds_without_them() {
        let none = Context {
            os: Os::Linux,
            storage_kinds: vec!["sqlite"],
            modules: vec![],
        };
        let shipped_without_url_section = SHIPPED
            .replace("[modules.url]", "# [modules.url]")
            .replace("query = \"redact_values\"", "# query");
        assert!(parse("", &file(), &none).is_ok());
        let err = parse(&shipped_without_url_section, &file(), &none).unwrap_err();
        assert!(err.message.contains("built: none"), "{err}");
    }

    #[test]
    fn deprecated_url_query_still_works_with_a_warning() {
        let mut s = resolve_text("[privacy]\nurl_query = \"strip\"\n");
        assert_eq!(s.warnings.len(), 1);
        assert!(
            s.warnings[0].contains("write `[modules.url] query = \"strip\"` instead"),
            "{:?}",
            s.warnings
        );
        s.modules = super::resolve::module_settings(
            &s.config,
            "[privacy]\nurl_query = \"strip\"\n",
            &ctx(),
        );
        let text = s.effective_toml();
        assert!(
            text.contains("# warning: privacy.url_query is deprecated"),
            "{text}"
        );
        assert!(text.contains("[modules.url]\nquery = \"strip\""), "{text}");
        assert!(!text.contains("[privacy]"), "{text}");
        assert_eq!(
            parse_ok(&text).modules.sections["url"].get_ref()["query"].as_str(),
            Some("strip")
        );
    }

    #[test]
    fn effective_config_shows_module_defaults() {
        let mut s = resolve_text("[modules]\nenabled = [\"url\"]\n");
        s.modules =
            super::resolve::module_settings(&s.config, "[modules]\nenabled = [\"url\"]\n", &ctx());
        let text = s.effective_toml();
        assert!(text.contains("[modules]\nenabled = [\"url\"]"), "{text}");
        assert!(text.contains("query = \"redact_values\""), "{text}");
        assert!(s.summary().iter().any(|l| l == "modules: url"));
        let off = resolve_text("[modules]\nenabled = []\n");
        assert!(off.summary().iter().any(|l| l == "modules: none"));
    }
}
