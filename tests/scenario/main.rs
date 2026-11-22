//! Scenario tests: one test per file in `testdata/scenarios/`, played in-process through the
//! module host and the policy engine with `FakeClock` and `MemoryStore` (see `runner.rs`).
//! Run with `cargo nextest run -E 'binary(scenario)'`.

mod runner;

macro_rules! scenario {
    ($(#[$attr:meta])* $fn:ident, $file:literal) => {
        #[test]
        $(#[$attr])*
        fn $fn() {
            runner::run(&runner::load($file));
        }
    };
}

scenario!(alert_acknowledged, "alert-acknowledged");
scenario!(alert_dedupe_window, "alert-dedupe-window");
scenario!(alert_unlisted_host, "alert-unlisted-host");
scenario!(caution_high_entropy_domain, "caution-high-entropy-domain");
scenario!(caution_new_tld_quiet, "caution-new-tld-quiet");
scenario!(caution_ordinary_new_host, "caution-ordinary-new-host");
scenario!(caution_plaintext_known_host, "caution-plaintext-known-host");
scenario!(caution_raw_ip, "caution-raw-ip");
scenario!(caution_threat_list, "caution-threat-list");
scenario!(
    caution_unusual_port_known_process,
    "caution-unusual-port-known-process"
);
scenario!(
    caution_unusual_port_new_process,
    "caution-unusual-port-new-process"
);
scenario!(
    #[ignore = "per-process counters arrive with the daemon pipeline (plan phase 5)"]
    counters_exact,
    "counters-exact"
);
scenario!(
    #[ignore = "hibernation and run states arrive in plan phase 5"]
    daemon_hibernate_capped,
    "daemon-hibernate-capped"
);
scenario!(
    #[ignore = "wakeup, reset and runtime counters arrive in plan phase 5"]
    daemon_wakeup_and_reset,
    "daemon-wakeup-and-reset"
);
scenario!(hostname_unresolved, "hostname-unresolved");
scenario!(learn_adds_hosts_no_alerts, "learn-adds-hosts-no-alerts");
scenario!(learn_auto_switch, "learn-auto-switch");
scenario!(mode_switch_via_api, "mode-switch-via-api");
scenario!(module_signal_scored, "module-signal-scored");

/// Every file has a test above, and only the scenarios that need phase 5 are ignored.
#[test]
fn every_scenario_file_has_a_test() {
    const LISTED: &[&str] = &[
        "alert-acknowledged",
        "alert-dedupe-window",
        "alert-unlisted-host",
        "caution-high-entropy-domain",
        "caution-new-tld-quiet",
        "caution-ordinary-new-host",
        "caution-plaintext-known-host",
        "caution-raw-ip",
        "caution-threat-list",
        "caution-unusual-port-known-process",
        "caution-unusual-port-new-process",
        "counters-exact",
        "daemon-hibernate-capped",
        "daemon-wakeup-and-reset",
        "hostname-unresolved",
        "learn-adds-hosts-no-alerts",
        "learn-auto-switch",
        "mode-switch-via-api",
        "module-signal-scored",
    ];
    const NEED_PHASE_5: &[&str] = &[
        "counters-exact",
        "daemon-hibernate-capped",
        "daemon-wakeup-and-reset",
    ];
    let dir = scribe_tests::testdata("scenarios");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".yaml").map(str::to_owned)
        })
        .collect();
    files.sort();
    assert_eq!(files, LISTED, "add a scenario!() line for each new file");
    for name in LISTED {
        let s = runner::load(name);
        let needs = runner::needs_phase_5(&s);
        assert_eq!(
            !needs.is_empty(),
            NEED_PHASE_5.contains(name),
            "{name}: phase 5 needs {needs:?}"
        );
    }
}

/// The runner really checks: a scenario with one wrong expectation fails.
#[test]
fn a_wrong_expectation_fails() {
    for change in [
        |s: &mut runner::Scenario| {
            s.expect.alerts.as_mut().unwrap()[0].reason = "unusual_port".into()
        },
        |s: &mut runner::Scenario| s.expect.alerts.as_mut().unwrap().clear(),
        |s: &mut runner::Scenario| s.expect.mode = Some(scribe_core::Mode::Alert),
    ] {
        let mut s = runner::load("caution-raw-ip");
        change(&mut s);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner::run(&s)));
        assert!(result.is_err());
    }
    let mut hosts = runner::load("caution-plaintext-known-host");
    hosts
        .expect
        .hosts
        .as_mut()
        .unwrap()
        .get_mut("plain.example.com")
        .unwrap()
        .requests = Some(2);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner::run(&hosts))).is_err()
    );
}

/// SCN-26: unknown keys and bad times are refused with where they are.
#[test]
fn runner_rejects_bad_scenarios() {
    let good = "name: x\ndescription: d\nmode: learn\nprofile: default\nevents:\n  - { at: 0s, dst: \"192.0.2.10:443\" }\nexpect: {}\n";
    assert!(runner::parse(good).is_ok());
    let typo = good.replace("profile:", "profle:");
    let err = runner::parse(&typo).err().unwrap();
    assert!(
        err.contains("unknown field `profle`") && err.contains("line 4"),
        "{err}"
    );
    let event_typo = good.replace("dst:", "dest:");
    let err = runner::parse(&event_typo).err().unwrap();
    assert!(
        err.contains("unknown field `dest`") && err.contains("line 6"),
        "{err}"
    );
    let bad_time = good.replace("at: 0s", "at: soon");
    let err = runner::parse(&bad_time).err().unwrap();
    assert!(err.contains("event 0: bad time \"soon\""), "{err}");
    let bad_mode = good.replace("mode: learn", "mode: paranoid");
    assert!(runner::parse(&bad_mode).err().unwrap().contains("line 3"));
}
