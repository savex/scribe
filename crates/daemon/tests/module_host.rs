//! The module host: notes, isolation, budgets, schedules and the output queue (NFR-20).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::Clock;
use scribe_daemon::modules::{ModuleHost, Output, OutputQueue, RunState};
use scribe_module_api::{ConfigDoc, Module, ModuleHealth};
use scribe_test_support::{flow, FakeClock, Fault, MisbehavingModule, TagModule, TicksModule};

fn host(modules: Vec<Box<dyn Module>>, text: &str) -> ModuleHost {
    ModuleHost::new(modules, &ConfigDoc::new(text)).unwrap()
}

fn start(host: &mut ModuleHost, clock: &FakeClock, queue: &OutputQueue) {
    let clock: Arc<dyn Clock> = Arc::new(clock.clone());
    for (id, result) in host.start(clock, |id| queue.emitter(id), BTreeMap::new()) {
        result.unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

fn http() -> scribe_core::Observation {
    flow("192.0.2.20:80")
        .http_get("http://plain.example.com/a")
        .observe()
}

mod functional {
    use super::*;

    #[test]
    fn notes_are_keyed_by_module_and_output_is_queued() {
        let mut host = host(
            vec![Box::new(TagModule::default())],
            "[modules.tag]\nlabel = \"seen\"\n",
        );
        assert_eq!(host.ids(), ["tag"]);
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);
        assert!(host.needs_payload());

        let (notes, signals) = host.on_flow(&http());
        assert_eq!(notes.get_str("tag"), Some("seen"));
        assert!(signals.is_empty());

        let out = queue.take();
        assert_eq!(out.len(), 2, "one record and one state write");
        assert!(out
            .iter()
            .any(|o| matches!(o, Output::Event(e) if e.kind().name() == "tag.seen")));
        assert!(out
            .iter()
            .any(|o| matches!(o, Output::State { module: "tag", key, .. } if key == "seen")));
    }

    #[test]
    fn a_panicking_module_is_switched_off_and_the_others_keep_running() {
        let mut host = host(
            vec![
                Box::new(MisbehavingModule::new(Fault::PanicsOnPayload)),
                Box::new(TicksModule::new()),
            ],
            "",
        );
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);

        let bad = flow("192.0.2.20:80")
            .plaintext()
            .payload(&[0xff, 1])
            .observe();
        let (notes, _) = host.on_flow(&bad);
        assert!(notes.is_empty());
        let status = host.status();
        assert!(matches!(&status[0].state, RunState::Failed(why) if why.contains("cannot parse")));
        assert!(matches!(status[0].health, ModuleHealth::Degraded(_)));
        assert_eq!(status[1].state, RunState::Running);

        // The failed module gets no more flows; the source still ticks.
        let (notes, _) = host.on_flow(&http());
        assert!(notes.is_empty());
        clock.advance(Duration::from_secs(10));
        host.tick();
        assert_eq!(queue.take().len(), 1, "ticks.count still emitted");
    }

    #[test]
    fn slow_hooks_are_counted() {
        let mut host = host(vec![Box::new(MisbehavingModule::new(Fault::Slow))], "")
            .with_budget(Duration::from_millis(1));
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);
        host.on_flow(&http());
        host.on_flow(&http());
        assert_eq!(host.status()[0].over_budget, 2);
    }

    #[test]
    fn sources_tick_on_their_interval() {
        let mut host = host(
            vec![Box::new(TicksModule::new())],
            "[modules.ticks]\nevery = \"30s\"\n",
        );
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);
        host.tick();
        assert!(queue.take().is_empty(), "not due yet");
        clock.advance(Duration::from_secs(29));
        host.tick();
        assert!(queue.take().is_empty());
        clock.advance(Duration::from_secs(1));
        host.tick();
        host.tick();
        assert_eq!(queue.take().len(), 1, "once per interval");
        clock.advance(Duration::from_secs(30));
        host.tick();
        assert_eq!(queue.take().len(), 1);
    }

    #[test]
    fn pause_resume_and_stop() {
        let mut host = host(
            vec![Box::new(TagModule::default()), Box::new(TicksModule::new())],
            "",
        );
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);

        host.pause();
        assert!(host.status().iter().all(|s| s.state == RunState::Paused));
        assert!(!host.needs_payload());
        assert!(host.on_flow(&http()).0.is_empty());
        clock.advance(Duration::from_secs(60));
        host.tick();
        assert!(queue.take().is_empty(), "nothing while paused");

        host.resume();
        assert_eq!(host.on_flow(&http()).0.get_str("tag"), Some("tagged"));
        host.stop();
        assert!(host.status().iter().all(|s| s.state == RunState::Stopped));
        assert!(host.on_flow(&http()).0.is_empty());
    }

    #[test]
    fn reload_reports_settings_that_need_a_restart() {
        let mut host = host(vec![Box::new(TagModule::default())], "");
        let clock = FakeClock::default();
        let queue = OutputQueue::new(100);
        start(&mut host, &clock, &queue);
        let restart = host
            .reconfigure(&ConfigDoc::new(
                "[modules.tag]\nlabel = \"x\"\nstrict = true\n",
            ))
            .unwrap();
        assert_eq!(restart, ["modules.tag.strict"]);
        assert_eq!(
            host.on_flow(&http()).0.get_str("tag"),
            Some("x"),
            "label applied live"
        );
        let err = host
            .reconfigure(&ConfigDoc::new("[modules.tag]\nlabel = \"\"\n"))
            .unwrap_err();
        assert!(err.contains("module tag: label must not be empty"), "{err}");
    }

    #[test]
    fn a_full_queue_drops_and_counts() {
        let mut host = host(vec![Box::new(TagModule::default())], "");
        let clock = FakeClock::default();
        let queue = OutputQueue::new(1);
        start(&mut host, &clock, &queue);
        host.on_flow(&http());
        host.on_flow(&http());
        assert_eq!(queue.take().len(), 1);
        assert_eq!(queue.dropped(), 3);
    }

    #[test]
    fn a_module_that_cannot_restart_is_marked_failed() {
        let mut host = host(vec![Box::new(MisbehavingModule::new(Fault::NoRestart))], "");
        let clock = FakeClock::default();
        let queue = OutputQueue::new(10);
        start(&mut host, &clock, &queue);
        host.stop();
        let results = host.start(
            Arc::new(clock.clone()),
            |id| queue.emitter(id),
            BTreeMap::new(),
        );
        assert!(results[0].1.is_err());
        assert!(matches!(host.status()[0].state, RunState::Failed(_)));
        assert!(matches!(
            host.status()[0].health,
            ModuleHealth::Unhealthy(_)
        ));
    }

    #[test]
    fn configuration_errors_name_the_module() {
        let err = ModuleHost::new(
            vec![Box::new(TagModule::default())],
            &ConfigDoc::new("[modules.tag]\nnope = 1\n"),
        )
        .err()
        .unwrap();
        assert!(err.starts_with("module tag: "), "{err}");
    }

    #[test]
    fn instantiate_follows_the_enabled_list() {
        use scribe_daemon::modules::{instantiate, ModuleSpec};
        let specs = [
            ModuleSpec {
                id: "tag",
                make: || Box::new(TagModule::default()),
            },
            ModuleSpec {
                id: "ticks",
                make: || Box::new(TicksModule::new()),
            },
        ];
        let ids = |enabled: &[&str]| -> Vec<&'static str> {
            let enabled: Vec<String> = enabled.iter().map(|s| s.to_string()).collect();
            instantiate(&specs, &enabled)
                .iter()
                .map(|m| m.manifest().id)
                .collect()
        };
        assert_eq!(ids(&["ticks", "tag"]), ["ticks", "tag"]);
        assert_eq!(ids(&["tag", "missing"]), ["tag"]);
        assert!(ids(&[]).is_empty());
    }
}
