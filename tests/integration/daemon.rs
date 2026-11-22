//! Config → resolve → storage manager → backends, through `scribed`'s `serve`.

use scribe_core::platform::DefaultPaths;
use scribe_daemon::app::serve;
use scribe_daemon::config::{context, parse, resolve, HostFacts, Settings, Source};

fn settings_in(dir: &std::path::Path) -> Settings {
    let text = format!("data_dir = '{}'\n[log]\nfile = ''\n", dir.display());
    let source = Source::File("test.toml".into());
    let config = parse(&text, &source, &context()).unwrap();
    resolve(
        config,
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

#[test]
fn serve_creates_folders_and_stops_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(serve(settings_in(&data), std::future::ready(())))
        .unwrap();
    assert!(data.is_dir());
    assert!(data.join("spool").is_dir());
    assert!(
        data.join("state.db").is_file(),
        "storage opened and migrated"
    );
}
