//! The UI's mock API scenarios (`ui/tests/mocks/api-scenarios/`) use the protocol's messages:
//! every API section parses as its message, with no unknown fields, so the mocks follow `proto/`.

use scribe_api::pb;
use scribe_tests::repo_root;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Keys a scenario file may have besides the API messages: how the mock server behaves.
const SCENARIO_KEYS: [&str; 7] = [
    "scenario",
    "description",
    "extends",
    "stream",
    "timeline",
    "generate",
    "connect",
];

fn parse<T: DeserializeOwned>(file: &str, part: &str, value: &Value) {
    if let Err(e) = serde_json::from_value::<T>(value.clone()) {
        panic!("{file}: {part} does not match the API message: {e}");
    }
}

#[test]
fn every_mock_scenario_matches_the_api_messages() {
    let dir = repo_root().join("ui/tests/mocks/api-scenarios");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(files.len() >= 10, "{}", dir.display());
    for path in files {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{file}: {e}"));
        let name = doc["scenario"].as_str().unwrap_or_default();
        assert_eq!(format!("{name}.json"), file, "the scenario names its file");
        for (key, value) in doc.as_object().unwrap() {
            match key.as_str() {
                "status" => {
                    parse::<pb::Status>(&file, key, value);
                    if let Some(state) = value.get("run_state").and_then(Value::as_str) {
                        // `degraded` is a health result, not a run state (specs 8.5).
                        assert!(
                            ["running", "hibernating"].contains(&state),
                            "{file}: run_state {state}"
                        );
                    }
                }
                "hosts" => parse::<pb::HostPage>(&file, key, value),
                "alerts" => parse::<pb::AlertPage>(&file, key, value),
                "baseline" => parse::<pb::Baseline>(&file, key, value),
                "stream" => {
                    if let Some(t) = value.pointer("/alerts/template") {
                        parse::<pb::Alert>(&file, "stream.alerts.template", t);
                    }
                }
                "timeline" => {
                    for step in value.as_array().unwrap() {
                        if let Some(s) = step.get("status_override") {
                            parse::<pb::Status>(&file, "timeline status_override", s);
                        }
                    }
                }
                "extends" => assert!(
                    path.with_file_name(value.as_str().unwrap()).is_file(),
                    "{file}: extends a missing file"
                ),
                other => assert!(
                    SCENARIO_KEYS.contains(&other),
                    "{file}: unknown key {other}"
                ),
            }
        }
    }
}

#[test]
fn the_check_catches_a_field_the_api_does_not_have() {
    let stale = serde_json::json!({ "api_version": 1, "counters_since": "2023-11-14T22:13:20Z" });
    assert!(serde_json::from_value::<pb::Status>(stale).is_err());
}
