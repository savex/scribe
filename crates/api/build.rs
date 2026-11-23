//! Generates the gRPC code from `proto/scribe/v1/api.proto`. `protox` parses the protocol in Rust,
//! so building needs no `protoc`. Only the sides the enabled features need are generated.
//! Every message also derives `serde::Serialize` and `Deserialize` (snake_case field names, as in
//! the .proto; unknown fields are refused when reading).
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let api = root.join("scribe/v1/api.proto");
    println!("cargo:rerun-if-changed={}", root.display());
    let fds = protox::compile([&api], [&root])?;
    tonic_prost_build::configure()
        .build_server(std::env::var_os("CARGO_FEATURE_SERVER").is_some())
        .build_client(std::env::var_os("CARGO_FEATURE_CLIENT").is_some())
        .build_transport(false)
        // `scribe … --json` prints the messages with the protocol's own field names.
        .type_attribute(
            ".scribe.v1",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        // Reading JSON (the UI's mock scenarios) fills absent fields and refuses unknown ones.
        .message_attribute(".scribe.v1", "#[serde(default, deny_unknown_fields)]")
        .compile_fds(fds)?;
    Ok(())
}
