//! Generates the module's gRPC code from `proto/scribe/v1/modules/url.proto` (with `protox`, no
//! `protoc`) when the `server` or `client` feature asks for it.
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var_os("CARGO_FEATURE_SERVER").is_some();
    let client = std::env::var_os("CARGO_FEATURE_CLIENT").is_some();
    if !server && !client {
        return Ok(());
    }
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let proto = root.join("scribe/v1/modules/url.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    let fds = protox::compile([&proto], [&root])?;
    tonic_prost_build::configure()
        .build_server(server)
        .build_client(client)
        .build_transport(false)
        .type_attribute(".scribe.v1.modules.url", "#[derive(serde::Serialize)]")
        .compile_fds(fds)?;
    Ok(())
}
