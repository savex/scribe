//! Compiles `src/bpf/scribe.bpf.c` with `clang -target bpf` and generates its `libbpf-rs`
//! skeleton (`$OUT_DIR/scribe.skel.rs`), on Linux only: other systems build the decoding half
//! alone. Needs `clang` and the kernel headers (`linux-libc-dev`, installed with `libc6-dev`).

fn main() {
    println!("cargo:rerun-if-changed=src/bpf");
    // Built on Linux for Linux only (the build machine compiles the eBPF programs).
    #[cfg(target_os = "linux")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        linux::build();
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    pub fn build() {
        let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
        // `asm/*.h` of the UAPI headers sit in the multiarch directory (native) or the cross
        // toolchain's include directory.
        let mut args = vec!["-O2".to_owned(), "-g".to_owned(), "-Wall".to_owned()];
        for dir in [
            format!("/usr/include/{arch}-linux-gnu"),
            format!("/usr/{arch}-linux-gnu/include"),
        ] {
            if Path::new(&dir).is_dir() {
                args.push(format!("-I{dir}"));
            }
        }
        if let Ok(clang) = std::env::var("SCRIBE_CLANG") {
            println!("cargo:warning=using {clang} for the eBPF programs");
        }
        let mut builder = libbpf_cargo::SkeletonBuilder::new();
        builder.source("src/bpf/scribe.bpf.c").clang_args(args);
        // The skeleton in OUT_DIR is never read by people: skip libbpf-cargo's rustfmt pass (a
        // missing binary is skipped), so toolchains without rustfmt (the MSRV job) build too.
        builder.rustfmt("/nonexistent/scribe-skip-rustfmt");
        if let Ok(clang) = std::env::var("SCRIBE_CLANG") {
            builder.clang(clang);
        }
        builder
            .build_and_generate(out.join("scribe.skel.rs"))
            .unwrap_or_else(|e| {
                panic!(
                    "building the eBPF programs failed (clang and the kernel headers are \
                     needed: apt-get install clang libelf-dev zlib1g-dev): {e:#}"
                )
            });
        println!("cargo:rerun-if-env-changed=SCRIBE_CLANG");
    }
}
