# Build image for scripts/build/linux.sh. Native arm64 on Apple silicon (cross-compiles
# x86_64-unknown-linux-gnu); also builds as amd64 for x86_64 hosts or Rosetta.
ARG BASE=ubuntu:24.04
FROM ${BASE}

ARG MSRV=1.89
ARG NEXTEST_VERSION=0.9.152
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Build tools; libpcap for the pcap sensor (phase 6); clang, libelf and zlib for the eBPF sensor
# (phase 7, option 7B). On arm64 also the x86_64 cross toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config git python3 curl ca-certificates xz-utils libpcap-dev \
      clang libelf-dev zlib1g-dev \
 && if [ "$(dpkg --print-architecture)" = arm64 ]; then \
      apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross; \
    fi \
 && rm -rf /var/lib/apt/lists/*

# Rust: stable (with fmt and clippy) and the minimum version, for both Linux targets.
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
      --component rustfmt,clippy \
 && rustup toolchain install "$MSRV" --profile minimal \
 && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
 && rustup target add --toolchain "$MSRV" x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# cargo-nextest, prebuilt.
RUN case "$(dpkg --print-architecture)" in arm64) a=linux-arm ;; *) a=linux ;; esac \
 && curl -sSfL "https://get.nexte.st/$NEXTEST_VERSION/$a" | tar zxf - -C "$CARGO_HOME/bin"

# Cross-compiling to x86_64 (only used on arm64; harmless elsewhere).
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar

# The repository is mounted from the host with another owner.
RUN git config --system --add safe.directory '*'
WORKDIR /src
