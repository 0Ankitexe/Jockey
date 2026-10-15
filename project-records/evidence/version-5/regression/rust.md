# T147 Rust regression — 2026-10-16

Local exact Rust/Cargo/Clippy/rustfmt 1.98.1, offline locked dependency cache.
From the repository root with repository-owned toolchain and Cargo cache:

```sh
export PATH=/home/zer0/main/jockey/target/v5-rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/home/zer0/main/jockey/target/v5-cargo-home
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline --quiet
cargo clippy -p jocky-native-linux --all-targets --features journal --locked --offline -- -D warnings
cargo test -p jocky-native-linux --features journal --locked --offline --quiet
```

All five commands exited 0. Test discovery listed **2,012 workspace tests**
and **1,509 journal-feature native tests**, with no ignored-test summary;
the corresponding runs passed. The list counts include every selected test
binary and doctest listed by Cargo; the journal suite is a focused overlapping
subset, not an additional 1,509 distinct requirements. Initial Clippy found style-only
lints in new V5 sources/tests (collapsible conditions, explicit lifetimes,
test-module placement and clone-on-Copy); they were corrected before the clean
run. No fixture/golden was changed. Configured Ubuntu/Windows CI jobs and
stable-toolchain matrix are not observed hosted runs in this local audit.
