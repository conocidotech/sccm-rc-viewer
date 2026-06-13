# Contributing to sccm-rc

Thanks for your interest in improving `sccm-rc`! This document covers the build
setup, how to run the checks, and the conventions we follow.

## Development setup

`sccm-rc` targets the **`x86_64-pc-windows-gnu`** Rust toolchain (no admin or MSVC
Build Tools required). The MinGW-w64 linker and `dlltool` come from
[WinLibs](https://winlibs.com/).

```powershell
# One-time
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal
rustup component add rustfmt clippy
winget install --id BrechtSanders.WinLibs.POSIX.UCRT --scope user
```

Before each shell session, source `env.ps1` to put Rust + MinGW on `PATH`:

```powershell
. .\env.ps1
cargo build --release
```

## Before opening a PR

Run the same checks CI runs:

```powershell
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

`fmt` and `clippy` are currently **advisory** in CI (the codebase predates gating);
new code should still be `fmt`-clean and avoid introducing clippy warnings.

## Project layout

- `crates/sccm-rc-protocol` — TCP/2701 framing, SSPI seal/unseal, arbitration, clipboard, MPPC
- `crates/sccm-rc-orders` — RDP drawing-order/bitmap decode + canvas
- `crates/sccm-rc-core` — high-level async `Session` API
- `crates/sccm-rc-diag` — pre-flight prerequisite checker
- `crates/sccm-rc-viewer` — native viewer UI
- `vendor/ironrdp-connector` — **patched** IronRDP (see `vendor/ironrdp-connector/SCCM-PATCHES.md`);
  redirected via `[patch.crates-io]`. Keep changes minimal and documented there.
- `docs/` — protocol/spec/roadmap; `experiments/` — reverse-engineering tooling.

## Conventions

- **Commits:** short imperative subject, optionally a Conventional-Commits prefix
  (`feat:`, `fix:`, `perf:`, `docs:`, `ci:`). Reference issues where relevant.
- **Comments:** match the density and idiom of the surrounding code; explain *why*,
  not *what*.
- **No secrets / no real infrastructure** in commits — hostnames, IPs, captures, and
  decrypted session dumps are git-ignored for a reason. Double-check before pushing.

## Testing against a target

Live testing needs a real SCCM-managed Windows target you are authorized to remote-
control. Never test against `localhost` (it can log you out of your own session).

## License

By contributing, you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, matching the project.
