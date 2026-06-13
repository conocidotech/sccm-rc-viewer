# sccm-rc — SCCM Remote Control viewer in Rust

A modern, pure-Rust reimplementation of the **viewer side** of Microsoft's
ConfigMgr Remote Control client (`CmRcViewer.exe`, the ConfigMgr 2012-era
ActiveX-hosting Win32 binary). Targets keep using the existing SCCM client
agent (`CcmExec` / `RdpCoreSccm.dll`) unchanged — only the operator-side
viewer is reimplemented.

It speaks the SCCM RC wire protocol directly: an SSPI-sealed (Kerberos/NTLM)
TCP/2701 stream carrying a standard RDP byte stream, decoded with a vendored,
SCCM-patched [IronRDP](https://github.com/Devolutions/IronRDP).

> Status: **working** — connects, authenticates (mutual-auth Kerberos), and
> renders live sessions with input, clipboard, file transfer, multi-monitor,
> session audit/recording and a GPU-accelerated renderer. See
> [`docs/ROADMAP.md`](docs/ROADMAP.md) for what's done and what's planned.

## Why this exists

The original viewer has poor HiDPI/multi-monitor support, cryptic error
messages that hide the actual missing prerequisite, no clipboard or
file-transfer, no bulk-connect, and no audit trail. Most of those pain points
are fixable in a new client; the rest are target-side Microsoft behaviours
this client surfaces clearly instead of failing silently.

## Crates

| Crate | Purpose | Status |
|---|---|---|
| `sccm-rc-protocol` | TCP/2701 SecFilter framing, SSPI seal/unseal handshake, session arbitration, `cliprdr` clipboard, MPPC decompression | working |
| `sccm-rc-orders` | RDP drawing-order + bitmap decode and software canvas | working |
| `sccm-rc-core` | High-level async `Session` API; glues the protocol layer to IronRDP | working |
| `sccm-rc-diag` | Pre-flight prerequisite checker (TCP/2701, LSA/SCM/WMI); CLI + library | working |
| `sccm-rc-viewer` | Native viewer UI: `winit` window, software (`softbuffer`) or GPU (`wgpu`) rendering, toolbar, clipboard, file transfer, curtain/view-only, audit, recording | working |

## Building

This project targets the `x86_64-pc-windows-gnu` Rust toolchain (no admin
required; MSVC Build Tools not needed). The MinGW-w64 linker/`dlltool` comes
from [WinLibs](https://winlibs.com/).

One-time setup:

```powershell
# 1. Rust (user-scope)
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal

# 2. MinGW-w64 (POSIX threads, UCRT)
winget install --id BrechtSanders.WinLibs.POSIX.UCRT --scope user
```

Then, before each shell session:

```powershell
. .\env.ps1   # prepends rust + MinGW to $env:Path
cargo build --release
```

CI (`.github/workflows/ci.yml`) builds and tests the workspace on
`windows-latest` with the same gnu toolchain.

## Running

```powershell
# Connect the viewer to a target
cargo run --release -p sccm-rc-viewer -- <target-hostname>

# Pre-flight prerequisite check (exit 0 = clear, 2 = blocker found)
cargo run -p sccm-rc-diag -- <target-hostname> [--json]
```

## Vendored IronRDP

`vendor/ironrdp-connector` is a patched copy of the crate (see
[`vendor/ironrdp-connector/SCCM-PATCHES.md`](vendor/ironrdp-connector/SCCM-PATCHES.md))
redirected via `[patch.crates-io]`. The patch allows standard RDP security
(`encryption = NONE`) because the SCCM SecurityFilter already seals every
frame. Its upstream MIT/Apache-2.0 licenses are preserved in that directory.

## Protocol notes

`docs/SPEC.md` and `docs/PROTOCOL.md` document the on-wire format as observed
from a live `CmRcViewer.exe` session. `experiments/` holds the
reverse-engineering tooling (SSPI hook, capture scripts) used to derive it,
against a Microsoft binary for interoperability.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. The vendored IronRDP code retains its own MIT/Apache-2.0
licenses.
