# sccm-rc — open-source SCCM Remote Control viewer in Rust

A modern, internal IT replacement for Microsoft's `CmRcViewer.exe`
(ConfigMgr 2012-era ActiveX-hosting Win32 binary). Targets keep using
the existing SCCM client agent (`CcmExec`/`RdpCoreSccm.dll`) — only
the viewer side is reimplemented.

Status: **Phase 0 — scaffold + diagnostics**. Protocol implementation
(Phases 1-2) requires a pcap of a live session against a known-good
target before the wire format can be confirmed. See
[`docs/SPEC.md`](docs/SPEC.md).

## Why this exists

See [`../../tools/rc-re/REBUILD-BRIEF.md`](../../tools/rc-re/REBUILD-BRIEF.md)
for the reverse-engineering analysis + deep-research-backed mapping
from real-world user complaints to rebuild scope.

Short version: the original viewer has bad HiDPI/multi-monitor support,
cryptic error messages that hide the actual prerequisite that's missing,
no clipboard/file-transfer, no bulk-connect, no audit. Roughly 70% of
those pain points are fixable in a new client; the remaining 30% are
target-side Microsoft bugs we can only flag clearly, not fix.

## Crates

| Crate | Purpose | Status |
|---|---|---|
| `sccm-rc-protocol` | TCP/2701 SecFilter framing, SSPI handshake, arbitration RPC | stubs |
| `sccm-rc-core` | High-level Session API, glues protocol → IronRDP | stubs |
| `sccm-rc-diag` | Pre-flight prereq-checker (CLI today, library for the UI tomorrow) | working: TCP/2701 check; stubs for LSA/SCM/WMI |
| `sccm-rc-viewer` | UI shell (Tauri 2 + egui canvas — chosen but not built) | empty |

## Building

This project uses the `x86_64-pc-windows-gnu` Rust toolchain (no admin
required; MSVC Build Tools not needed). The classic-MinGW linker comes
from WinLibs.

One-time setup:

```powershell
# 1. Rust (user-scope)
& $env:USERPROFILE\tools\rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal --no-modify-path

# 2. Classic MinGW (POSIX threads, UCRT)
winget install --id BrechtSanders.WinLibs.POSIX.UCRT --scope user
```

Then before each shell session:

```powershell
. .\env.ps1   # adds rust + MinGW to $env:Path
cargo build
```

## Running the diagnostics tool

```powershell
cargo run --bin sccm-rc-diag -- <target-hostname>
# or:
cargo run --bin sccm-rc-diag -- <target-hostname> --json
```

Exit code 0 = no blockers, 2 = at least one blocker found.

## What's next

1. **Get a pcap** of a live `CmRcViewer.exe` session against a known-good
   test target. Drop it in `captures/`. See `docs/SPEC.md` § 6.
2. Decode the SecFilter framing → fill in stubs in
   `sccm-rc-protocol::transport`.
3. Wire SSPI via `sspi-rs` (pin to a version without the picky-krb
   conflict — `sspi 0.16` is currently broken in build).
4. Implement arbitration RPC.
5. Hand off pure RDP bytes to IronRDP.
6. Build the UI.
