# SCCM Remote Control wire protocol — work-in-progress spec

Reverse-engineered from `RdpCoreSccm.dll` 5.00.7958.1401 (SCCM 2012,
build 2014-09-04, x86) and the viewer `CmRcViewer.exe` of the same
version. Source artifacts live in `C:\Users\you\tools\rc-re\out\`.

**Status legend per section:**
- ✅ confirmed from decomp + strings
- 🟡 inferred, plausible — needs pcap confirmation
- ❓ unknown — TBD via pcap or live trace

---

## 1. Transport

| Field | Value | Source |
|---|---|---|
| Transport | TCP | ✅ `WSASocketW`, `WSASend`, `WSARecv`, IOCP via `BindIoCompletionCallback` |
| Port | **2701/TCP** | ✅ literal in error string: *"windows firewall blocks TCP Port 2701, or remote control feature is disabled"* |
| Listening on target | `CcmExec.exe` (SMS Agent Host service) loads `RdpCoreSccm.dll` as in-process server | ✅ same DLL exports both client + server APIs (`RpcServerListen`, `RpcServerRegisterIfEx`, `NdrServerCall2` are all present) |
| Server lookup | `HKLM\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control` on target | ✅ string in `RdpCoreSccm.dll` |
| Viewer-side history | `HKCU\Software\Microsoft\ConfigMgr10\Remote Control` | ✅ |

The data path on a single connection layers like this:

```
   TCP/2701 stream (raw socket, IOCP)
     └── SecFilter wrap  (per-message length-prefixed framing,
     │                    holding SSPI tokens during handshake
     │                    and an opaque envelope after)         🟡 — framing details TBD
     │
     ├── Phase 1: SSPI Negotiate token exchange                  ✅ flow / ❓ exact bytes
     │
     ├── Phase 2: Session arbitration RPC (RequestHostArbitration) ✅ semantics / ❓ RPC UUID + opnums
     │
     └── Phase 3: Standard MS-RDPBCGR frames                     ✅ (it IS standard RDP)
                  (= what the original viewer feeds into
                   `IMsRdpClient6` via the `IRDPENCNetStream`
                   external-transport interface)
```

---

## 2. Phase 1 — SSPI Negotiate handshake

### What we know ✅

- Auth package: **Negotiate** (NTLM/Kerberos), via `Secur32.dll!InitSecurityInterfaceW`
- Helper used: `pHelper->AllocateSSPIBuffer(...)`
- SPN format: `TERMSRV/<target-hostname>` — viewer string `Target SPN = %s`
- SPN built by:
  ```c
  StringCbPrintf(pTarget, cbTargetSize, L"%s/%s", L"TERMSRV", wszTargetHost);
  ```
- After token exchange, `CompleteAuthToken` is called (rare — only used
  with Negotiate when extra handshake legs needed).
- Two-sided: failure strings exist for `"Failed to do Handshake in client"` and `"Failed to do Handshake in Server"` → both ends of the DLL are reachable from this binary.

### What we don't know ❓

- **Exact SecFilter frame header**: length-prefix size (16-bit vs 32-bit),
  byte-order, version byte, type byte. The decomp suggests there's a
  small structured header before each SSPI token. Confirm via pcap.
- **Whether channel-binding / EPA is applied** to the SSPI context
  (would matter for downgrade-resistance under TLS — but no TLS here).

### Open questions to resolve via pcap

1. Does the viewer send a "client hello" before the first SSPI token,
   or does the first packet contain the NEGOTIATE token directly?
2. How are multi-leg NTLM/Kerberos token exchanges multiplexed
   (one-token-per-TCP-segment, or framed)?
3. Does the server respond with a fixed-length status code after auth
   succeeds, before arbitration begins?

---

## 3. Phase 2 — Session arbitration

### What we know ✅

- Method name in viewer: `m_spIRDPCLAxHost->RequestHostArbitration(target, viewerUser)`
- Event callbacks (state machine):
  - `OnSessionArbitrationHostIdle` — no user logged into target
  - `OnSessionArbitrationHostInUse` — someone else already in RC session
  - `OnSessionArbitrationHostAllowed` — remote user clicked Allow
  - `OnSessionArbitrationHostDenied` — remote user clicked Deny / timeout
- Arbitration runs **after** SSPI auth completes but **before** RDP frames.
- "Permission" UX on target side is rendered by `SCCMRDPUser.exe`
  (a child process spawned by `CcmExec` for the consent prompt) — this
  is why the 2111-era third-party-DLL-injection bugs in `SCCMRDPUser.exe`
  cause "stuck on Connecting to host session" symptoms.

### What we don't know ❓

- **RPC interface UUID + opnum table**: not in the strings we extracted.
  Need pcap with the RPC bind PDU visible.
- **Async timeout**: how long does the viewer wait for HostAllowed
  before treating it as Denied? (Some `SCCM RC` deployments configure
  this via `HKLM\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control\PermissionRequired`.)
- **Bypass conditions**: when `PermissionRequired = 0` on the target,
  is the RPC skipped entirely or does the server short-circuit to
  HostAllowed? (Probably the latter — keeps the wire format stable.)

---

## 4. Phase 3 — RDP

### What we know ✅

This is **standard MS-RDPBCGR** as defined by Microsoft public docs.
The original viewer feeds these bytes into the **standard RDP ActiveX**
(`mstscax.dll`'s `IMsRdpClient6+`) via the `IRDPENCNetStream` external
transport interface. Settings observed:

| Setting | Value | Note |
|---|---|---|
| Color depth | server-driven | no override seen |
| Compression | server-driven | likely RDP6+ bulk compression |
| `put_RedirectDrives` | `VARIANT_FALSE` | hardcoded off in viewer |
| `put_RedirectPorts` | `VARIANT_FALSE` | hardcoded off |
| `put_RedirectPrinters` | `VARIANT_FALSE` | hardcoded off |
| `put_RedirectSmartCards` | `VARIANT_FALSE` | hardcoded off |
| `put_HotKeyCtrlAltDel` | `VK_END` | so `Ctrl+Alt+End` sends `Ctrl+Alt+Del` to target |
| `put_GatewayProfileUsageMethod` | `TSC_PROXY_PROFILE_MODE_EXPLICIT` | no TS gateway |

### Implication for our rebuild

- For the RDP layer itself, **IronRDP** does everything we need.
- For the hardened-off redirections — we **can flip them on** in our
  viewer if HCPA security policy allows. CLIPRDR/RDPDR/RDPSND are
  natively supported in IronRDP.
- The `put_HotKeyCtrlAltDel` mapping is a viewer-side preference, not
  wire. We control it.

### What we don't know ❓

- **Does the SCCM-flavored RDP have any custom virtual channels** beyond
  the standard set? The strings mention `IRDPVirtualChannel`,
  `IRDPCoreVirtualChannel`, `IRDPENCWLCUserServices` — these may be
  pure ActiveX/COM aggregations rather than wire-level channels.
- **What MS-RDPBCGR security layer is negotiated**? Standard RDP can do
  Standard RDP Security, TLS, or CredSSP. Given SSPI is already done
  outside the RDP-frame layer, it's likely **Standard RDP Security** or
  even "encryption off" with the outer SecFilter layer providing privacy.

---

## 5. Implementation roadmap (mirrors `REBUILD-BRIEF.md` § 7)

| Phase | Crate | Status |
|---|---|---|
| 0 | `sccm-rc-diag` TCP/2701 check | ✅ implemented |
| 1 | Confirm spec via pcap → fill the ❓ sections above | ⏳ pending |
| 2 | `sccm-rc-protocol::transport` SecFilter framing | ⏳ stubs only |
| 2 | `sccm-rc-protocol::handshake` SSPI loop | ⏳ stubs only |
| 2 | `sccm-rc-protocol::arbitration` RPC bind + call | ⏳ stubs only |
| 3 | `sccm-rc-core::Session` glue to IronRDP | ⏳ stubs only |
| 4 | `sccm-rc-diag` LSA/SCM/WMI checks 2-4 | ⏳ stubs only |
| 5 | `sccm-rc-viewer` UI (Tauri 2 + egui canvas) | ⏳ empty |

---

## 6. Action required from the user before Phase 1 can complete

A **pcap of a live `CmRcViewer.exe` → test-target session** with:

- Wireshark on the viewer-side host (or a SPAN port mirroring its traffic)
- A test target where you have admin (so you can rule out prereq issues)
- Capture filter: `tcp port 2701`
- Save as `captures/<hostname>-<date>.pcapng` in this workspace
- Annotate timing (in a sibling `.notes.md`):
  - T+0: when "Connect" was clicked
  - T+x: when the consent prompt appeared on target
  - T+y: when the operator clicked Allow on target
  - T+z: when screen first rendered

Once we have one good capture, the SecFilter framing + RPC opnums can
be decoded by hand (it's only ~10 KB of bytes before pure RDP starts).
