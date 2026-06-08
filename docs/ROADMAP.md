# Feature roadmap — clipboard, file transfer, multi-monitor (+ connect UX)

## STATUS (2026-06-04)

**Done & verified:**
- ✅ Bulk **MPPC decompression** (RDP5/64K) — decoder proven vs FreeRDP vectors; ~3× less
  data. **ON by default** (`SCCM_RC_COMPRESS`, disable with `=0`). The `#79` fidelity bug is
  FIXED + live-verified: per-fragment decompress (shared history), reassemble at the order
  layer — see PERFORMANCE.md / PROTOCOL.md §14.1.
- ✅ **Clipboard text** (MS-RDPECLIP / `cliprdr`) — both directions, §1a below. Real
  `CliprdrChannel` (distinct SVC type — fixes the `StaticChannelSet` TypeId collision that
  meant only the last `PassiveChannel` ever joined).
- ✅ **Ctrl+Alt+Del** (SAS) — local hotkey **Ctrl+Alt+End** → Ctrl+Alt+Del to the remote.
- ✅ **Toolbar / status bar** — host · mode · connection · fps · bandwidth, buttons
  Ctrl+Alt+Del / Curtain / View-Only / Record / Fullscreen / Disconnect.
- ✅ **Live diagnostics** — fps + inbound bandwidth in the toolbar.
- ✅ **View-only** local lock (suppresses input) with mode indicator.
- ✅ **Audit log** — JSONL session log (`%LOCALAPPDATA%\sccm-rc\audit.jsonl`).
- ✅ **Session recording** — toolbar Record → PNG frame series (background thread).
- ✅ **Curtain / privacy** (`curtain` channel) — RE'd from RdpCoreSccm (`CRDPWLCCurtainVC`):
  event = WLC envelope `[1][12][type]`, enable type 5 / disable 6. Channel joins + server
  echoes the same envelope. Final physical-screen-blank to be confirmed by the operator.
- ✅ Connect UX (§4): PC-name arg + input box, graceful disconnect, auto-reconnect.

**Remaining:** multi-monitor (§3 — untestable on the single-mon target) and
multi-session/bulk-connect. (`#79` MPPC fidelity is fixed; file transfer, lock-input,
recent-hosts, WMI info, Wake-on-LAN all landed.)

The detailed plans below stay as the reference for the remaining items.

---


Concrete implementation plan for the next features, grounded in our architecture
(`sccm-rc-core` transport/RDP, `sccm-rc-orders` renderer, `sccm-rc-viewer` GUI) and
the relevant MS Open Specs. Each remote-control feature rides a standard RDP
**static/dynamic virtual channel** inside the SCCM seal — the same channels we
already declare passively (`cliprdr`, `rdpdr`, `drdynvc`, `dynres`, `dskcfg`…), so the
plumbing (declare → join → send/recv channel PDUs) already exists; we "only" need to
implement each channel's protocol and bridge it to the OS.

Shared prerequisite (small): a generic **SVC read/write hook**. Today `PassiveChannel`
ignores traffic and `ArbitrationChannel` is bespoke. Generalise to a trait that can
*receive* channel PDUs from `run_active_session` and *send* replies (IronRDP's
`SvcProcessor` already models this — we just need to route per-channel data in the
active loop instead of dropping it). This unblocks clipboard + rdpdr at once.

---

## 1. Copy / paste (clipboard) — MS-RDPECLIP over `cliprdr`

**Spec:** MS-RDPECLIP. **Channel:** `cliprdr` (already declared; flags 0xA0C0).
**Effort:** small–medium. Text first, then files.

Protocol flow (both directions, symmetric):
1. Server & client exchange **Clipboard Capabilities** + **Monitor Ready**.
2. When either side's clipboard changes it sends a **Format List** (advertises
   available formats: CF_UNICODETEXT, CF_TEXT, HTML, `FileGroupDescriptorW`…).
3. The other side replies **Format List Response**, and on paste sends a
   **Format Data Request(formatId)**; the owner replies **Format Data Response(data)**.

Implementation steps:
- Replace the `cliprdr` `PassiveChannel` with a `ClipboardChannel` (SvcProcessor):
  parse `CLIPRDR_HEADER` (msgType, msgFlags, dataLen) + the body per type.
- Bridge to the Windows clipboard. Use the `arboard` crate (simple, cross-platform
  text+image) for v1; drop to the Win32 clipboard API (`windows` crate) when we add
  file groups, which arboard doesn't cover.
- Local→remote: watch the local clipboard (or on Ctrl+C focus) → send Format List;
  answer the server's Format Data Request with the local data.
- Remote→local: on the server's Format List, request the formats we support and put
  the returned data on the local clipboard.
- Wire a small channel: `run_active_session` routes inbound `cliprdr` SVC data to the
  `ClipboardChannel` and flushes its outbound PDUs (same path the `sessarb` event uses).

Phasing: **(a)** Unicode text both ways → **(b)** bitmap/image → **(c)** file copy
(`FileGroupDescriptorW` + `FileContents` request/response = streamed file bytes over
the clipboard; this is also the simplest *file transfer*, see §2).

---

## 2. File transfer

Two viable mechanisms; recommend doing **(A)** first (reuses §1) then **(B)** if we
need drag-and-drop/drive-style access.

**(A) Clipboard file copy — MS-RDPECLIP `FileContents` (recommended first).**
Once §1 handles `FileGroupDescriptorW`, copy/paste of *files* works: the source sends
the descriptor (names/sizes), the destination issues `FILECONTENTS_REQUEST`
(range/size) and receives `FILECONTENTS_RESPONSE` chunks. This gives copy-paste file
transfer with no extra channel. **Effort:** medium (on top of §1).

**(B) Drive redirection — MS-RDPEFS over `rdpdr` (full filesystem access).**
**Channel:** `rdpdr` (already declared). The client *announces* a device (a mapped
local folder as a drive); the server then issues filesystem **I/O requests** (create/
read/write/query/close) that we service against the local folder. This is what gives a
mapped drive inside the session. **Effort:** large (device announce + a real IRP
handler + path/security mapping), but it's well-specified and the channel exists.
Recommend deferring until clipboard-file-copy is proven.

Note: check what the real CmRcViewer's "File Transfer" button uses — capture it with
the existing SSPI hook (`experiments/hook.c`) during a transfer to confirm whether SCCM
RC uses RDPECLIP file groups, RDPEFS, or a bespoke WLC channel, then match it.

---

## 3. Multiple monitors

Two layers: **(a) tell the server** we want multi-mon, **(b) render** the result.

**Spec:** MS-RDPBCGR `TS_UD_CS_MONITOR` / `TS_UD_CS_MONITOR_EX` (client GCC data) +
MS-RDPEDISP (`dynres`/Display Control) for live layout changes.
**Effort:** medium.

Implementation steps:
- **Advertise the monitor layout** in the MCS Connect-Initial GCC client data: add a
  `TS_UD_CS_MONITOR` block listing each monitor's rect (left/top/right/bottom) + the
  primary flag. The vendored connector builds the client data, so this is a patch
  there (next to where we declare channels / desktop size).
- The server then composes a **single combined desktop** spanning all monitors and
  streams it as one framebuffer (the orders/bitmaps already carry absolute coords).
  Our `CompositeFrame` + renderer handle an arbitrary desktop size unchanged — so the
  combined image "just works" once advertised; we size the canvas to the bounding box.
- **Rendering choice:** v1 = one big window showing the whole combined desktop (scaled
  to fit); v2 = split per-monitor into separate windows/tabs using each monitor's rect
  from the layout.
- **Live re-layout / resolution**: MS-RDPEDISP over the `dynres` channel sends
  `DISPLAYCONTROL_MONITOR_LAYOUT` to change monitors/resolution on the fly (e.g. when
  you resize the viewer). Defer to v2.

Phasing: **(a)** advertise a single explicit monitor (validates the GCC block) →
**(b)** advertise the target's real multi-mon layout, render combined → **(c)** Display
Control for dynamic resize.

---

## 4. Connect UX (done / near-term)

- **PC name as parameter** — done: `sccm-rc-viewer.exe <host>` (like CmRcViewer).
- **PC name input box** — done: launched without an argument, a native Windows input
  box prompts for the hostname.
- **Graceful disconnect on window close** — done: closing the window sends the MCS
  Disconnect-Provider-Ultimatum so the server releases the host immediately (avoids the
  lingering `HostInUse` we saw after abrupt kills).
- Near-term polish: a small in-window connection bar (host + reconnect/disconnect
  buttons), a recent-hosts list, and a status line (connected/HostInUse/reconnecting).

---

## Suggested order

1. **Clipboard text** (§1a) — highest value/effort ratio, channel already present.
2. **Clipboard image + file copy** (§1b, §2A) — extends §1, gives file transfer.
3. **Multi-monitor advertise + combined render** (§3a–b).
4. **rdpdr drive redirection** (§2B) and **Display Control** (§3c) — larger, later.

Before each, capture the real CmRcViewer doing the same action with the SSPI hook to
confirm SCCM's exact channel/format choices, then implement to match.
