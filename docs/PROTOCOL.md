# SCCM / ConfigMgr Remote Control — Protocol Specification (reverse-engineered)

This document specifies the wire protocol used by Microsoft's ConfigMgr (SCCM)
Remote Control tool (`CmRcViewer.exe` ↔ `CcmExec` hosting `RdpCoreSccm.dll`), as
reconstructed by reverse engineering for a clean-room pure-Rust re-implementation
(`sccm-rc`).

**Status of each layer**
- 🟩 **Public** — documented by Microsoft Open Specs; we only reference it.
- 🟨 **RE (solid)** — proprietary SCCM glue, reverse-engineered and verified live.
- 🟧 **RE (partial)** — understood enough to implement; some fields still opaque.

> Microsoft's CmRcViewer is built on the public RDP specs **plus** the proprietary
> SCCM layer below. Only the RDP layers have an official spec; everything
> SCCM-specific here is our reverse engineering (static via Ghidra on
> `RdpCoreSccm.dll`, dynamic via an SSPI hotpatch hook inside `CmRcViewer.exe`,
> and live black-box testing against a real target).

---

## 1. Layering overview

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop graphics & input  (RDP fast-path orders / input)    │ 🟩 MS-RDPEGDI/BCGR
├─────────────────────────────────────────────────────────────┤
│  RDP capability + session control (DemandActive/ConfirmActive,│ 🟩 MS-RDPBCGR
│  Deactivate, Share Data PDUs)  + WLC desktop-control TLVs      │ 🟨 (TLVs = RE)
├─────────────────────────────────────────────────────────────┤
│  Session arbitration  ("sessarb" static virtual channel)      │ 🟨 RE
│  WLC static virtual channels (curtain/dynres/dskcfg/…)        │ 🟨 RE
├─────────────────────────────────────────────────────────────┤
│  Standard RDP connection sequence (X.224, MCS, GCC, channels) │ 🟩 MS-RDPBCGR
├─────────────────────────────────────────────────────────────┤
│  GSS message sealing  (SSPI EncryptMessage/DecryptMessage)    │ 🟨 RE framing
├─────────────────────────────────────────────────────────────┤
│  SCCM control + auth handshake (greeting, SSPI Negotiate SSO, │ 🟨 RE
│  access grant, UTF-16 control messages)                       │
├─────────────────────────────────────────────────────────────┤
│  SCCM frame transport  ([u32 header][body]) over TCP          │ 🟨 RE
├─────────────────────────────────────────────────────────────┤
│  TCP — port 2701                                              │ 🟩
└─────────────────────────────────────────────────────────────┘
```

**The key insight of this RE:** once the SSPI seal is removed, the inner stream is
*standard RDP*. The "desktop layer" is **not** a custom DCE/RPC protocol (an earlier
hypothesis); the ncalrpc/NDR to `rdpuser.exe` seen in `RdpCoreSccm.dll` is the
**server's internal** plumbing and never appears on the wire.

---

## 2. Transport framing 🟨

TCP to **port 2701**. Every message on the wire is:

```
+---------------------+---------------------------+
| u32 header (LE)     | body (header.len bytes)   |
+---------------------+---------------------------+

header = (body_len & 0x00FF_FFFF) | (msg_type << 24)
   body_len : low 24 bits  (max ~16 MB)
   msg_type : high byte
```

`msg_type` values observed:
| value | name             | body                                            |
|-------|------------------|-------------------------------------------------|
| 0x00  | `MSG_TYPE_DATA`  | a single SSPI-sealed message (see §4)            |
| 0x80  | `MSG_TYPE_CONTROL`| UTF-16LE control string, **unsealed** (handshake)|

One frame = exactly one body of `body_len` bytes. A `DATA` frame body is exactly
one `EncryptMessage` output — **one seal per frame, one unseal per frame**, in order
(critical for the GSS sequence numbers, §4).

Handshake-token frames use a sub-format: `[u32 header type=0x00][u16 LE token_len][token]`.

---

## 3. Connection, authentication & access grant 🟨

1. **Greeting.** Server → client: a `CONTROL` frame containing UTF-16 `"START_HANDSHAKE"`.
2. **SSPI Negotiate (Kerberos SSO).** Client uses the Windows SSPI `Negotiate`
   package with the *current user's* credentials (single sign-on, no password).
   `InitializeSecurityContext` ↔ server, tokens exchanged as handshake-token frames
   until the context completes. Kerberos is selected (the target is domain-joined and
   addressed by hostname → SPN `HOST/<machine>`).
3. **Access grant.** After the context is established the server sends a sealed
   control message indicating the granted control level:
   - `"SUCCESS_FULL_CONTROL"` → full mouse/keyboard control
   - (view-only / denied variants exist; full control is the common case)
4. From here all `DATA` frames carry the sealed inner RDP stream.

**Data-phase control keywords** (sealed UTF-16, interleaved, to be skipped by the RDP
parser but still consumed for the GSS sequence): prefixes `SUCCESS_`, `ERROR_`,
`START_`, and `STOP_HANDSHAKE`.

---

## 4. GSS message sealing 🟨

Each `DATA` frame body is a GSS-wrapped (sealed) blob produced by the SSPI
`EncryptMessage` / consumed by `DecryptMessage` on the established Negotiate(Kerberos)
context.

- **Seal (send):** `EncryptMessage(ctx, qop=0, [SECBUFFER_TOKEN | SECBUFFER_DATA | SECBUFFER_PADDING], seq=0)`.
  Output framed as `[u32 header type=0x00][token][data][padding]` per the package's
  `cbSecurityTrailer`/`cbBlockSize`.
- **Unseal (recv):** `DecryptMessage(ctx, desc, seq=0, &qop)`; the `SECBUFFER_DATA`
  buffer holds the plaintext RDP bytes.
- **Sequence numbers:** `seq=0` is passed, so the SSP maintains internal send/receive
  counters. **Frames MUST be sealed/unsealed strictly in order, one per `DATA` frame,
  with none skipped or repeated.** Violating this yields `SEC_E_OUT_OF_SEQUENCE
  (0x80090310)` on `DecryptMessage`. *(Open issue: a desync observed ~20 s into busy
  sessions — see §12.)*

---

## 5. Inner RDP connection sequence 🟩 (MS-RDPBCGR)

Standard, byte-for-byte RDP inside the seal:

1. **X.224**: Connection Request (`CR`, `0x0E E0`) / Connection Confirm (`CC`, `0x0E D0`).
   RDP security = **None** (`SecurityProtocol(0x0)`) — the SCCM seal already provides
   confidentiality, so inner RDP encryption is disabled.
2. **MCS Connect-Initial / Connect-Response** carrying GCC client/server data blocks
   (core, security=none, network = the channel list in §6). The client data also
   carries a connection GUID (UTF-16) and the client machine name (UTF-16).
3. **MCS Erect-Domain-Request, Attach-User-Request/Confirm.**
4. **Channel Join Request/Confirm** for the I/O channel and every virtual channel.
5. **Client Info PDU** (time-zone, etc.), **License** ("Server did not initiate license
   exchange"), then the **capability exchange** (§8).

**Channel IDs** (server-assigned in this RE): I/O channel **1003 (0x3EB)**; virtual
channels **0x3EC … 0x3F3** in client-request order (§6); 0x3F4 also joined (global).

---

## 6. WLC static virtual channels 🟨

The client advertises 8 virtual channels in the GCC client network data, in this
exact order (mstscax/CmRcViewer order), with these `CHANNEL_DEF` option flags:

| order | name      | flags  | server MCS id | purpose                          |
|-------|-----------|--------|---------------|----------------------------------|
| 1     | `rdpdr`   | 0x8080 | 0x3EC         | device redirection (passive)     |
| 2     | `rdpsnd`  | 0x00C0 | 0x3ED         | audio (passive)                  |
| 3     | `cliprdr` | 0xA0C0 | 0x3EE         | clipboard (passive)              |
| 4     | `curtain` | 0x0080 | 0x3EF         | screen curtain (WLC)             |
| 5     | `sessarb` | 0x0080 | 0x3F0         | **session arbitration** (§7)     |
| 6     | `dynres`  | 0x0080 | 0x3F1         | dynamic resolution (WLC)         |
| 7     | `dskcfg`  | 0x0080 | 0x3F2         | desktop config (WLC)             |
| 8     | `drdynvc` | 0x80C0 | 0x3F3         | dynamic VC (passive)             |

A client that does **not** present this mstscax-like channel set + caps (§8) does not
receive desktop graphics — the server withholds its reactivation.

---

## 7. Session arbitration — `sessarb` 🟨

Before the server attaches a shadow of the console session and starts painting, the
session must be **arbitrated** over the `sessarb` static virtual channel.

**Event payload (16 bytes):**
```
+--------+--------+-----------+-----------+
| u32 tag| u32 len| u32 type  | u32 arg2  |
|  = 2   |  = 16  |  event    |   = 0     |
+--------+--------+-----------+-----------+
```

**Server event types** (the `type` field of a server→client event):
| type | name        | meaning                                             |
|------|-------------|-----------------------------------------------------|
| 1    | `HostInUse` | host is in use (a session/user present) → withheld  |
| 4    | `HostAllowed`| host free → server attaches shadow & reactivates    |

**Observed flow (host free):** the server **emits `HostAllowed (4)` itself** once the
host is free (in the captured real CmRcViewer session, *no* client-initiated sessarb
event was seen — the client receives the server's state). The pure-Rust client also
sends an initial event (`type=1`) which is harmless when the host is free.

After `HostAllowed`, the server runs a **DeactivateAll → DemandActive → ConfirmActive**
reactivation (§8) and then streams the desktop. When the server replies `HostInUse (1)`
(another RC session or user present, including a *lingering* session that has not yet
timed out), no shadow attaches and no graphics flow. *(How CmRcViewer forces a take-over
of a busy host is not yet captured — §12.)*

---

## 8. Capability exchange & reactivation 🟩 framing / 🟨 caps

Standard RDP Share Control PDUs on the I/O channel (1003). Note these are **plain RDP**,
not a custom envelope (an earlier mis-read):

- **Server Demand Active** — `pduType 0x0011`, source descriptor `"RDP\0"`.
- **Client Confirm Active** — `pduType 0x0013`, source descriptor **`"MSTSC\0"`**.
- **Server Deactivate All** — `pduType 0x0016` (13-byte body).

**Full session-start sequence:**
```
DemandActive(RDP) → ConfirmActive(MSTSC) → sessarb HostAllowed
   → DeactivateAll → DemandActive(RDP) → ConfirmActive(MSTSC) → graphics
```

**The Confirm Active capabilities matter.** The 2014-era SCCM RDP server only begins
desktop output when the client confirms **mstscax's exact capability set** — 21
capability sets:

```
GENERAL  BITMAP(prefBpp 16)  ORDER(88B)  BITMAPCACHE_REV2  COLORCACHE
WINDOWACTIVATION  CONTROL  POINTER  SHARE  INPUT(88B)  SOUND  FONT
GLYPHCACHE(52B)  BRUSH  OFFSCREEN  VIRTUALCHANNEL  DRAWNINEGRID
MULTIFRAGMENTUPDATE  SURFACE_COMMANDS  LARGE_POINTER  FRAME_ACK
```

(The pure-Rust client replays mstscax's captured Confirm Active bytes verbatim,
patching only session fields: `pduSource`, `shareId`, and the Bitmap-cap desktop size.)

**Reactivation may recur**; each reactivation re-runs the cap exchange (the connector
re-sends the `MSTSC` Confirm Active).

---

## 9. WLC desktop-control TLVs 🟧

Immediately after each Confirm Active, the client sends a handful of small **Share Data
PDUs** (`pduType 0x0017`) over the I/O channel that drive the WLC desktop features
(curtain / dynres / dskcfg). They use **custom `pduType2` values** (e.g. `0x1F`) not in
MS-RDPBCGR, with an inner addressing pair (`src=0x03F4`, `dst=0x03EA`):

```
client req:  … src=03F4 dst=03EA 01 <type 0108/010c/0100> <len> <value…>
server resp: … src=03EA dst=03EA 02 <type 0216/021a>       <len> <value…>
```
(dir byte `01` = client request, `02` = server response.) Sending these after the
shadow-attach reactivation is what makes the server start the desktop capture. The
exact field semantics of each TLV are only partially decoded.

---

## 10. Desktop graphics 🟩 (MS-RDPEGDI) + 🟨 cache model

The server paints via **RDP fast-path output** PDUs (update header byte e.g. `0xA0` =
`ORDERS` + `FRAGMENT_LAST` + `COMPRESSION_USED` flag, though in practice the observed
streams were **uncompressed**). The desktop is rendered as a **grid of 64×64 32bpp
tiles**:

- **Cache Bitmap Rev2** (secondary order, type `0x04` uncompressed / `0x05` compressed,
  MS-RDPEGDI 2.2.2.2.1.2.3): caches a tile. Header fields packed in the secondary
  `extraFlags`: `cacheId = flags & 0x07`, `bppId = (flags>>3)&0x07`, CBR2 flags
  `= flags>>7` (`HEIGHT_SAME_AS_WIDTH 0x01`, `PERSISTENT_KEY_PRESENT 0x02`,
  `NO_BITMAP_COMPRESSION_HDR 0x08`, `DO_NOT_CACHE 0x10`). Width/height via the
  1–2-byte var-length encoding; bitmapLength via the 1–4-byte var-length encoding.
  *(The SCCM server sends `bppId 0`; derive bpp from `len/(w*h)` → 32bpp.)*
- **Waiting list (`cacheIndex 0x7FFF`):** tiles are cached with the waiting-list index
  and promoted to real indices `0,1,2,…` in send order. Model: assign each waiting-list
  tile the next sequential index per `cacheId`; also remember the last as "transient".
- **MemBlt** (primary order `0x0D`): blits a cached tile to the screen. References a
  real index, or `0x7FFF` = the last transient tile.

Other primary orders (DstBlt/PatBlt/ScrBlt/LineTo/OpaqueRect) and secondary
caches (Cache Color Table) follow MS-RDPEGDI. **Text** uses the glyph orders, now
implemented: **Cache Glyph** (secondary, rev1) populates a glyph cache of 1-bpp
bitmaps, and **GlyphIndex (0x1B) / FastIndex (0x13) / FastGlyph (0x18)** blit those
glyphs in the foreground color along an advancing pen, including the glyph-fragment
cache (`0xFF` add / `0xFE` replay). Pending validation against a real glyph-emitting
session (the SCCM login screen paints text via bitmap tiles, so it exercises MemBlt,
not glyphs).

The server may also send some regions via **slow-path Bitmap Update / Surface
Commands** (a separate framebuffer in IronRDP); a complete client composites both.

---

## 11. Input 🟩

Client → server **fast-path input** PDUs (MS-RDPBCGR 2.2.8.1.2): keyboard (PS/2 set-1
scancodes, `0xE000` extended prefix) and mouse (move / button / wheel) events.

---

## 12. Open questions / not-yet-captured

- **Sealed-stream desync (`SEC_E_OUT_OF_SEQUENCE`)** ~20 s into busy sessions, around a
  second reactivation and/or while sending input. Cause not yet captured (suspects:
  `drive_reactivation` byte handling on the 2nd reactivation, or a server frame whose
  body our framing mis-sizes under load). Diagnostics in place to capture it.
- **HostInUse take-over.** How CmRcViewer proceeds to a desktop when the server reports
  `HostInUse (1)` (lingering/concurrent session) — the take-over arbitration event(s)
  are not yet captured (CmRcViewer sits on a "host in use" prompt when launched headless).
- **WLC TLV semantics** (§9) — only partially decoded.
- **Graceful disconnect / session release** — we currently drop the socket; a proper
  release event would let the server free the host immediately (avoiding lingering-
  session `HostInUse`).

---

## 13. References

Public Microsoft Open Specifications the inner protocol conforms to:
- **MS-RDPBCGR** — Remote Desktop Protocol: Basic Connectivity and Graphics Remoting.
- **MS-RDPEGDI** — Graphics Device Interface (GDI) Acceleration Extensions (orders).
- **MS-RDPELE** — Licensing (no-op here).
- **MS-RDPEDISP** — Display Control (dynamic resolution).
- RFC 4121 / RFC 2743 — Kerberos GSS-API per-message tokens (the seal in §4).

Reverse-engineering artifacts in this repo:
- `experiments/captures/desktop-wlc-2026-06-03.txt` + `DECODE.md` — annotated plaintext
  capture (SSPI hotpatch hook inside CmRcViewer).
- `experiments/hook.c`, `experiments/inject.c` — the capture tooling.
- `crates/sccm-rc-orders/` — the MS-RDPEGDI order renderer (CBR2 + MemBlt + caches).
- `crates/sccm-rc-core/src/rdp.rs` — connection, arbitration, WLC, reactivation, composite.
- `vendor/ironrdp-connector/` — SCCM patches (mstscax Confirm Active, order caps).
