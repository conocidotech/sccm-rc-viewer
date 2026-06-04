# Desktop/WLC wire decode — capture desktop-wlc-2026-06-03.txt

Captured by hotpatching `EncryptMessage`/`DecryptMessage` (sspicli) inside the real
`CmRcViewer.exe` (32-bit hotpatch detour, `experiments/hook.c`) against TARGET-HOST
(no user logged in → login screen). `C` = client→server (plaintext before seal),
`S` = server→client (plaintext after unseal). 27 C frames, 193 S frames.

## BIG FINDING — the desktop layer is NOT on-wire DCE/RPC

The whole inner protocol is a **standard RDP byte stream** that SCCM just SSPI-seals.
The earlier RE conclusion "desktop = ncalrpc to rdpuser.exe (Bind/Request/NDR)" is the
server's *internal* plumbing; it is **not** on the TCP wire. On the wire we see:

1. X.224 CR/CC, MCS Connect-Initial/Response, Erect-Domain, Attach-User, Channel-Joins.
2. A WLC control protocol multiplexed over the **I/O channel 03eb**, using an inner
   envelope and an `"MSTSC"`/`"RDP"` capability exchange + small TLV control messages.
3. Plain **RDP fast-path server output** (compressed ORDERS + bitmap) = the pixels.

=> No NDR/DCE-RPC client required. We need to advertise the WLC channels, run the
   `MSTSC`/`RDP` capability exchange + TLVs over 03eb, and the server starts fast-path
   graphics that the existing `sccm-rc-orders` renderer already consumes.

## Channel map (from client Connect-Initial C#2 + server Connect-Response)

Client requests 8 virtual channels in this order (GCC client network data):
`rdpdr(8080) rdpsnd(c0) cliprdr(a0c0) curtain(80) sessarb(80) dynres(80) dskcfg(80) drdynvc(80c0)`
plus a connection GUID (UTF-16 "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee...") and client name
(UTF-16 "CLIENT-HOST").

Server allocates (server network data `030c1800 eb03 0800 ec03…f303`):
- I/O channel **03eb** (1003)
- rdpdr **03ec**, rdpsnd **03ed**, cliprdr **03ee**, curtain **03ef**,
  sessarb **03f0**, dynres **03f1**, dskcfg **03f2**, drdynvc **03f3**
- 03f4 (1012) also joined (global/broadcast).

## WLC inner envelope (over MCS Send-Data to channel 03eb)

After the MCS SDrq/SDin header (`…03eb 70 <PER-len>`), the WLC payload is:

```
[u16 innerLen LE] [u16 type] [u16 src] [u16 dst] [u16 ?] [u16 ?] [u16 ?] [u16 blobLen] [blob]
```

Observed:
- Client caps  (C#16/C#21, 505B): type `0013`, src `03f4`, dst `03ea`, … blobLen `01d4`,
  blob = `"MSTSC\0"` + capability structure.
- Server caps  (S 395/515B):      type `0011`, src `03ea`, dst `03ea`, … blob = `"RDP\0"`
  + capability sets (bitmap caps `fe00xx…`, order caps `aa0001…`, glyph/cache cells).
- Server "ready"(S 34B):          `…03eb 70 1480 000000 ff03 1000 07000000 02000000 04000000`

The `"MSTSC"`/`"RDP"` blobs carry the familiar RDP capability cells:
glyph/bitmap cache cells `fe0004 00 fe000400 fe000800 fe000800 fe001000 fe002000
fe004000 fe008000 fe000001` (mstsc's classic cache sizes), color depth, desktop size, etc.

## TLV control messages (curtain / dynres / dskcfg) over 03eb, inner dst 03ea

Small fixed messages, `[dir][type][len…]`, dir `01`=client, `02`=server:
```
C#17  …f403 ea03 0100 00 01 0800 1f000000 0100 ea03      (req type 0108)
C#18  …f403 ea03 0100 00 01 0c00 14000000 04000000 00…    (req type 010c, val 4)
C#19  …                01 0c00 14000000 01000000 00…       (req type 010c, val 1)
C#20  …                01 00  27000000 …0300 3200           (req type 0100)
S     …ea03 ea03 0100 00 02 1600 1f000000 01000000         (resp 0216)
S     …                02 1a00 14000000 04000000 00…        (resp 021a, val 4)
S     …                02 1a00 14000000 02 00 f403 ea03 00… (resp 021a)
S     …                02 1a00 28000000 …0300 0400          (resp 021a)
```
Plus named-channel PDUs on curtain 03ef / sessarb 03f0 / dynres 03f1:
```
S …03f0 f018 10000000 03000000 02000000 10000000 0400…
S …03ef f014 0c000000 03000000 01000000 0c000000 0100
S …03f1 f014 0c000000 03000000 03000000 0c000000 0100
```

## Fast-path graphics (S frames 60+)

`00 80xx …` = fast-path server output, 2-byte PER length. updateHeader `a0` =
updateCode 0 (ORDERS) + FRAGMENT_LAST + COMPRESSION_USED. Big frames 6–16 KB =
bitmap/surface data. These are exactly what `sccm-rc-orders` decodes.

## Client fast-path input (C#26/C#27)

`6c 17 …` = fast-path input (numEvents/flags + events) — sync + scancode. Not needed
to *get* pixels; needed later for remote control input.

## What our Rust client was missing

It did sessarb arbitration + reactivation but no graphics. The missing trigger is the
**`MSTSC` capability envelope over the I/O channel 03eb** (+ the TLV control exchange).
Sending that is what makes the server begin fast-path desktop output.

## Next (pure Rust)
1. Advertise all 8 WLC channels (names+flags as above) in Connect-Initial.
2. After reactivation, send the `MSTSC` envelope (C#16 structure) + TLV control msgs
   over 03eb; handle the `RDP` server reply + `02xx` TLV responses.
3. Feed the resulting fast-path ORDERS/bitmap into the existing order renderer.

---
## CORRECTION (2026-06-03, later) — it's all STANDARD RDP, not a custom envelope

Decoding the ordering proved the "WLC inner envelope" reading above was WRONG. The
`MSTSC`/`RDP` messages and the TLVs are plain RDP share-control/share-data PDUs on the
I/O channel (03eb); the `[len][type][src][dst]` I described is just the Share Control
Header (totalLength, pduType, pduSource) + the ConfirmActive/DemandActive body:

- `"MSTSC"` (C#16/C#21) = **Client Confirm Active PDU** (pduType 0x0013, srcDesc "MSTSC\0").
- `"RDP"`   (S 35/49)   = **Server Demand Active PDU**  (pduType 0x0011, srcDesc "RDP\0").
- TLVs (C#17-20) = **Share Data PDUs** (pduType 0x0017) with custom pduType2 (0x1f, ...)
  — WLC desktop control (resolution/curtain), sent after each ConfirmActive.
- A real **DeactivateAll** (pduType 0x0016, 13-byte body) IS sent by the server.

True flow: DemandActive(35)/ConfirmActive(36) -> sessarb **HostAllowed**(45) ->
**DeactivateAll**(48) -> DemandActive(49)/ConfirmActive(50) -> graphics flood(61+).
=> Our pure-Rust client already reproduces this through the 2nd ConfirmActive
(arbitration + reactivation work). The ONLY remaining blocker: our IronRDP
ConfirmActive advertises different CAPABILITIES than mstscax, so the server won't paint.

### mstscax ConfirmActive = 21 capability sets (the target to match)
GENERAL(24) BITMAP(28,prefBpp16) ORDER(88) BITMAPCACHE_REV2(40) COLORCACHE(8)
WINDOWACTIVATION(12) CONTROL(12) POINTER(10) SHARE(8) INPUT(88) SOUND(8) FONT(8)
GLYPHCACHE(52) BRUSH(8) OFFSCREEN(12) VIRTUALCHANNEL(12) DRAWNINEGRID(12)
MULTIFRAGMENTUPDATE(8) SURFACE_COMMANDS(12) LARGE_POINTER(6) FRAME_ACK(8)

NEXT: make the (vendored) connector emit exactly these caps in the ConfirmActive
(simplest: replace IronRDP's ConfirmActive cap collection with mstscax's captured
bytes — shareId 0x103ea is deterministic and already matches). Then the TLV control
PDUs (C#17-20) + the existing order renderer should yield pixels. The SCCM_RC_WLC
MSTSC replay is a *duplicate* ConfirmActive and should be dropped; keep only the TLVs.
