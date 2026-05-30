# SCCM Remote Control wire protocol — work-in-progress spec

Reverse-engineered from `RdpCoreSccm.dll` 5.00.7958.1401 (SCCM 2012,
build 2014-09-04, x86) and the viewer `CmRcViewer.exe` of the same
version. Source artifacts live in `C:\Users\you\tools\rc-re\out\`.

Ghidra recovered the **original Microsoft source-file paths** from debug
strings — that lets us name the architectural layers:

| Module | Source path (Microsoft internal) | Role |
|---|---|---|
| `cmrcviewer\viewer.cpp` | top-level viewer EXE | UI + connection driver |
| `customtransport\sccmstream.cpp` | "SccmStream" | TCP/2701 socket I/O with buffer abstraction |
| `customtransport\securityfilter.cpp` | "SecurityFilter" | SSPI handshake + per-message wrap |
| `customtransport\commonsecurity.cpp` | "CommonSecurity" | SSPI function-table loader |

**Status legend per section:**
- ✅ confirmed from decomp + strings
- 🟡 inferred, plausible — needs pcap confirmation
- ❓ unknown — TBD via pcap or live trace

---

## 0. Wire framing — DISCOVERED 2026-05-30 ✅

Confirmed empirically by connecting to `localhost:2701` and observing
the server's greeting + reply to our first SSPI token.

Every message on the wire (both directions, both handshake and data
phase) is framed as:

```
+---------+---------+---------+---------+
| len[0]  | len[1]  | len[2]  | type    |   header (u32, little-endian)
+---------+---------+---------+---------+
| body... (len bytes — header excluded) |
+---------------------------------------+
```

- **`type` (high byte)**: message type / flag
  - `0x80` = control message (body is a UTF-16 string)
  - `0x00` = SSPI handshake or data payload (body is raw binary)
  - Other values TBD via more probing
- **`len` (low 24 bits)**: number of body bytes that follow

For control messages (type `0x80`):

```
+---------+---------+
| u16 LE: byte-length of UTF-16 string (excluding null)
+---------+---------+
| UTF-16LE string                                       |
+---------+---------+
| 0x00 0x00 (null terminator)                           |
+---------+---------+
```

Known control message strings:

- `START_HANDSHAKE` — server sends this immediately on connect, before
  the viewer says anything.
- `ERROR_LOGON_DENIED` — server's reply when our SSPI token parses
  but the authenticated identity is not in the Permitted Viewers
  group on the target.

For SSPI / data messages (type `0x00`), the body is **NOT** the raw
payload — it has an inner structure.

### ⭐ Inner framing for SSPI handshake messages (type 0x00) — CONFIRMED via pcap 2026-05-30

The body of a handshake message is:

```
+---------+---------+
| u16 LE: token length (excluding these 2 bytes)        |
+---------+---------+
| SSPI/SPNEGO token (token_length bytes)                |
+---------------------------------------------------------+
```

So `outer_body_len = 2 + token_length`.

**This was the bug in our first pure-Rust attempt.** We sent the raw
SPNEGO token as the body; the server replied `ERROR_LOGON_DENIED`. Once
we prepended the `u16 LE` token-length, the server accepted our AP-REQ
and replied with a SPNEGO `NegTokenResp` (AP-REP) — byte-identical to
what the real CmRcViewer receives:

```
→ frame [u32 type=0x00 len=3437] [u16 len=3435] [3435-byte SPNEGO NegTokenInit/AP-REQ]
← frame [u32 type=0x00 len=187]  [u16 len=185]  [185-byte SPNEGO NegTokenResp/AP-REP]
```

The root cause was a **2-byte inner length prefix** — trivially fixable.
Pure-Rust Pad B1 is viable after all; we do not strictly need to wrap
Microsoft's DLL.

### Data-phase messages (type 0x00, post-handshake) — CONFIRMED working 2026-05-30

Once authenticated, the body uses the `SecurityFilter::EncryptData`
layout, **confirmed by sealing/unsealing live against TARGET-HOST**:

```
SecFilter body = [u16 LE data_len][encrypted data][u16 LE token_len][GSS wrap token]
```

- `data` = application payload, encrypted in place (AES-CTS, length-preserving)
- `token` = GSS wrap token from `EncryptMessage`'s SECBUFFER_TOKEN
  (`05 04 06 ff …` from client = initiator, `05 04 07 ff …` from server
  = acceptor), ~60 bytes, RFC 4121, with an internal incrementing
  sequence number.

Our pure-Rust `SspiSession::seal()` / `unseal()` (via `EncryptMessage` /
`DecryptMessage` with SECBUFFER_DATA + SECBUFFER_TOKEN) interoperate
with the real server:

```
→ handshake (AP-REQ / AP-REP)  → context established
→ our seal() produces a token starting 05 04 06 ff  (== real viewer)
→ send a sealed frame
← server replies with a sealed frame
← our unseal() decrypts it to UTF-16LE "SUCCESS_FULL_CONTROL"
```

`SUCCESS_FULL_CONTROL` is the server granting the remote-control session
(full-control mode). Data-phase control strings are **raw UTF-16LE**
(no length prefix, unlike the unencrypted greeting).

This proves the entire transport + auth + crypto stack works in pure
Rust end-to-end. What remains is the application layer: the RDP stream
(MS-RDPBCGR via IronRDP) carried inside these sealed frames, plus the
SCCM data-phase control messages (SUCCESS_*, screen negotiation, etc.).

### Worked examples (observed against real targets)

**Localhost (NTLM fallback — no Kerberos ticket exists for `TERMSRV/localhost`):**

```
→ 84 00 00 00 + 132 bytes NTLMSSP Type-1 token
← 28 00 00 80 + UTF-16LE "ERROR_LOGON_DENIED" (exampleuser not in Permitted Viewers)
```

**TARGET-HOST via corporate VPN (Kerberos works — domain target):**

```
→ 67 0d 00 00 + 3431 bytes SPNEGO + Kerberos AP-REQ
   embedded: realm "CORP.EXAMPLE.NET", SPN "TERMSRV/TARGET-HOST",
             encrypted user PAC with group SIDs (3.3 KB)
← 28 00 00 80 + UTF-16LE "ERROR_LOGON_DENIED" (identical format)
```

Both confirm the framing handles any size message, both directions.
Server rejects on authorization-check (user not in Permitted Viewers
on that target), not on protocol-parsing.

---

## 1. Transport overview

| Field | Value | Source |
|---|---|---|
| Transport | TCP, async via WSARecv/WSASend + IOCP | ✅ `WSASocketW`, `WSARecv`, `WSASend` callsites in viewer |
| Port | **2701/TCP** | ✅ literal in error string |
| Connect | `GetAddrInfoW(target, "2701", ...)` → `WSASocketW` + `connect()` per address | ✅ `viewer.cpp:0x9b0` log line "WSASocket error" |
| Log msg | "Successfully connected to address [%s:%d]" / "Failed to connect to address [%s:%d]" | ✅ `viewer.cpp:0x9b7` / `0x9bc` |
| Listener on target | `CcmExec.exe` loads `RdpCoreSccm.dll` as in-process server | ✅ DLL has both client + server RPC paths compiled in |

The bytes on the wire layer like this:

```
   TCP/2701 stream (CmRcViewer.exe owns this socket directly)
     └── SecurityFilter (SSPI Negotiate)
           ├── handshake phase  → bytes are raw SSPI tokens (no extra header)  🟡
           └── data phase       → EncryptMessage/DecryptMessage via fn-table   🟡
     │
     └── above SecurityFilter: standard MS-RDPBCGR frames                       ✅
                  (= what `IRDPENCNetStream` produces / consumes)
```

> **Significant correction from earlier version of this spec**: the
> viewer makes **no RPC calls**. All `RpcStringBindingComposeW` etc.
> in `RdpCoreSccm.dll` use `ncalrpc` (Local RPC) and are **target-side
> only** — they're used by `CcmExec` to talk to its `SccmRDPUser.exe`
> consent-prompt child process on the target. From the viewer's
> perspective the entire arbitration flow is just signalling on the
> TCP/2701 stream.

---

## 2. SecurityFilter layer ✅

Confirmed from `securityfilter.cpp` decompilation:

### Setup (one-time, per session)

1. `InitSecurityInterfaceW()` returns a `SecurityFunctionTableW*` (29 dwords / 116 bytes). Viewer copies all 29 function pointers into its `SecurityFilter` instance (`commonsecurity.cpp:0x68`).
2. Auth package: **Negotiate** (NTLM/Kerberos). The handshake function uses `SEC_I_CONTINUE_NEEDED` (0x90313) and `SEC_I_COMPLETE_AND_CONTINUE` (0x90314) return values — those are SSPI standard.
3. SPN format: `TERMSRV/<target-hostname>` (in `CmRcViewer.exe` strings).

### Handshake loop (`HandshakeWorker`)

```c
// Input from peer = (param_1, param_2)
// Allocate two SecBuffers (24 bytes), set first to type SECBUFFER_TOKEN (2):
input_buf = { cbBuffer = param_2, BufferType = SECBUFFER_TOKEN, pvBuffer = copy(param_1) }
input_desc = { ulVersion = SECBUFFER_VERSION, cBuffers = 2, pBuffers = &input_buf }

// Allocate one output SecBuffer:
output_buf = { cbBuffer = 0, BufferType = SECBUFFER_TOKEN, pvBuffer = NULL }
output_desc = { ulVersion = SECBUFFER_VERSION, cBuffers = 1, pBuffers = &output_buf }

// Call InitializeSecurityContextW (via fn-table) with these:
status = ISC(...);

if (status == SEC_I_COMPLETE_AND_CONTINUE) {
    CompleteAuthToken(ctxt, &output_desc);
}

if (status == SEC_I_CONTINUE_NEEDED || (status==COMPLETE_AND_CONTINUE && CompleteAuthToken ok)) {
    // copy output_buf.pvBuffer (output_buf.cbBuffer bytes) → outgoing bytes
    *out_bytes = output_buf.cbBuffer;
    *out_data  = AllocateBuffer(*out_bytes);
    memcpy(*out_data, output_buf.pvBuffer, *out_bytes);
    FreeContextBuffer(output_buf.pvBuffer);
} else if (status == 0 /* success */) {
    // handshake complete
    SecurityFilter::handshake_done = 1;
}
```

The viewer offset constants:
- `this+0x7c` = `CtxtHandle` (8 bytes)
- `this+0x78` = `CredHandle` (8 bytes, inferred — usual layout)
- `this+0x8c` = pointer to a buffer-allocator interface (IRDPENCNetStreamBuffer factory)
- `this+0xb4` = max-token-size (probably from QuerySecurityPackageInfo)
- `this+0xb8` = handshake-in-progress flag

Error string seen on the wire-encrypted path: **"Remote Control Viewer user is member of too many security groups, use a different account which has less security group memberships."** This is the classic Negotiate-token-too-large failure — Kerberos PAC can balloon past the negotiated `cbMaxToken`.

### Per-message wrap/unwrap ✅ (confirmed via fn-table indirection)

`SecurityFilter` stores the SSPI function table inline starting at
`this+0x04`. Each SSPI method lives at `this + 0x04 + <fn-table-offset>`.
Two key methods we confirmed:

| Offset in `this` | SSPI function |
|---|---|
| `this+0x20` | `InitializeSecurityContextW` |
| `this+0x28` | `CompleteAuthToken` |
| `this+0x6C` | `EncryptMessage` |
| `this+0x70` | `DecryptMessage` |

Other instance fields:

| Offset | Field | Source of value |
|---|---|---|
| `this+0x7c..0x84` | `CtxtHandle` (8 bytes) | `InitializeSecurityContextW` output |
| `this+0x94` | state: 0=uninit, 1=initialized, 2=handshaking, 3=authenticated | `*(this+0x94) == 3` check guards encrypt/decrypt |
| `this+0x98` | `cbMaximumMessage` | `QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES)` |
| `this+0x9c` | `cbHeader` | same query |
| `this+0xa0` | `cbTrailer` | same query |
| `this+0xa4` | `cBuffers` / extra | same query |
| `this+0xa8` | `cbBlockSize` | same query |

Error strings that confirm: `"GetStreamSizes failed"`, `"QueryContextAttributes failed"`, `"m_pSecFilter->GetStreamSizes failed"`.

### Encrypt path (`SecurityFilter::EncryptData`, decompiled at 0x44c28c)

```c
// Sanity checks
if (this->ctxt invalid)                                  return 0xd0000008;
if (*plain_size <= cbHeader + cbTrailer + extra)         return "buffer too small";
if (*plain_size > cbMaximumMessage)                      return "data too large";

// Set up 2 SecBuffers (NOT 3 — no SECBUFFER_PADDING used):
SecBuffer[0] = {
    cbBuffer   = read_u16_le(plain + cbHeader),  // data length from header field
    BufferType = SECBUFFER_DATA (1),
    pvBuffer   = plain + cbHeader + cbTrailer,   // skip header+trailer reservation
};
SecBuffer[1] = {
    cbBuffer   = cbBlockSize,
    BufferType = SECBUFFER_TOKEN (2),
    pvBuffer   = plain + cbHeader + cbTrailer + data_len + extra,
};
SecBufferDesc = { ulVersion = 0, cBuffers = 2, pBuffers = SecBuffer };

EncryptMessage(&this->ctxt, fQOP, &desc, 0);   // MessageSeqNo = 0 — relies on SSPI internal counter

// After encryption, write data-length trailer + return total size
*(uint16_t*)(plain + cbHeader + cbTrailer + data_len) = data_size_field;
*out_total = cbHeader + cbTrailer + data_len + extra + cbBlockSize;
```

### Decrypt path (`SecurityFilter::DecryptData`, decompiled at 0x44bc83)

```c
if (this->ctxt invalid)                       return 0xd0000008;

uint16_t data_len = read_u16_le(buf + cbHeader);
SecBuffer[0] = {
    cbBuffer   = data_len,
    BufferType = SECBUFFER_DATA (1),
    pvBuffer   = buf + cbHeader + cbTrailer,
};
SecBuffer[1] = {
    cbBuffer   = read_u16_le(buf + token_offset),
    BufferType = SECBUFFER_TOKEN (2),
    pvBuffer   = buf + extra + token_offset,
};
SecBufferDesc = { ulVersion = 0, cBuffers = 2, pBuffers = SecBuffer };

status = DecryptMessage(&this->ctxt, &desc, 0, NULL);
if (status == SEC_E_INCOMPLETE_MESSAGE (0x80090318)) {
    return "need more bytes";   // standard streaming SSPI semantic
}

// On success, *out_data_size = SecBuffer[0].cbBuffer (decrypted length)
//             *out_total_consumed = SecBuffer[1] end offset
```

### Wire layout per wrapped message ✅

```text
+-------------------------------------------+
| HEADER  (cbHeader bytes)                  |  contains 2-byte data-length field
+-------------------------------------------+
| TRAILER reserve (cbTrailer bytes)         |
+-------------------------------------------+
| DATA payload   (variable, ≤cbMaxMessage)  |  encrypted in-place by EncryptMessage
+-------------------------------------------+
| EXTRA          (cBuffers bytes)           |  separator before TOKEN
+-------------------------------------------+
| TOKEN/MIC      (cbBlockSize bytes)        |  signature
+-------------------------------------------+
```

For our Rust rebuild we **don't need to compute these sizes ourselves** —
`sspi-rs::query_context_stream_sizes` returns the same struct, and we
just lay out our buffers accordingly.

---

## 3. Arbitration / consent flow ✅ (target-side only)

`RdpCoreSccm.dll` does set up an `ncalrpc` server (`encrpcpipe[<hex>]`,
random 32-bit ID) using `RpcServerUseProtseqEpW(L"ncalrpc", 5, ep, NULL)`
+ `RpcServerRegisterIfEx` + `RpcServerListen(1, 1234, 1)`.

But this entire RPC server runs **inside `CcmExec.exe` on the target**,
not on the viewer. It exists for `CcmExec` ↔ `SccmRDPUser.exe`
communication (the consent-prompt child process). The viewer never
opens this LRPC pipe.

Two RPC interfaces detected, both local-only:
- Interface 1 (`FUN_1008eb14`): client side connects to `encrpcpipe[%08x]` 
  with auth `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (6), package
  `RPC_C_AUTHN_GSS_NEGOTIATE` (10), SPN `"NT AUTHORITY\\SYSTEM"`. 4
  client stubs (`FUN_1008f6eb`/`f71d`/`f74f`/`f781`) → 4 RPC methods.
- Interface 2 (`FUN_1011f275`): also `ncalrpc`, no endpoint name, with
  mutual-auth QoS (`Capabilities = 1 = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH`).
  1 client stub (`FUN_1011f239`).

**Implication for our rebuild**: we do NOT need to implement any
RPC. The arbitration outcome is observable as data on the TCP/2701
stream. The session-arbitration state names
(`OnSessionArbitrationHost{Idle,InUse,Allowed,Denied}`) live in the
viewer EXE as event sinks, not as RPC method names.

---

## 4. RDP layer ✅

This is **standard MS-RDPBCGR** as defined by Microsoft public docs.
The viewer feeds the bytes from SecurityFilter::Decrypt into the standard
RDP ActiveX via the `IRDPENCNetStream` external transport interface.

Hardcoded viewer settings (no UI to change):

| Setting | Value | Source |
|---|---|---|
| `put_RedirectDrives` | `VARIANT_FALSE` | hardcoded off in viewer |
| `put_RedirectPorts` | `VARIANT_FALSE` | hardcoded off |
| `put_RedirectPrinters` | `VARIANT_FALSE` | hardcoded off |
| `put_RedirectSmartCards` | `VARIANT_FALSE` | hardcoded off |
| `put_HotKeyCtrlAltDel` | `VK_END` | `Ctrl+Alt+End` sends Ctrl+Alt+Del to target |
| `put_GatewayProfileUsageMethod` | `TSC_PROXY_PROFILE_MODE_EXPLICIT` | no TS gateway |

### What we don't know ❓

- **Does the Microsoft "External Transport Interface" pass any framing
  bytes to RDP-the-ActiveX, or just raw decrypted RDP bytes**?
  If raw: IronRDP can ingest straight from SecurityFilter::Decrypt.
  If there's framing (length prefix etc.): one more layer to strip.

---

## 5. Implementation roadmap (mirrors `REBUILD-BRIEF.md` § 7)

| Phase | Crate | Status | Blocked-on |
|---|---|---|---|
| 0 | `sccm-rc-diag` TCP/2701 + SCM + LSA + Local-Group checks | ✅ done | — |
| 1a | Static RE of viewer transport layer | ✅ done (this doc) | — |
| 1b | Confirm spec via pcap → fill the 🟡/❓ above | ⏳ | one pcap |
| 2 | `sccm-rc-protocol::transport` TCP socket | ⏳ stubs | — |
| 2 | `sccm-rc-protocol::handshake` SSPI loop | ⏳ stubs | (small; pattern is clear) |
| 2 | `sccm-rc-protocol::secfilter` per-message wrap | ⏳ stubs | pcap |
| 2 | ~~`sccm-rc-protocol::arbitration`~~ | ❌ delete | not needed — see § 3 |
| 3 | `sccm-rc-core::Session` glue to IronRDP | ⏳ stubs | phase 2 |
| 5 | `sccm-rc-viewer` UI | ⏳ empty | phase 3 |

---

## 6. Status — what's known, what still needs a pcap

After the deeper Ghidra-pass on 2026-05-30 we have enough to fully
implement the viewer side WITHOUT a pcap. What a pcap would still add:

| Question | Confidence | Pcap needed? |
|---|---|---|
| Is per-message wrap used? | ✅ confirmed YES via `(*(this+0x70))` and `(*(this+0x6C))` callsites | no |
| Wire layout per wrapped message? | ✅ confirmed: HEADER+TRAILER-reserve+DATA+EXTRA+TOKEN | no |
| Exact byte values of cbHeader/cbTrailer/etc? | runtime values from `QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES)` — `sspi-rs` handles this for us | no |
| Framing above SecurityFilter (length-prefix etc.)? | ✅ confirmed NO — the buffer abstraction IS the framing, no separate length-prefix layer | no |
| Negotiate package final winner per connection (NTLM vs Kerberos)? | ❓ environment-dependent | yes, **but** only for diagnostics — the protocol works either way |
| Edge cases (invalid SPN, RC disabled, target offline) | ❓ | yes, for error UX polish |
| End-to-end validation of our implementation | ❓ | yes, after we have something to validate against |

A pcap is now a **validation** step, not a discovery step.

If/when capturing one:
- Wireshark on the viewer-side host, capture filter `tcp port 2701`
- Save as `captures/<hostname>-<date>.pcapng`
- Optional `.notes.md` sibling with timing annotations (Connect / consent
  prompt / Allow click / first frame)
