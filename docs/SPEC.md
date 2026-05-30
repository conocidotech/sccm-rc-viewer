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

### Per-message wrap/unwrap 🟡

Not directly visible in the decomp because the calls go via the
function-table at offset 0x68 (EncryptMessage) and 0x6C (DecryptMessage)
on the `SecurityFunctionTableW`. The SecurityFilter does maintain the
`CtxtHandle` post-handshake, which is only useful if EncryptMessage /
DecryptMessage are called.

Standard pattern for Negotiate seal:

```c
SecBuffer[3] = {
    [0] = { BufferType = SECBUFFER_TOKEN, cbBuffer = max_token_size,
            pvBuffer = scratch_buffer_at_offset_0 },
    [1] = { BufferType = SECBUFFER_DATA,  cbBuffer = payload_size,
            pvBuffer = payload_buffer },
    [2] = { BufferType = SECBUFFER_PADDING, cbBuffer = block_size,
            pvBuffer = scratch_after_payload }
}
EncryptMessage(ctxt, 0, &desc, sequence_number)
// → on wire: [TOKEN bytes][DATA bytes][PADDING bytes] concatenated
```

The buffer abstraction `IRDPENCNetStreamBuffer` (with `get_PayloadOffset`/
`get_PayloadSize`/`get_Storage`) is shaped exactly for this: the buffer
reserves header space at offset 0 (for TOKEN) and trailer space at the
end (for PADDING), with the payload in the middle. After `EncryptMessage`,
WSASend is called with `len = payload_size, buf = base + payload_offset` —
but the surrounding TOKEN and PADDING bytes are also part of the stream
(they live in the same buffer; WSASend's offset is only the START — and
the **actual sent length includes the trailer** based on what
SecurityFilter writes back into PayloadSize). **This still needs pcap
confirmation**: whether one WSASend is one SSPI message, or whether
multiple SSPI messages get batched.

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

## 6. Action required from the user before Phase 2 (impl) can finish

A **pcap of a live `CmRcViewer.exe` → test-target session** with:

- Wireshark on the viewer-side host
- A test target where you have admin
- Capture filter: `tcp port 2701`
- Save as `captures/<hostname>-<date>.pcapng` in this workspace
- Annotate timing in a sibling `.notes.md`:
  - T+0: "Connect" clicked
  - T+x: consent prompt appeared on target
  - T+y: operator clicked Allow
  - T+z: screen first rendered

With one good pcap we can:
1. Confirm whether per-message EncryptMessage is used (compare ratio of
   bytes-on-wire vs RDP-frame sizes after decrypt — if 1:1 plus
   ~16 bytes overhead, no per-message wrap; if larger overhead, wrap is
   active).
2. Determine exact byte-layout per message (token + data + padding order).
3. Confirm that no framing exists above SecurityFilter on the viewer side.

Without the pcap we can still write the handshake (it's clear from decomp)
but the per-message path will be a guess until we see real bytes.
