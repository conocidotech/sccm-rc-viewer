# Local patches to ironrdp-connector 0.8.0 for SCCM Remote Control

Vendored copy with 2 minimal changes to allow standard RDP security
(encryption level NONE), in `src/connection.rs`:

1. Initiation send: removed the hard error on standard RDP security
   (replaced with a warning).
2. Initiation wait-confirm: standard security is SecurityProtocol(0x0),
   so `intersects()` is false even when both agree — added a
   `both_standard` bypass.

## Why it is safe

SCCM inner-RDP uses encryption_method=NONE / encryption_level=None
(confirmed via MCS Connect Response). The outer SCCM SecurityFilter
(Kerberos GSS) provides all confidentiality. There is no RC4 to perform.

## Drawing-order patches (`src/connection_activation.rs`)

The 2014-era SCCM RDP server only paints via RDP primary drawing orders
(MS-RDPEGDI), which IronRDP does not implement. `crates/sccm-rc-orders`
implements them; these capability changes make the server send them.
Gated on `SCCM_RC_ORDERS=1` (default off — leave off for plain bitmap mode):

3. Order capability advertises NEGOTIATE_ORDER_SUPPORT and, in orders mode,
   the order-support flags for exactly the orders our renderer services
   (DstBlt, PatBlt, ScrBlt, MemBlt, LineTo).
4. BitmapCache capability is populated with the classic mstsc rev1 cache
   dimensions (120/256, 120/1024, 336/4096) in orders mode. Advertising
   MemBlt with a zero-capacity cache makes the server reject the inconsistent
   caps (Terminate); a populated rev1 cache also steers it to Cache Bitmap
   Rev1 secondary orders, which the renderer decodes.

Also note `SCCM_RC_LEGACY_GFX=1` (separate gate) drops Surface Commands +
RemoteFx codec caps to force slow-path bitmaps.

## Multi-monitor advertise (`src/lib.rs` + `src/connection.rs`)

5. `Config` gained a `monitors: Vec<gcc::Monitor>` field (default empty =
   single-monitor, today's behaviour). `create_gcc_blocks` emits the
   `TS_UD_CS_MONITOR` block (`ClientMonitorData`) when it is non-empty. The
   caller (`sccm_rdp_config`) sets `desktop_size` to the monitors' bounding box,
   which the block requires. Driven by the viewer's `--monitor` flag.

## Version

Pinned to the IronRDP 0.8 release set: connector 0.8.0, session 0.8.0,
pdu 0.7, graphics 0.7, core 0.1. Re-apply these 2 diffs when bumping.
