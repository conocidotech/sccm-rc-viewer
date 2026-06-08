# Performance plan — making the viewer fast

The viewer still feels much too slow. This is the plan to fix it, ordered by
**measure → cheap wins → architecture → GPU**. Don't guess: each step says what to
measure so we know it worked.

Current data (release build, rc-bench vs TARGET-HOST on 10.0.0.10):
- time-to-RDP-active ~640 ms, **first paint ~4.2 s**, **~5 graphics updates/s**, 122
  updates to reach 100% painted. Server delivers ~14 sealed frames/s; orders are
  **uncompressed** (large 16 KB tiles).

Likely the slowness is a mix of: (a) per-update work done serially on the network
recv path, (b) CPU softbuffer scaling/blit on the UI thread, (c) input/round-trip
latency, (d) lots of uncompressed bytes for the initial paint. We tackle them in order.

---

## RESULT (2026-06-04)

Measured (`SCCM_RC_PROFILE=1`): we are **100% network-bound** — render is ~0.5% of wall time.
So GPU/wgpu (§3) is pointless; the lever is **bytes on the wire**, i.e. compression (§4/§1a).

- **Bulk MPPC compression implemented and ON by default** (`SCCM_RC_COMPRESS`, disable with
  `=0`): clean A/B = **3.63 MB → 1.16 MB (~3×)** for the same full-desktop paint, both 100%
  rendered. Decoder proven against FreeRDP ground-truth vectors. See PROTOCOL.md §14.1.
- The fidelity bug (`#79`) is **FIXED** (2026-06-05): each fast-path fragment is bulk-decompressed
  independently (sharing the persistent 64K history) and reassembled at the plaintext/order layer,
  per FreeRDP — *not* by reassembling the raw compressed bytes first. Live-verified via a 126-record
  capture replay (705 orders, 0 desync) and a clean live render. The 3× win matters over the VPN
  that prompted the original "too slow".
- First-paint time (~3.4 s) is dominated by the arbitration→attach→reactivation handshake,
  not pixel transfer, so it's similar compressed vs not — the win is bandwidth, not latency.
- Also shipped: RELEASE builds (10–30× vs debug), dirty-region sink copies + periodic resync,
  mouse-move coalescing, client-side cursor, TCP_NODELAY.

---

## 0. Measure first — instrument the pipeline

Add lightweight, env-gated timers (SCCM_RC_PROFILE=1) that accumulate, per second:
- `recv_wait` — time blocked in `recv_rdp().await` (network/server bound).
- `unseal` — time in `DecryptMessage`.
- `order_render` — time in `process_orders` (tile/glyph blits).
- `composite` + `sink` — copies.
- UI: time in `render()` (scale + present), and redraws/s.

This tells us whether we are **network-bound** (recv_wait dominates → fix bytes/latency,
§4/§1a) or **render-bound** (order_render/UI dominates → fix pipeline/GPU, §2/§3). Print
a summary at the end of rc-bench. ~1–2 h, unblocks everything.

---

## 1. Quick wins (do now, low risk)

a. **TCP_NODELAY** on the socket — disable Nagle so small input/ack frames aren't
   delayed up to ~40 ms. Pure latency win for interactivity. *(Implemented.)*
   Measure: input→cursor round-trip feel; recv_wait gaps.

b. **Coalesce graphics updates to one per display frame (~60 fps).** Today every order
   stream → a `composite.blit` + a shared-buffer copy + a UI wake. During a burst that's
   dozens of copies+redraws for one visual change. Instead: keep rendering orders into
   the OrderCanvas as they arrive, accumulate the **union dirty rect**, and push to the
   sink only when (i) no more PDUs are buffered, or (ii) >16 ms since the last push.
   Measure: copies/s and redraws/s drop sharply during bursts; smoother motion.

c. **Cap UI redraws.** The cursor-follow requests a redraw per mouse move; ensure winit
   coalescing actually limits us to ~display-refresh (it does), and don't redraw when
   nothing changed.

---

## 2. Architecture — get rendering off the network path

d. **Decouple recv from render.** The active loop currently does
   `recv → process_orders (heavy) → composite → sink` serially, so a heavy paint blocks
   the next network read (and vice-versa). Split into:
   - a **reader** that only `recv_rdp` + reassembles order streams and pushes them to a
     bounded channel (decrypt stays here, it's cheap), and
   - a **renderer** task/thread that drains the channel, runs `process_orders` +
     composite, and emits coalesced frames.
   Now network and rendering pipeline; the reader never stalls on a slow paint.
   Measure: sustained updates/s under load; recv_wait no longer correlated with render.

e. **Remove a buffer copy.** Today: OrderCanvas → composite → shared → window-scale =
   3 buffers, 2 region copies before scaling. Render orders **directly into the
   composite** (the order renderer already owns a canvas; make that canvas the composite,
   or have IronRDP's bitmap path and orders share one buffer). Saves a full copy per
   frame. Measure: composite time → ~0.

---

## 3. GPU rendering (wgpu) — the big smoothness win

f. Replace the **softbuffer** CPU path (per-pixel scale + blit every redraw) with a
   small **wgpu** renderer: upload the desktop framebuffer as a texture (only the dirty
   region via `write_texture`), draw a full-screen quad (GPU does the scaling/filtering
   for free), and draw the cursor as a second textured quad. Present vsync'd.
   - Frees the CPU entirely from scaling/blitting → high, smooth frame rate even at 4K.
   - Crisp/smooth scaling instead of nearest-neighbour.
   This is the single biggest "feels fast" change for a scaled remote desktop. ~1–2 days.
   Measure: UI render time → sub-millisecond; smooth dragging/scrolling.

---

## 4. Fewer bytes on the wire (initial paint + big changes)

g. **Persistent bitmap cache.** We advertise the bitmap cache; ensure the server reuses
   cached tiles across the session instead of re-sending. Reduces the 4.2 s initial paint
   on reconnect. Measure: bytes for the first full paint.

h. **Compression / modern codec.** The server sends us **uncompressed** orders because we
   don't negotiate bulk compression (IronRDP has no MPPC decompressor). Options, in order
   of payoff/effort:
   - Investigate enabling **RDPEGFX / RemoteFX (zgfx)** — IronRDP *does* have a zgfx
     decoder (`ironrdp-graphics`); advertising the GFX pipeline would let the server send
     far less data (and H.264/progressive). Bigger change to the graphics path.
   - Or implement the legacy **MPPC** bulk decompressor and advertise compression in the
     Client Info PDU. Smaller scope, classic RDP.
   Measure: bytes/s and first-paint time.

---

## 5. Latency / first paint specifics

i. **First-paint gap.** ~3.5 s between "reactivation complete" and the first sink update.
   Instrument where it goes (waiting on the server vs reassembling a huge first order
   stream). If server-side, send the Refresh Rect earlier / differently; if client-side
   reassembly, stream partial paints instead of waiting for the whole update.

j. **Server update cadence.** A near-idle screen sends ~5/s; this is fine. The real test
   is active use — re-measure §0 while typing/scrolling once the pipeline (§2) is fixed.

---

## Suggested execution order

1. §0 instrument + §1a TCP_NODELAY + §1b coalesce  → measure, likely a clear improvement.
2. §2d decouple recv/render + §2e drop a copy      → smoother under load.
3. §3f **wgpu** renderer                            → the big smoothness win.
4. §4h GFX/zgfx (or MPPC) compression               → faster initial paint + big changes.

Stop after each and re-measure; pick the next item by what the numbers say.
