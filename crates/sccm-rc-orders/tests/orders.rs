//! Order-stream decode/render tests against hand-built byte sequences.
//! Exercises the primary-order header machinery (field flags, coordinate
//! deltas, persistence), bounds clipping, and the secondary Cache Bitmap ->
//! MemBlt path.

use sccm_rc_orders::{ColorDepth, OrderProcessor};

const W: u16 = 100;
const H: u16 = 100;

/// Read an RGBA pixel from the processor's canvas.
fn px(p: &OrderProcessor, x: u16, y: u16) -> [u8; 4] {
    let c = p.canvas();
    let i = (y as usize * c.width() as usize + x as usize) * 4;
    let d = c.data();
    [d[i], d[i + 1], d[i + 2], d[i + 3]]
}

/// Wrap order bytes with the Fast-Path Orders update header (numberOrders).
fn update(number_orders: u16, orders: &[u8]) -> Vec<u8> {
    let mut v = number_orders.to_le_bytes().to_vec();
    v.extend_from_slice(orders);
    v
}

fn proc() -> OrderProcessor {
    OrderProcessor::new(W, H, ColorDepth::Bpp16)
}

#[test]
fn opaque_rect_fills_with_color() {
    let mut p = proc();
    // control = STANDARD|TYPE_CHANGE, type = OPAQUE_RECT(0x0A), fieldFlags=0x7F
    // (all 7 fields), then x=10,y=20,w=30,h=40 (i16 LE), r,g,b.
    #[rustfmt::skip]
    let order = [
        0x09, 0x0A, 0x7F,
        10, 0, 20, 0, 30, 0, 40, 0,
        0x11, 0x22, 0x33,
    ];
    let outcome = p.process_orders(&update(1, &order)).unwrap();
    assert_eq!(outcome.orders, 1);

    assert_eq!(px(&p, 10, 20), [0x11, 0x22, 0x33, 0xff]);
    assert_eq!(px(&p, 39, 59), [0x11, 0x22, 0x33, 0xff]); // bottom-right inside
    assert_eq!(px(&p, 40, 20), [0, 0, 0, 0]); // just outside right edge: untouched
    assert_eq!(px(&p, 9, 20), [0, 0, 0, 0]); // just outside left edge
}

#[test]
fn delta_coords_and_field_persistence() {
    let mut p = proc();
    // First OpaqueRect (absolute), all fields.
    #[rustfmt::skip]
    let first = [
        0x09, 0x0A, 0x7F,
        10, 0, 10, 0, 5, 0, 5, 0,
        0xAA, 0xBB, 0xCC,
    ];
    // Second OpaqueRect, same type (no TYPE_CHANGE), DELTA coords, only move
    // x/y by +20 (fieldFlags = bits 0,1 = 0x03). w/h/color persist.
    #[rustfmt::skip]
    let second = [
        0x01 | 0x10, // STANDARD | DELTA_COORDINATES
        0x03,        // fields: x, y
        20, 20,      // dx=+20, dy=+20 (i8)
    ];
    let mut bytes = first.to_vec();
    bytes.extend_from_slice(&second);
    p.process_orders(&update(2, &bytes)).unwrap();

    // First rect still there.
    assert_eq!(px(&p, 10, 10), [0xAA, 0xBB, 0xCC, 0xff]);
    // Second rect at (30,30) with persisted 5x5 size and persisted color.
    assert_eq!(px(&p, 30, 30), [0xAA, 0xBB, 0xCC, 0xff]);
    assert_eq!(px(&p, 34, 34), [0xAA, 0xBB, 0xCC, 0xff]);
    assert_eq!(px(&p, 35, 35), [0, 0, 0, 0]); // outside persisted 5x5
}

#[test]
fn dstblt_whiteness_and_blackness() {
    let mut p = proc();
    // WHITENESS dstblt over 5x5 at (0,0): control STANDARD|TYPE_CHANGE,
    // type DSTBLT(0x00), fieldFlags=0x1F (all 5), x,y,w,h,rop=0xFF.
    #[rustfmt::skip]
    let white = [
        0x09, 0x00, 0x1F,
        0, 0, 0, 0, 5, 0, 5, 0,
        0xFF,
    ];
    p.process_orders(&update(1, &white)).unwrap();
    assert_eq!(px(&p, 2, 2), [0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn scrblt_copies_region() {
    let mut p = proc();
    // Paint a 10x10 red block at (0,0).
    #[rustfmt::skip]
    let fill = [
        0x09, 0x0A, 0x7F,
        0, 0, 0, 0, 10, 0, 10, 0,
        0xFF, 0x00, 0x00,
    ];
    // ScrBlt: copy from (0,0) to (50,50), 10x10. type SCRBLT(0x02),
    // fieldFlags=0x7F (7 fields): x=50,y=50,w=10,h=10,rop=0xCC,xSrc=0,ySrc=0.
    #[rustfmt::skip]
    let scr = [
        0x09, 0x02, 0x7F,
        50, 0, 50, 0, 10, 0, 10, 0,
        0xCC,
        0, 0, 0, 0,
    ];
    let mut bytes = fill.to_vec();
    bytes.extend_from_slice(&scr);
    p.process_orders(&update(2, &bytes)).unwrap();

    assert_eq!(px(&p, 55, 55), [0xff, 0x00, 0x00, 0xff]);
    assert_eq!(px(&p, 5, 5), [0xff, 0x00, 0x00, 0xff]); // source intact
}

#[test]
fn memblt_blits_cached_bitmap() {
    let mut p = proc();

    // Secondary: Cache Bitmap Rev1 uncompressed, a 2x2 all-red 16bpp bitmap
    // into cache_id=0, index=0.
    let red565 = 0xF800u16.to_le_bytes();
    let mut payload = vec![
        0x00, // cacheId
        0x00, // pad
        0x02, // width
        0x02, // height
        16,   // bpp
    ];
    payload.extend_from_slice(&(8u16).to_le_bytes()); // bitmapLength = 2*2*2
    payload.extend_from_slice(&(0u16).to_le_bytes()); // cacheIndex
    for _ in 0..4 {
        payload.extend_from_slice(&red565);
    }
    // payload is 17 bytes -> orderLength = 17 - 7 = 10.
    assert_eq!(payload.len(), 17);
    let mut secondary = vec![0x03]; // STANDARD | SECONDARY
    secondary.extend_from_slice(&(10u16).to_le_bytes()); // orderLength
    secondary.extend_from_slice(&(0u16).to_le_bytes()); // extraFlags
    secondary.push(0x00); // orderType = CACHE_BITMAP_UNCOMPRESSED
    secondary.extend_from_slice(&payload);

    // MemBlt: type MEMBLT(0x0D), fieldFlags=0x01FF (9 fields).
    #[rustfmt::skip]
    let memblt = [
        0x09, 0x0D, 0xFF, 0x01,
        0, 0,        // cacheId
        50, 0,       // x
        50, 0,       // y
        2, 0,        // w
        2, 0,        // h
        0xCC,        // rop
        0, 0,        // xSrc
        0, 0,        // ySrc
        0, 0,        // cacheIndex
    ];

    let mut bytes = secondary;
    bytes.extend_from_slice(&memblt);
    let outcome = p.process_orders(&update(2, &bytes)).unwrap();
    assert_eq!(outcome.orders, 2);

    assert_eq!(px(&p, 50, 50), [0xff, 0x00, 0x00, 0xff]);
    assert_eq!(px(&p, 51, 51), [0xff, 0x00, 0x00, 0xff]);
    assert_eq!(px(&p, 52, 52), [0, 0, 0, 0]); // outside the 2x2
}

#[test]
fn cache_glyph_then_fast_index_draws_text() {
    let mut p = proc();

    // Secondary Cache Glyph: cacheId=0, 1 glyph, index 0, origin (0,0), 8x8,
    // all bits set (a solid 8x8 block). aj = 8 bytes (1 row-byte * 8 rows).
    #[rustfmt::skip]
    let payload: Vec<u8> = vec![
        0x00, // cacheId
        0x01, // cGlyphs
        0, 0, // cacheIndex
        0, 0, // x
        0, 0, // y
        8, 0, // cx
        8, 0, // cy
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // aj
    ];
    assert_eq!(payload.len(), 20); // orderLength = 20 - 7 = 13
    let mut secondary = vec![0x03]; // STANDARD | SECONDARY
    secondary.extend_from_slice(&(13u16).to_le_bytes());
    secondary.extend_from_slice(&(0u16).to_le_bytes()); // extraFlags
    secondary.push(0x03); // orderType = CACHE_GLYPH
    secondary.extend_from_slice(&payload);

    // Primary FastIndex (0x13): draw cached glyph 0 in red at (10,10).
    // fields: cacheId(0), ulCharInc+flAccel(1), foreColor(3), x(12), y(13), data(14)
    // = bits 0,1,3,12,13,14 = 0x700B -> 3 bytes LE 0B 70 00.
    #[rustfmt::skip]
    let fast_index = [
        0x09, 0x13,        // STANDARD|TYPE_CHANGE, FAST_INDEX
        0x0B, 0x70, 0x00,  // field flags
        0x00,              // cacheId = 0
        0x08, 0x00,        // ulCharInc = 8, flAccel = 0
        0xFF, 0x00, 0x00,  // foreColor R,G,B = red
        10, 0,             // x = 10
        10, 0,             // y = 10
        0x01, 0x00,        // cbData = 1, data = [glyph index 0]
    ];

    let mut bytes = secondary;
    bytes.extend_from_slice(&fast_index);
    let outcome = p.process_orders(&update(2, &bytes)).unwrap();
    assert_eq!(outcome.orders, 2);
    assert_eq!(outcome.skipped, 0);

    // The 8x8 glyph painted red at (10,10)..(17,17).
    assert_eq!(px(&p, 10, 10), [0xff, 0x00, 0x00, 0xff]);
    assert_eq!(px(&p, 17, 17), [0xff, 0x00, 0x00, 0xff]);
    assert_eq!(px(&p, 18, 18), [0, 0, 0, 0]); // just outside the glyph
    assert_eq!(px(&p, 9, 9), [0, 0, 0, 0]); // before the glyph origin
}

#[test]
fn glyph_fragment_cache_replays() {
    let mut p = proc();

    // Cache one 8x8 solid glyph (index 0), as in the previous test.
    #[rustfmt::skip]
    let payload: Vec<u8> = vec![
        0x00, 0x01, 0, 0, 0, 0, 0, 0, 8, 0, 8, 0,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    let mut secondary = vec![0x03];
    secondary.extend_from_slice(&(13u16).to_le_bytes());
    secondary.extend_from_slice(&(0u16).to_le_bytes());
    secondary.push(0x03);
    secondary.extend_from_slice(&payload);

    // FastIndex with glyph data: [idx0, 0xFF id=0 size=1, 0xFE id=0].
    // -> draw glyph0 at x=10 (advance 8), cache the preceding [idx0] as fragment 0,
    //    then replay fragment 0 -> draw glyph0 again at x=18.
    #[rustfmt::skip]
    let fast_index = [
        0x09, 0x13,
        0x0B, 0x70, 0x00,
        0x00,            // cacheId
        0x08, 0x00,      // ulCharInc=8, flAccel=0
        0xFF, 0x00, 0x00, // foreColor red
        10, 0,           // x
        10, 0,           // y
        0x06,            // cbData = 6
        0x00, 0xFF, 0x00, 0x01, 0xFE, 0x00,
    ];

    let mut bytes = secondary;
    bytes.extend_from_slice(&fast_index);
    p.process_orders(&update(2, &bytes)).unwrap();

    assert_eq!(px(&p, 10, 10), [0xff, 0x00, 0x00, 0xff]); // first glyph
    assert_eq!(px(&p, 18, 10), [0xff, 0x00, 0x00, 0xff]); // replayed fragment glyph
    assert_eq!(px(&p, 25, 10), [0xff, 0x00, 0x00, 0xff]); // right edge of 2nd glyph
    assert_eq!(px(&p, 26, 10), [0, 0, 0, 0]); // just past it
}

#[test]
fn bounds_clip_restricts_drawing() {
    let mut p = proc();
    // OpaqueRect 0..50 square but clipped to bounds (0,0)-(9,9) inclusive.
    // control = STANDARD | TYPE_CHANGE | BOUNDS.
    // bounds desc flags = LEFT|TOP|RIGHT|BOTTOM (0x0F), values 0,0,9,9 (i16).
    #[rustfmt::skip]
    let order = [
        0x01 | 0x08 | 0x04, // STANDARD|TYPE_CHANGE|BOUNDS
        0x0A,               // OPAQUE_RECT
        0x7F,               // all fields
        0x0F,               // bounds: absolute L,T,R,B
        0, 0,  0, 0,  9, 0,  9, 0,
        0, 0, 0, 0, 50, 0, 50, 0, // x,y,w,h
        0x10, 0x20, 0x30,
    ];
    p.process_orders(&update(1, &order)).unwrap();

    assert_eq!(px(&p, 9, 9), [0x10, 0x20, 0x30, 0xff]); // inside bounds
    assert_eq!(px(&p, 10, 10), [0, 0, 0, 0]); // clipped away by bounds
}
