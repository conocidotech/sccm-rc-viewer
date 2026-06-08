//! Caches the server populates via secondary orders and references from
//! primary orders. For now: the bitmap cache (Cache Bitmap -> MemBlt) and the
//! color-table cache (palettes for 8 bpp). Glyph cache lands with text support.

use crate::canvas::Bitmap;

/// The waiting-list cache index (MS-RDPBCGR): bitmaps sent with this index are
/// transient / promoted to the cache proper via the waiting list.
pub const WAITING_LIST_INDEX: usize = 0x7FFF;

/// Bitmap cache: indexed by `(cache_id, cache_index)`. Grown on demand.
///
/// The SCCM RC server paints the desktop as a grid of 64x64 tiles. Tiles it will
/// reuse are cached via Cache Bitmap Rev2 with an EXPLICIT, contiguous index
/// (0,1,2,… per `cache_id`) and later re-blitted by MemBlt with that index. Tiles
/// it uses only once are cached with the waiting-list index `0x7FFF` and blitted
/// immediately via MemBlt(0x7FFF).
///
/// Critically, the `0x7FFF` (transient) bitmaps must NOT occupy real cache cells:
/// they share the cell space with the explicitly-indexed tiles, so writing them
/// into real slots clobbers reusable tiles → MemBlt(real index) later fetches the
/// wrong bitmap (ghost tiles). Per FreeRDP (`bitmap_cache_get`/`put`: index ==
/// WAITING_LIST → `cells[id].number`), we map `0x7FFF` to a single dedicated
/// transient slot per `cache_id`, kept entirely separate from the real cells.
#[derive(Default)]
pub struct BitmapCache {
    caches: Vec<Vec<Option<Bitmap>>>,
    /// Per-`cache_id` waiting-list (transient) slot for bitmaps cached with the
    /// `0x7FFF` index. Read back via `get(cache_id, 0x7FFF)`; never aliases a real
    /// cell, so it cannot corrupt explicitly-indexed tiles.
    waiting: Vec<Option<Bitmap>>,
}

impl BitmapCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&mut self, cache_id: usize, cache_index: usize) -> &mut Option<Bitmap> {
        if cache_id >= self.caches.len() {
            self.caches.resize_with(cache_id + 1, Vec::new);
        }
        let cache = &mut self.caches[cache_id];
        if cache_index >= cache.len() {
            cache.resize_with(cache_index + 1, || None);
        }
        &mut cache[cache_index]
    }

    pub fn insert(&mut self, cache_id: usize, cache_index: usize, bitmap: Bitmap) {
        *self.slot(cache_id, cache_index) = Some(bitmap);
    }

    /// Store a bitmap cached with the waiting-list index (`0x7FFF`) in this cache's
    /// dedicated transient slot — NOT a real cell. Read back via
    /// `get(cache_id, 0x7FFF)` (the MemBlt that immediately follows).
    pub fn insert_waiting(&mut self, cache_id: usize, bitmap: Bitmap) {
        if cache_id >= self.waiting.len() {
            self.waiting.resize_with(cache_id + 1, || None);
        }
        self.waiting[cache_id] = Some(bitmap);
    }

    pub fn get(&self, cache_id: usize, cache_index: usize) -> Option<&Bitmap> {
        if cache_index == WAITING_LIST_INDEX {
            return self.waiting.get(cache_id)?.as_ref();
        }
        self.caches.get(cache_id)?.get(cache_index)?.as_ref()
    }
}

/// A cached glyph: a 1-bpp bitmap plus its origin bearing (x,y offset applied
/// when the glyph is drawn). `aj` is `ceil(cx/8)` bytes per row, MSB-first.
#[derive(Clone, Debug)]
pub struct Glyph {
    pub x: i16,
    pub y: i16,
    pub cx: u16,
    pub cy: u16,
    pub aj: Vec<u8>,
}

/// Glyph cache, indexed by `(cache_id, cache_index)`. Populated by Cache Glyph
/// secondary orders, read by GlyphIndex/FastIndex/FastGlyph primary orders. Also
/// holds the glyph *fragment* cache (sequences of glyph-index bytes the server
/// caches via the 0xFF escape and replays via 0xFE).
#[derive(Default)]
pub struct GlyphCache {
    caches: Vec<Vec<Option<Glyph>>>,
    fragments: Vec<Vec<u8>>,
}

impl GlyphCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, cache_id: usize, cache_index: usize, glyph: Glyph) {
        if cache_id >= self.caches.len() {
            self.caches.resize_with(cache_id + 1, Vec::new);
        }
        let cache = &mut self.caches[cache_id];
        if cache_index >= cache.len() {
            cache.resize_with(cache_index + 1, || None);
        }
        cache[cache_index] = Some(glyph);
    }

    pub fn get(&self, cache_id: usize, cache_index: usize) -> Option<&Glyph> {
        self.caches.get(cache_id)?.get(cache_index)?.as_ref()
    }

    /// Cache a glyph-fragment byte sequence (the 0xFF "add to cache" escape).
    pub fn put_fragment(&mut self, id: usize, bytes: &[u8]) {
        if id >= self.fragments.len() {
            self.fragments.resize_with(id + 1, Vec::new);
        }
        self.fragments[id] = bytes.to_vec();
    }

    /// Look up a cached fragment (the 0xFE "use from cache" escape).
    pub fn fragment(&self, id: usize) -> Option<&[u8]> {
        self.fragments.get(id).map(|v| v.as_slice())
    }
}

/// Color-table (palette) cache for 8 bpp sessions.
#[derive(Default)]
pub struct PaletteCache {
    tables: Vec<Option<Box<[[u8; 4]; 256]>>>,
}

impl PaletteCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, index: usize, table: Box<[[u8; 4]; 256]>) {
        if index >= self.tables.len() {
            self.tables.resize_with(index + 1, || None);
        }
        self.tables[index] = Some(table);
    }

    #[allow(dead_code)] // consumed once 8 bpp MemBlt palette lookup lands
    pub fn get(&self, index: usize) -> Option<&[[u8; 4]; 256]> {
        self.tables.get(index)?.as_deref()
    }
}
