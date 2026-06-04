//! Caches the server populates via secondary orders and references from
//! primary orders. For now: the bitmap cache (Cache Bitmap -> MemBlt) and the
//! color-table cache (palettes for 8 bpp). Glyph cache lands with text support.

use crate::canvas::Bitmap;

/// The waiting-list cache index (MS-RDPBCGR): bitmaps sent with this index are
/// transient / promoted to the cache proper via the waiting list.
pub const WAITING_LIST_INDEX: usize = 0x7FFF;

/// Bitmap cache: indexed by `(cache_id, cache_index)`. Grown on demand.
///
/// The SCCM RC server paints the desktop as a grid of 64x64 tiles, caching every
/// tile via Cache Bitmap Rev2 with the waiting-list index (0x7FFF) and then
/// blitting them with MemBlt — referencing either 0x7FFF (the most-recent tile)
/// or a real index 0,1,2,… (a previously waiting-listed tile, promoted in send
/// order). We model that by assigning each waiting-list bitmap the next
/// sequential real index per `cache_id`, and also remembering the last one.
#[derive(Default)]
pub struct BitmapCache {
    caches: Vec<Vec<Option<Bitmap>>>,
    next_seq: Vec<usize>,
    last_transient: Option<Bitmap>,
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
        self.last_transient = Some(bitmap.clone());
        *self.slot(cache_id, cache_index) = Some(bitmap);
    }

    /// Store a waiting-list bitmap: assign it the next sequential index for this
    /// cache and remember it as the last transient. Returns the assigned index.
    pub fn insert_waiting(&mut self, cache_id: usize, bitmap: Bitmap) -> usize {
        if cache_id >= self.next_seq.len() {
            self.next_seq.resize(cache_id + 1, 0);
        }
        let idx = self.next_seq[cache_id];
        self.next_seq[cache_id] = idx + 1;
        self.insert(cache_id, idx, bitmap);
        idx
    }

    pub fn get(&self, cache_id: usize, cache_index: usize) -> Option<&Bitmap> {
        if cache_index == WAITING_LIST_INDEX {
            return self.last_transient.as_ref();
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
