//! Caches the server populates via secondary orders and references from
//! primary orders. For now: the bitmap cache (Cache Bitmap -> MemBlt) and the
//! color-table cache (palettes for 8 bpp). Glyph cache lands with text support.

use crate::canvas::Bitmap;

/// Bitmap cache: indexed by `(cache_id, cache_index)`. Grown on demand.
#[derive(Default)]
pub struct BitmapCache {
    caches: Vec<Vec<Option<Bitmap>>>,
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

    pub fn get(&self, cache_id: usize, cache_index: usize) -> Option<&Bitmap> {
        self.caches.get(cache_id)?.get(cache_index)?.as_ref()
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
