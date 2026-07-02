//! In-window host-picker overlay. Shown when the viewer starts without a
//! CLI target and after the operator clicks Disconnect — replaces the
//! separate Win32 modal so the picker lives inside the same viewer window
//! and shares its font/rendering.
//!
//! State-only: no windowing calls, no allocations per frame. `draw()`
//! rasterises the overlay into a u32 ARGB buffer using the same softbuffer
//! conventions as the About screen (top byte = X, then RGB). App polls
//! `take_outcome()` in `about_to_wait` after every event batch and reacts.
//!
//! Keyboard model, deliberately spartan for v1:
//!   - printable char → append to `input`
//!   - Backspace → pop last char
//!   - ↑ / ↓ → move `selected` over recents; the highlighted recent becomes
//!     the new `input`, so Enter always confirms exactly what's shown
//!   - Enter → confirm current `input` (Trim-empty ignored)
//!   - Esc → cancel

use crate::recent;
use crate::text::TextRenderer;
use crate::toolbar;
use rust_i18n::t;

const CARD_W: u32 = 480;
const CARD_H: u32 = 360;
const ROW_H: u32 = 28;
const MAX_RECENTS_SHOWN: usize = 6;

pub enum PromptOutcome {
    Confirmed(String),
    Cancelled,
}

pub struct HostPromptOverlay {
    input: String,
    recents: Vec<String>,
    /// None = the text edit is active. Some(i) means arrow-nav landed on the
    /// i-th recent — that string is mirrored into `input` so Enter always
    /// confirms exactly what the user sees in the edit field.
    selected: Option<usize>,
    outcome: Option<PromptOutcome>,
    /// Anchor for the caret-blink phase. Reset on every keystroke so the
    /// caret is immediately visible after a change (standard OS behaviour),
    /// then blinks at 500 ms cadence.
    caret_anchor: std::time::Instant,
}

impl HostPromptOverlay {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            recents: recent::load(),
            selected: None,
            outcome: None,
            caret_anchor: std::time::Instant::now(),
        }
    }

    fn bump_caret(&mut self) {
        self.caret_anchor = std::time::Instant::now();
    }

    pub fn on_text(&mut self, s: &str) {
        for c in s.chars() {
            if c.is_control() {
                continue;
            }
            self.input.push(c);
        }
        self.selected = None;
        self.bump_caret();
    }

    pub fn on_backspace(&mut self) {
        self.input.pop();
        self.selected = None;
        self.bump_caret();
    }

    pub fn on_arrow_down(&mut self) {
        if self.recents.is_empty() {
            return;
        }
        let next = match self.selected {
            None => 0,
            Some(i) if i + 1 < self.recents.len().min(MAX_RECENTS_SHOWN) => i + 1,
            Some(i) => i,
        };
        self.selected = Some(next);
        self.input = self.recents[next].clone();
        self.bump_caret();
    }

    pub fn on_arrow_up(&mut self) {
        if self.recents.is_empty() {
            return;
        }
        self.selected = match self.selected {
            Some(0) | None => None,
            Some(i) => Some(i - 1),
        };
        if let Some(i) = self.selected {
            self.input = self.recents[i].clone();
        }
        self.bump_caret();
    }

    pub fn on_enter(&mut self) {
        let trimmed = self.input.trim();
        if trimmed.is_empty() {
            return;
        }
        self.outcome = Some(PromptOutcome::Confirmed(trimmed.to_string()));
    }

    pub fn on_esc(&mut self) {
        self.outcome = Some(PromptOutcome::Cancelled);
    }

    pub fn take_outcome(&mut self) -> Option<PromptOutcome> {
        self.outcome.take()
    }
}

/// Rasterise the overlay into an ARGB u32 buffer. Fills the full frame with a
/// dim backdrop and draws a centered card on top.
pub fn draw(
    buf: &mut [u32],
    w: u32,
    h: u32,
    font: Option<&TextRenderer>,
    overlay: &HostPromptOverlay,
) {
    for px in buf.iter_mut() {
        *px = 0x0020_2020;
    }

    let cx = (w / 2) as i32;
    let cy = (h / 2) as i32;
    let card_x = cx - (CARD_W as i32) / 2;
    let card_y = cy - (CARD_H as i32) / 2;

    fill_rect(buf, w, h, card_x, card_y, CARD_W, CARD_H, 0x002E_343C);
    stroke_rect(buf, w, h, card_x, card_y, CARD_W, CARD_H, 0x0050_5860);

    // Title
    let title = t!("prompt.label");
    if let Some(f) = font {
        f.draw_centered(buf, w, h, (card_y + 40) as f32, &title, 0x00E4_EAF0, 22.0);
    } else {
        toolbar::draw_text_centered(buf, w, h, (card_y + 32) as u32, &title, 0x00E4_EAF0, 2);
    }

    // Text field
    let tf_x = card_x + 24;
    let tf_y = card_y + 68;
    let tf_w = CARD_W - 48;
    let tf_h = 36u32;
    fill_rect(buf, w, h, tf_x, tf_y, tf_w, tf_h, 0x001B_1E23);
    let border = if overlay.selected.is_none() {
        0x0060_88B8
    } else {
        0x0045_4C55
    };
    stroke_rect(buf, w, h, tf_x, tf_y, tf_w, tf_h, border);

    let placeholder = t!("prompt.placeholder");
    let text_x = (tf_x + 10) as f32;
    let text_y = (tf_y + 6) as f32;
    let text_band = tf_h - 12;
    // Show placeholder in grey when the field is empty AND unfocused-to-recent;
    // otherwise the real input in the normal colour. The caret is drawn
    // separately so it also renders (blinking) when the field is empty.
    let show_placeholder = overlay.input.is_empty() && overlay.selected.is_none();
    if show_placeholder {
        draw_left(buf, w, h, text_x, text_y, text_band, &placeholder, 0x0070_7880, 18.0, font);
    } else {
        draw_left(buf, w, h, text_x, text_y, text_band, &overlay.input, 0x00E4_EAF0, 18.0, font);
    }
    // Blinking caret when the edit field is focused (i.e. no recent is
    // arrow-selected). On/off at 500 ms cadence, anchored at `caret_anchor`
    // which resets on every keystroke — same behaviour as native text fields.
    if overlay.selected.is_none() {
        let ms = overlay.caret_anchor.elapsed().as_millis();
        let visible = (ms / 500) % 2 == 0;
        if visible {
            let text_w = if overlay.input.is_empty() {
                0.0
            } else {
                font.map(|f| f.width(&overlay.input, 18.0))
                    .unwrap_or(overlay.input.chars().count() as f32 * 8.0)
            };
            let caret_x = (text_x + text_w) as i32;
            let caret_y = (tf_y + 8) as i32;
            let caret_h = (tf_h - 16).max(1);
            fill_rect(buf, w, h, caret_x, caret_y, 2, caret_h, 0x00E4_EAF0);
        }
    }

    // Recents list
    let list_x = tf_x;
    let mut row_y = tf_y as i32 + tf_h as i32 + 18;
    for (idx, host) in overlay.recents.iter().take(MAX_RECENTS_SHOWN).enumerate() {
        let highlighted = overlay.selected == Some(idx);
        if highlighted {
            fill_rect(buf, w, h, list_x, row_y, tf_w, ROW_H, 0x0038_4454);
        }
        let colour = if highlighted { 0x00FF_FFFF } else { 0x00C0_C8D0 };
        draw_left(buf, w, h, (list_x + 12) as f32, row_y as f32, ROW_H, host, colour, 17.0, font);
        row_y += ROW_H as i32;
    }

    // Hint at the bottom of the card
    let hint = t!("prompt.hint");
    let hint_y = card_y + CARD_H as i32 - 30;
    if let Some(f) = font {
        f.draw_centered(buf, w, h, (hint_y + 12) as f32, &hint, 0x0070_7880, 14.0);
    } else {
        toolbar::draw_text_centered(buf, w, h, hint_y as u32, &hint, 0x0070_7880, 1);
    }
}

fn draw_left(
    buf: &mut [u32],
    w: u32,
    h: u32,
    x: f32,
    band_top: f32,
    band_h: u32,
    s: &str,
    color: u32,
    px: f32,
    font: Option<&TextRenderer>,
) {
    if let Some(f) = font {
        f.draw_vcenter(buf, w, h, x, band_top, band_h as f32, s, color, px);
    } else {
        toolbar::draw_text_scaled(buf, w, h, x as u32, band_top as u32, s, color, 1);
    }
}

fn fill_rect(buf: &mut [u32], w: u32, h: u32, x: i32, y: i32, rw: u32, rh: u32, color: u32) {
    let x0 = x.max(0) as u32;
    let y0 = y.max(0) as u32;
    let x1 = ((x + rw as i32).max(0) as u32).min(w);
    let y1 = ((y + rh as i32).max(0) as u32).min(h);
    for py in y0..y1 {
        let row = (py * w) as usize;
        for px in x0..x1 {
            buf[row + px as usize] = color;
        }
    }
}

fn stroke_rect(buf: &mut [u32], w: u32, h: u32, x: i32, y: i32, rw: u32, rh: u32, color: u32) {
    let w_i = w as i32;
    let h_i = h as i32;
    for i in 0..rw as i32 {
        let px = x + i;
        if px < 0 || px >= w_i {
            continue;
        }
        for &py in &[y, y + rh as i32 - 1] {
            if py < 0 || py >= h_i {
                continue;
            }
            buf[(py * w_i + px) as usize] = color;
        }
    }
    for i in 0..rh as i32 {
        let py = y + i;
        if py < 0 || py >= h_i {
            continue;
        }
        for &px in &[x, x + rw as i32 - 1] {
            if px < 0 || px >= w_i {
                continue;
            }
            buf[(py * w_i + px) as usize] = color;
        }
    }
}
