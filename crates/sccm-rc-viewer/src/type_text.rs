//! Type-text overlay: prompts the operator for a string, then sends it as a
//! keystroke sequence to the remote. Purpose: paste credentials into a UAC
//! prompt or Secure Desktop, where MS-RDPECLIP (our cliprdr channel) is
//! deliberately blocked by Windows.
//!
//! Deliberately narrow: ASCII only. Non-ASCII would need per-keyboard-layout
//! translation (a dead-key on nl-NL is not the same scancode as on en-US);
//! for credentials that's rarely a problem — passwords tend to be
//! ASCII-printable.

use crate::text::TextRenderer;
use crate::toolbar;
use rust_i18n::t;
use sccm_rc_core::rdp::{FastPathInputEvent, KeyboardFlags};

const CARD_W: u32 = 480;
const CARD_H: u32 = 220;
const TF_H: u32 = 36;
const BTN_W: u32 = 110;
const BTN_H: u32 = 32;

pub enum TypeOutcome {
    Confirmed(Vec<FastPathInputEvent>),
    Cancelled,
}

pub struct TypeTextOverlay {
    input: String,
    outcome: Option<TypeOutcome>,
    caret_anchor: std::time::Instant,
}

impl TypeTextOverlay {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            outcome: None,
            caret_anchor: std::time::Instant::now(),
        }
    }

    fn bump(&mut self) {
        self.caret_anchor = std::time::Instant::now();
    }

    pub fn on_text(&mut self, s: &str) {
        for c in s.chars() {
            if c.is_control() {
                continue;
            }
            self.input.push(c);
        }
        self.bump();
    }

    pub fn on_backspace(&mut self) {
        self.input.pop();
        self.bump();
    }

    /// Ctrl+A / Ctrl+Del: since we don't render a visual selection, "select
    /// all + retype" collapses to "clear the field" — same visible outcome.
    pub fn on_clear(&mut self) {
        self.input.clear();
        self.bump();
    }

    pub fn on_enter(&mut self) {
        if self.input.is_empty() {
            return;
        }
        let events = encode_string(&self.input);
        self.outcome = Some(TypeOutcome::Confirmed(events));
    }

    pub fn on_esc(&mut self) {
        self.outcome = Some(TypeOutcome::Cancelled);
    }

    /// Left-click handling. Send button → confirm, Cancel → cancel. A click on
    /// the text field is a no-op (the field is always "focused" while the
    /// overlay is up).
    pub fn on_click(&mut self, x: f64, y: f64, win_w: u32, win_h: u32) {
        let l = layout(win_w, win_h);
        if l.send.contains(x, y) {
            self.on_enter();
        } else if l.cancel.contains(x, y) {
            self.on_esc();
        }
    }

    pub fn take_outcome(&mut self) -> Option<TypeOutcome> {
        self.outcome.take()
    }
}

/// Translate `text` to a set-1 keystroke sequence: for every char, press then
/// release, holding Shift for characters that require it. Unknown chars are
/// skipped — better a shorter password than a corrupted one. Public so the
/// Ctrl+Shift+V "paste as scancodes" handler in main.rs can call it without
/// spinning up the overlay.
pub fn encode_string(text: &str) -> Vec<FastPathInputEvent> {
    let mut out = Vec::with_capacity(text.len() * 4);
    let down = KeyboardFlags::empty();
    let up = KeyboardFlags::RELEASE;
    let shift_sc: u8 = 0x2A; // Left Shift
    let mut shift_down = false;
    for ch in text.chars() {
        let Some((sc, need_shift)) = ascii_to_scancode(ch) else {
            continue;
        };
        if need_shift && !shift_down {
            out.push(FastPathInputEvent::KeyboardEvent(down, shift_sc));
            shift_down = true;
        } else if !need_shift && shift_down {
            out.push(FastPathInputEvent::KeyboardEvent(up, shift_sc));
            shift_down = false;
        }
        out.push(FastPathInputEvent::KeyboardEvent(down, sc));
        out.push(FastPathInputEvent::KeyboardEvent(up, sc));
    }
    if shift_down {
        out.push(FastPathInputEvent::KeyboardEvent(up, shift_sc));
    }
    out
}

/// ASCII → (set-1 scancode, needs_shift) for a US layout. Covers the printable
/// range that credentials typically use. Return None for anything else.
fn ascii_to_scancode(ch: char) -> Option<(u8, bool)> {
    Some(match ch {
        'a' => (0x1E, false), 'A' => (0x1E, true),
        'b' => (0x30, false), 'B' => (0x30, true),
        'c' => (0x2E, false), 'C' => (0x2E, true),
        'd' => (0x20, false), 'D' => (0x20, true),
        'e' => (0x12, false), 'E' => (0x12, true),
        'f' => (0x21, false), 'F' => (0x21, true),
        'g' => (0x22, false), 'G' => (0x22, true),
        'h' => (0x23, false), 'H' => (0x23, true),
        'i' => (0x17, false), 'I' => (0x17, true),
        'j' => (0x24, false), 'J' => (0x24, true),
        'k' => (0x25, false), 'K' => (0x25, true),
        'l' => (0x26, false), 'L' => (0x26, true),
        'm' => (0x32, false), 'M' => (0x32, true),
        'n' => (0x31, false), 'N' => (0x31, true),
        'o' => (0x18, false), 'O' => (0x18, true),
        'p' => (0x19, false), 'P' => (0x19, true),
        'q' => (0x10, false), 'Q' => (0x10, true),
        'r' => (0x13, false), 'R' => (0x13, true),
        's' => (0x1F, false), 'S' => (0x1F, true),
        't' => (0x14, false), 'T' => (0x14, true),
        'u' => (0x16, false), 'U' => (0x16, true),
        'v' => (0x2F, false), 'V' => (0x2F, true),
        'w' => (0x11, false), 'W' => (0x11, true),
        'x' => (0x2D, false), 'X' => (0x2D, true),
        'y' => (0x15, false), 'Y' => (0x15, true),
        'z' => (0x2C, false), 'Z' => (0x2C, true),
        '0' => (0x0B, false), ')' => (0x0B, true),
        '1' => (0x02, false), '!' => (0x02, true),
        '2' => (0x03, false), '@' => (0x03, true),
        '3' => (0x04, false), '#' => (0x04, true),
        '4' => (0x05, false), '$' => (0x05, true),
        '5' => (0x06, false), '%' => (0x06, true),
        '6' => (0x07, false), '^' => (0x07, true),
        '7' => (0x08, false), '&' => (0x08, true),
        '8' => (0x09, false), '*' => (0x09, true),
        '9' => (0x0A, false), '(' => (0x0A, true),
        '-' => (0x0C, false), '_' => (0x0C, true),
        '=' => (0x0D, false), '+' => (0x0D, true),
        '[' => (0x1A, false), '{' => (0x1A, true),
        ']' => (0x1B, false), '}' => (0x1B, true),
        '\\' => (0x2B, false), '|' => (0x2B, true),
        ';' => (0x27, false), ':' => (0x27, true),
        '\'' => (0x28, false), '"' => (0x28, true),
        '`' => (0x29, false), '~' => (0x29, true),
        ',' => (0x33, false), '<' => (0x33, true),
        '.' => (0x34, false), '>' => (0x34, true),
        '/' => (0x35, false), '?' => (0x35, true),
        ' ' => (0x39, false),
        '\t' => (0x0F, false),
        _ => return None,
    })
}

#[derive(Clone, Copy)]
struct Rect { x: i32, y: i32, w: u32, h: u32 }
impl Rect {
    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x as f64
            && y >= self.y as f64
            && x < self.x as f64 + self.w as f64
            && y < self.y as f64 + self.h as f64
    }
}
struct Layout {
    text_field: Rect,
    send: Rect,
    cancel: Rect,
}

fn layout(win_w: u32, win_h: u32) -> Layout {
    let cx = (win_w / 2) as i32;
    let cy = (win_h / 2) as i32;
    let card_x = cx - (CARD_W as i32) / 2;
    let card_y = cy - (CARD_H as i32) / 2;
    let tf_x = card_x + 24;
    let tf_y = card_y + 68;
    let tf_w = CARD_W - 48;
    let btn_y = card_y + CARD_H as i32 - BTN_H as i32 - 20;
    let cancel_x = card_x + CARD_W as i32 - BTN_W as i32 - 24;
    let send_x = cancel_x - BTN_W as i32 - 12;
    Layout {
        text_field: Rect { x: tf_x, y: tf_y, w: tf_w, h: TF_H },
        send: Rect { x: send_x, y: btn_y, w: BTN_W, h: BTN_H },
        cancel: Rect { x: cancel_x, y: btn_y, w: BTN_W, h: BTN_H },
    }
}

pub fn draw(buf: &mut [u32], w: u32, h: u32, font: Option<&TextRenderer>, overlay: &TypeTextOverlay) {
    for px in buf.iter_mut() {
        *px = 0x0020_2020;
    }
    let cx = (w / 2) as i32;
    let cy = (h / 2) as i32;
    let card_x = cx - (CARD_W as i32) / 2;
    let card_y = cy - (CARD_H as i32) / 2;
    fill_rect(buf, w, h, card_x, card_y, CARD_W, CARD_H, 0x002E_343C);
    stroke_rect(buf, w, h, card_x, card_y, CARD_W, CARD_H, 0x0050_5860);

    let title = t!("type.label");
    if let Some(f) = font {
        f.draw_centered(buf, w, h, (card_y + 40) as f32, &title, 0x00E4_EAF0, 20.0);
    } else {
        toolbar::draw_text_centered(buf, w, h, (card_y + 32) as u32, &title, 0x00E4_EAF0, 2);
    }

    let l = layout(w, h);
    // Text field (masked — treat every char as * for shoulder-surfing safety).
    let tf = l.text_field;
    fill_rect(buf, w, h, tf.x, tf.y, tf.w, tf.h, 0x001B_1E23);
    stroke_rect(buf, w, h, tf.x, tf.y, tf.w, tf.h, 0x0060_88B8);
    let masked: String = "•".repeat(overlay.input.chars().count());
    let placeholder = t!("type.placeholder");
    let show_placeholder = overlay.input.is_empty();
    let text = if show_placeholder { placeholder.as_ref() } else { masked.as_str() };
    let colour = if show_placeholder { 0x0070_7880 } else { 0x00E4_EAF0 };
    draw_left(buf, w, h, (tf.x + 10) as f32, (tf.y + 6) as f32, tf.h - 12, text, colour, 18.0, font);
    // Blinking caret at end of text.
    let ms = overlay.caret_anchor.elapsed().as_millis();
    if (ms / 500) % 2 == 0 {
        let text_w = if overlay.input.is_empty() {
            0.0
        } else {
            font.map(|f| f.width(&masked, 18.0)).unwrap_or(masked.chars().count() as f32 * 8.0)
        };
        fill_rect(buf, w, h, (tf.x as f32 + 10.0 + text_w) as i32, tf.y + 8, 2, (tf.h - 16).max(1), 0x00E4_EAF0);
    }

    // Send + Cancel buttons.
    let send_label = t!("type.send");
    let cancel_label = t!("type.cancel");
    draw_button(buf, w, h, l.send, &send_label, 0x0038_5A8C, 0x00FF_FFFF, font);
    draw_button(buf, w, h, l.cancel, &cancel_label, 0x003A_4048, 0x00E4_EAF0, font);
}

fn draw_button(buf: &mut [u32], w: u32, h: u32, r: Rect, label: &str, fill: u32, fg: u32, font: Option<&TextRenderer>) {
    fill_rect(buf, w, h, r.x, r.y, r.w, r.h, fill);
    stroke_rect(buf, w, h, r.x, r.y, r.w, r.h, 0x0050_5860);
    let text_w = font.map(|f| f.width(label, 16.0)).unwrap_or(label.chars().count() as f32 * 8.0);
    let tx = r.x as f32 + (r.w as f32 - text_w) / 2.0;
    draw_left(buf, w, h, tx, r.y as f32 + 4.0, r.h - 8, label, fg, 16.0, font);
}

fn draw_left(buf: &mut [u32], w: u32, h: u32, x: f32, band_top: f32, band_h: u32, s: &str, color: u32, px: f32, font: Option<&TextRenderer>) {
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
        for px in x0..x1 { buf[row + px as usize] = color; }
    }
}

fn stroke_rect(buf: &mut [u32], w: u32, h: u32, x: i32, y: i32, rw: u32, rh: u32, color: u32) {
    let w_i = w as i32;
    let h_i = h as i32;
    for i in 0..rw as i32 {
        let px = x + i;
        if px < 0 || px >= w_i { continue; }
        for &py in &[y, y + rh as i32 - 1] {
            if py < 0 || py >= h_i { continue; }
            buf[(py * w_i + px) as usize] = color;
        }
    }
    for i in 0..rh as i32 {
        let py = y + i;
        if py < 0 || py >= h_i { continue; }
        for &px in &[x, x + rw as i32 - 1] {
            if px < 0 || px >= w_i { continue; }
            buf[(py * w_i + px) as usize] = color;
        }
    }
}
