//! Overlay toolbar/status bar drawn into the softbuffer at the top of the
//! window. Self-contained immediate-mode UI: a status line on the left and a
//! row of clickable buttons on the right, rendered with an embedded 8x8 font.

use crate::text::TextRenderer;
use font8x8::UnicodeFonts;
use rust_i18n::t;

/// Height of the toolbar strip in pixels. The remote desktop renders below it.
pub const TOOLBAR_H: u32 = 30;
/// Pixel size for the proportional toolbar font.
const FONT_PX: f32 = 15.0;

/// Width of `s` in the toolbar font (proportional if available, else 8px/char).
fn measure(font: Option<&TextRenderer>, s: &str) -> u32 {
    match font {
        Some(f) => f.width(s, FONT_PX).ceil() as u32,
        None => s.chars().count() as u32 * 8,
    }
}

/// Draw `s` vertically centered in the toolbar band at `x` (proportional font
/// if available, else the 8x8 bitmap fallback).
fn put_text(buf: &mut [u32], win_w: u32, win_h: u32, x: u32, s: &str, color: u32, font: Option<&TextRenderer>) {
    match font {
        Some(f) => f.draw_vcenter(buf, win_w, win_h, x as f32, 0.0, TOOLBAR_H as f32, s, color, FONT_PX),
        None => draw_text(buf, win_w, win_h, x, (TOOLBAR_H - 8) / 2, s, color),
    }
}

const BAR_BG: u32 = 0x002D_2D30;
const TEXT: u32 = 0x00E0_E0E0;
const TEXT_DIM: u32 = 0x0090_9098;
const BTN_BG: u32 = 0x003E_3E42;
const BTN_TEXT: u32 = 0x00F0_F0F0;
const ACCENT_OK: u32 = 0x0040_C040;
const ACCENT_BUSY: u32 = 0x00D0_A030;
const REC_RED: u32 = 0x00D0_3030;
const BTN_ACTIVE: u32 = 0x00305A8C;

/// A clickable toolbar action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolbarAction {
    CtrlAltDel,
    SendFile,
    ToggleCurtain,
    ToggleViewOnly,
    ToggleRecord,
    ToggleFullscreen,
    Disconnect,
}

/// Dynamic status shown on the left of the bar.
pub struct Status<'a> {
    pub host: &'a str,
    pub mode: &'a str,
    pub state: &'a str,
    pub connected: bool,
    pub fps: u32,
    pub bytes_per_sec: u64,
    pub recording: bool,
    pub curtain: bool,
    /// Transport-security summary (e.g. "Kerberos · versleuteld"). Empty hides it.
    pub security: &'a str,
    /// True = encrypted AND server verified (green lock); false = amber/red.
    pub secure: bool,
    /// True = the link is encrypted (red when false, amber when true-but-unverified)
    /// — drives the lock colour without string-matching the localized label.
    pub encrypted: bool,
    /// True = view-only mode — drives the View-Only button's active tint without
    /// string-matching the localized mode label.
    pub view_only: bool,
}

/// Human-readable bandwidth (e.g. "1.4 MB/s", "320 KB/s").
fn fmt_bw(bps: u64) -> String {
    if bps >= 1_048_576 {
        format!("{:.1} MB/s", bps as f64 / 1_048_576.0)
    } else if bps >= 1024 {
        format!("{} KB/s", bps / 1024)
    } else {
        format!("{bps} B/s")
    }
}

/// The buttons, right-to-left (rightmost first). Labels are resolved per-locale.
const BUTTONS: &[ToolbarAction] = &[
    ToolbarAction::Disconnect,
    ToolbarAction::ToggleFullscreen,
    ToolbarAction::ToggleRecord,
    ToolbarAction::ToggleViewOnly,
    ToolbarAction::ToggleCurtain,
    ToolbarAction::SendFile,
    ToolbarAction::CtrlAltDel,
];

/// Localized label for a toolbar button.
fn button_label(action: ToolbarAction) -> String {
    match action {
        ToolbarAction::Disconnect => t!("toolbar.disconnect"),
        ToolbarAction::ToggleFullscreen => t!("toolbar.fullscreen"),
        ToolbarAction::ToggleRecord => t!("toolbar.record"),
        ToolbarAction::ToggleViewOnly => t!("toolbar.view_only"),
        ToolbarAction::ToggleCurtain => t!("toolbar.curtain"),
        ToolbarAction::SendFile => t!("toolbar.send_file"),
        ToolbarAction::CtrlAltDel => t!("toolbar.ctrl_alt_del"),
    }
    .to_string()
}

const PAD: u32 = 11; // horizontal padding inside a button

/// Compute button rectangles `(action, x, y, w, h)` laid out from the right edge.
fn layout(win_w: u32, font: Option<&TextRenderer>) -> Vec<(ToolbarAction, u32, u32, u32, u32)> {
    let mut out = Vec::with_capacity(BUTTONS.len());
    let mut right = win_w.saturating_sub(4);
    for action in BUTTONS {
        let label = button_label(*action);
        let w = measure(font, &label) + PAD * 2;
        let x = right.saturating_sub(w);
        out.push((*action, x, 3, w, TOOLBAR_H - 6));
        right = x.saturating_sub(6);
    }
    out
}

/// Hit-test a window-space click against the toolbar buttons.
pub fn hit_test(x: f64, y: f64, win_w: u32, font: Option<&TextRenderer>) -> Option<ToolbarAction> {
    if y < 0.0 || y >= TOOLBAR_H as f64 {
        return None;
    }
    let (xi, yi) = (x as u32, y as u32);
    for (action, bx, by, bw, bh) in layout(win_w, font) {
        if xi >= bx && xi < bx + bw && yi >= by && yi < by + bh {
            return Some(action);
        }
    }
    None
}

/// Draw the toolbar over the top `TOOLBAR_H` rows of `buf`.
pub fn draw(buf: &mut [u32], win_w: u32, win_h: u32, status: &Status, font: Option<&TextRenderer>) {
    if win_h < TOOLBAR_H {
        return;
    }
    // Background strip.
    fill_rect(buf, win_w, win_h, 0, 0, win_w, TOOLBAR_H, BAR_BG);
    // Bottom hairline separator.
    fill_rect(buf, win_w, win_h, 0, TOOLBAR_H - 1, win_w, 1, 0x0020_2022);

    // Status line (left): a connection dot + "host  ·  mode  ·  state  ·  N fps".
    let dot = if status.connected { ACCENT_OK } else { ACCENT_BUSY };
    fill_rect(buf, win_w, win_h, 10, TOOLBAR_H / 2 - 4, 8, 8, dot);
    let text = format!(
        "{}   \u{00b7}   {}   \u{00b7}   {}   \u{00b7}   {} fps   \u{00b7}   {}",
        status.host,
        status.mode,
        status.state,
        status.fps,
        fmt_bw(status.bytes_per_sec)
    );
    put_text(buf, win_w, win_h, 26, &text, TEXT, font);
    let mut x_after = 26 + measure(font, &text) + 16;
    // Recording indicator: a red dot + "REC" after the status line.
    if status.recording {
        fill_rect(buf, win_w, win_h, x_after, TOOLBAR_H / 2 - 4, 8, 8, REC_RED);
        put_text(buf, win_w, win_h, x_after + 14, "REC", REC_RED, font);
        x_after += 14 + measure(font, "REC") + 18;
    }
    // Security indicator: a small coloured padlock + the encryption/auth summary.
    // Green = encrypted + server verified (Kerberos); amber = encrypted but
    // unverified (NTLM); red = not encrypted.
    if !status.security.is_empty() {
        let col = if status.secure {
            ACCENT_OK
        } else if !status.encrypted {
            REC_RED
        } else {
            ACCENT_BUSY
        };
        let cy = TOOLBAR_H / 2;
        fill_rect(buf, win_w, win_h, x_after, cy - 3, 9, 7, col); // padlock body
        fill_rect(buf, win_w, win_h, x_after + 2, cy - 6, 5, 3, col); // shackle
        put_text(buf, win_w, win_h, x_after + 15, status.security, col, font);
    }

    // Buttons (right). Active toggles are tinted; Record is red.
    let lay = layout(win_w, font);
    for (action, bx, by, bw, bh) in &lay {
        let active = (*action == ToolbarAction::ToggleCurtain && status.curtain)
            || (*action == ToolbarAction::ToggleViewOnly && status.view_only);
        let bg = if *action == ToolbarAction::ToggleRecord && status.recording {
            REC_RED
        } else if active {
            BTN_ACTIVE
        } else {
            BTN_BG
        };
        fill_rect(buf, win_w, win_h, *bx, *by, *bw, *bh, bg);
    }
    let _ = TEXT_DIM; // reserved for a future hover state
    for (action, (_, bx, _by, bw, _bh)) in BUTTONS.iter().zip(&lay) {
        let label = button_label(*action);
        let tx = bx + (bw.saturating_sub(measure(font, &label))) / 2;
        put_text(buf, win_w, win_h, tx, &label, BTN_TEXT, font);
    }
}

fn fill_rect(buf: &mut [u32], win_w: u32, win_h: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for yy in y..(y + h).min(win_h) {
        let row = (yy * win_w) as usize;
        for xx in x..(x + w).min(win_w) {
            buf[row + xx as usize] = color;
        }
    }
}

fn draw_text(buf: &mut [u32], win_w: u32, win_h: u32, x: u32, y: u32, s: &str, color: u32) {
    draw_text_scaled(buf, win_w, win_h, x, y, s, color, 1);
}

/// Draw `s` with the 8x8 font at integer `scale`.
pub fn draw_text_scaled(
    buf: &mut [u32],
    win_w: u32,
    win_h: u32,
    mut x: u32,
    y: u32,
    s: &str,
    color: u32,
    scale: u32,
) {
    for ch in s.chars() {
        if let Some(glyph) = font8x8::BASIC_FONTS.get(ch) {
            for (row, bits) in glyph.iter().enumerate() {
                for col in 0..8u32 {
                    if bits & (1 << col) == 0 {
                        continue;
                    }
                    for sy in 0..scale {
                        let py = y + row as u32 * scale + sy;
                        if py >= win_h {
                            continue;
                        }
                        for sx in 0..scale {
                            let px = x + col * scale + sx;
                            if px < win_w {
                                buf[(py * win_w + px) as usize] = color;
                            }
                        }
                    }
                }
            }
        }
        x += 8 * scale;
    }
}

/// Draw `s` horizontally centered at vertical position `y`, scaled.
pub fn draw_text_centered(buf: &mut [u32], win_w: u32, win_h: u32, y: u32, s: &str, color: u32, scale: u32) {
    let w = s.chars().count() as u32 * 8 * scale;
    let x = win_w.saturating_sub(w) / 2;
    draw_text_scaled(buf, win_w, win_h, x, y, s, color, scale);
}
