//! Low-level keyboard hook (`WH_KEYBOARD_LL`) so the viewer can forward the
//! Windows key — and the Ctrl+Esc local-Start shortcut — to the remote without
//! the OS opening the LOCAL Start menu. winit/our app-level handler never
//! sees these keystrokes because USER32 dispatches them at a lower layer; the
//! only way to suppress them is from inside a system-wide LL hook.
//!
//! The hook is installed once at startup, runs in our message-loop thread, and
//! is gated on `ACTIVE` (set true when the viewer window has focus). When
//! active it intercepts:
//!   - VK_LWIN / VK_RWIN  (KEYDOWN + KEYUP — paired so Win never sticks down)
//!   - Ctrl+Esc           (KEYDOWN — translated to a Win-key tap)
//! and forwards them to the remote via the shared input channel, returning 1
//! to swallow the local event.

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};

use sccm_rc_core::rdp::{FastPathInputEvent, KeyboardFlags};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VK_CONTROL, VK_ESCAPE, VK_LWIN, VK_RWIN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, SetWindowsHookExW, HHOOK, KBDLLHOOKSTRUCT, WH_KEYBOARD_LL, WM_KEYDOWN,
    WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

static HOOK: AtomicIsize = AtomicIsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Current input channel — replaced on every reconnect via `set_tx`. The hook
/// callback runs in arbitrary OS threads, so the cell is a `Mutex` rather
/// than an `OnceLock`. None means "no session active; swallow Win events but
/// don't forward anything" — preferable to leaving the local Start menu
/// reachable while we wait for a new session.
static INPUT_TX: OnceLock<Mutex<Option<Sender<Vec<FastPathInputEvent>>>>> = OnceLock::new();

fn tx_cell() -> &'static Mutex<Option<Sender<Vec<FastPathInputEvent>>>> {
    INPUT_TX.get_or_init(|| Mutex::new(None))
}

/// Install the LL keyboard hook and register the initial input channel.
/// Idempotent. Errors are logged and swallowed — the viewer still works, the
/// toolbar Win button stays functional, only the OS-level capture is lost.
pub fn install(tx: Sender<Vec<FastPathInputEvent>>) {
    *tx_cell().lock().unwrap() = Some(tx);
    if HOOK.load(Ordering::Relaxed) != 0 {
        return;
    }
    unsafe {
        match SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(hook_proc),
            Some(HINSTANCE(std::ptr::null_mut())),
            0,
        ) {
            Ok(h) => {
                HOOK.store(h.0 as isize, Ordering::Relaxed);
                info!("WH_KEYBOARD_LL installed for Win-key passthrough");
            }
            Err(e) => warn!(error = %e, "could not install WH_KEYBOARD_LL hook"),
        }
    }
}

/// Replace the input channel — call after every reconnect (or with None when
/// the session ends). Without this the hook keeps trying to send on a closed
/// channel and Win-key silently stops working after the first disconnect.
pub fn set_tx(tx: Option<Sender<Vec<FastPathInputEvent>>>) {
    *tx_cell().lock().unwrap() = tx;
}

/// Mark the hook active (viewer window has focus) or inactive. While inactive
/// every keystroke is forwarded to the next hook unchanged.
pub fn set_active(active: bool) {
    ACTIVE.store(active, Ordering::Relaxed);
}

fn send(events: Vec<FastPathInputEvent>) {
    // Use try_lock — the hook runs in the OS message-pump thread, and a
    // blocking acquire here would freeze the entire UI if anything else
    // is currently holding the mutex (set_tx during a reconnect, etc.).
    // Dropping a Win-keystroke once in a blue moon is strictly preferable
    // to deadlocking the whole viewer.
    let Some(cell) = INPUT_TX.get() else {
        return;
    };
    let Ok(guard) = cell.try_lock() else {
        return;
    };
    if let Some(tx) = guard.as_ref() {
        let _ = tx.try_send(events);
    }
}

fn forward_win_down() {
    send(vec![FastPathInputEvent::KeyboardEvent(
        KeyboardFlags::EXTENDED,
        0x5B,
    )]);
}

fn forward_win_up() {
    send(vec![FastPathInputEvent::KeyboardEvent(
        KeyboardFlags::EXTENDED | KeyboardFlags::RELEASE,
        0x5B,
    )]);
}

fn forward_win_tap() {
    let ext = KeyboardFlags::EXTENDED;
    let up = KeyboardFlags::RELEASE;
    send(vec![
        FastPathInputEvent::KeyboardEvent(ext, 0x5B),
        FastPathInputEvent::KeyboardEvent(ext | up, 0x5B),
    ]);
}

unsafe extern "system" fn hook_proc(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
    if code < 0 || !ACTIVE.load(Ordering::Relaxed) {
        return CallNextHookEx(Some(HHOOK(std::ptr::null_mut())), code, w, l);
    }
    let kb = unsafe { &*(l.0 as *const KBDLLHOOKSTRUCT) };
    let msg = w.0 as u32;
    let is_down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
    let is_up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
    if !is_down && !is_up {
        return unsafe { CallNextHookEx(Some(HHOOK(std::ptr::null_mut())), code, w, l) };
    }

    let vk = kb.vkCode;
    let is_win = vk == VK_LWIN.0 as u32 || vk == VK_RWIN.0 as u32;
    let ctrl_held = unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) as u16 & 0x8000 != 0 };
    let is_ctrl_esc = vk == VK_ESCAPE.0 as u32 && ctrl_held;

    if is_win {
        if is_down {
            forward_win_down();
        } else {
            forward_win_up();
        }
        return LRESULT(1); // swallow — keep local OS out of it
    }
    if is_ctrl_esc {
        if is_down {
            forward_win_tap();
        }
        return LRESULT(1);
    }
    unsafe { CallNextHookEx(Some(HHOOK(std::ptr::null_mut())), code, w, l) }
}
