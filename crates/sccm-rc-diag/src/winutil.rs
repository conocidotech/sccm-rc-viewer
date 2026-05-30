//! Small Win32 helpers shared by checks.

use windows::core::PCWSTR;

/// Convert a Rust string to a null-terminated UTF-16 buffer suitable
/// for passing to Win32 wide-string APIs. The returned `Vec` MUST
/// outlive any `PCWSTR` derived from it.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build the `\\HOST` UNC target string used by SCM / LSA / NetLocalGroup
/// remote APIs. For an empty/`"localhost"` host, returns an empty buffer
/// (with a null terminator) — most APIs interpret that as "local machine".
pub fn unc_target(host: &str) -> Vec<u16> {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("localhost")
        || trimmed == "127.0.0.1"
        || trimmed == "::1"
    {
        to_wide("")
    } else {
        to_wide(&format!(r"\\{}", trimmed))
    }
}

pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}

/// Read a null-terminated UTF-16 string at the given pointer.
///
/// # Safety
/// The pointer must point to a valid null-terminated UTF-16 sequence,
/// and the memory must remain valid for the duration of the call.
pub unsafe fn read_wide_nul(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller asserts ptr is a valid, null-terminated UTF-16 sequence.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}
