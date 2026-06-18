//! Build script:
//! 1. Embeds the short git commit hash as the `GIT_HASH` env var so `--version`
//!    (and the window title) show exactly which build is running.
//! 2. On Windows, compiles a VERSIONINFO + icon resource with `windres` and links
//!    it into the binary, so Explorer's Properties → Details tab is populated and
//!    the .exe carries an application icon. Done manually (not via winresource)
//!    because that crate's link step is unreliable on the windows-gnu toolchain.

use std::process::Command;

fn main() {
    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={hash}");
    // Re-run when HEAD moves so the hash stays current (best-effort).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");

    #[cfg(windows)]
    embed_win_resource();
}

/// Compile `assets/app.ico` + a VERSIONINFO block into a COFF object via `windres`
/// and link it. Warns (does not fail) if `windres` is unavailable, so the build
/// still produces a working — if icon-less — binary.
#[cfg(windows)]
fn embed_win_resource() {
    use std::io::Write;
    use std::path::Path;

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let ico = format!("{manifest}/assets/app.ico").replace('\\', "/");
    println!("cargo:rerun-if-changed=assets/app.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if !Path::new(&ico).exists() {
        println!("cargo:warning=app.ico not found at {ico}; skipping icon/version resource");
        return;
    }

    // CARGO_PKG_VERSION (e.g. "0.9.3") → "0,9,3,0" for the binary FILEVERSION field.
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let mut parts: Vec<&str> = ver.split(['.', '-', '+']).collect();
    parts.resize(4, "0");
    let quad: Vec<&str> = parts
        .iter()
        .take(4)
        .map(|p| if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() { *p } else { "0" })
        .collect();
    let fileversion = quad.join(",");

    let rc = format!(
        "1 ICON \"{ico}\"\n\
         1 VERSIONINFO\n\
         FILEVERSION {fv}\n\
         PRODUCTVERSION {fv}\n\
         FILEOS 0x40004L\n\
         FILETYPE 0x1L\n\
         BEGIN\n\
           BLOCK \"StringFileInfo\"\n\
           BEGIN\n\
             BLOCK \"040904b0\"\n\
             BEGIN\n\
               VALUE \"CompanyName\", \"conocidotech\"\n\
               VALUE \"FileDescription\", \"SCCM Remote Control viewer (pure Rust, independent reimplementation)\"\n\
               VALUE \"FileVersion\", \"{ver}\"\n\
               VALUE \"InternalName\", \"sccm-rc-viewer\"\n\
               VALUE \"LegalCopyright\", \"MIT OR Apache-2.0\"\n\
               VALUE \"OriginalFilename\", \"sccm-rc-viewer.exe\"\n\
               VALUE \"ProductName\", \"sccm-rc\"\n\
               VALUE \"ProductVersion\", \"{ver}\"\n\
             END\n\
           END\n\
           BLOCK \"VarFileInfo\"\n\
           BEGIN\n\
             VALUE \"Translation\", 0x409, 1200\n\
           END\n\
         END\n",
        ico = ico,
        fv = fileversion,
        ver = ver,
    );

    let rc_path = format!("{out_dir}/app.rc");
    let obj_path = format!("{out_dir}/app-resource.o");
    if let Err(e) = std::fs::File::create(&rc_path).and_then(|mut f| f.write_all(rc.as_bytes())) {
        println!("cargo:warning=could not write {rc_path}: {e}");
        return;
    }

    match Command::new("windres")
        .args(["-O", "coff", &rc_path, &obj_path])
        .status()
    {
        Ok(s) if s.success() => {
            // Link the compiled resource object into the binary.
            println!("cargo:rustc-link-arg-bins={obj_path}");
        }
        Ok(s) => println!("cargo:warning=windres exited with {s}; no icon/version resource"),
        Err(e) => println!("cargo:warning=windres not found ({e}); no icon/version resource"),
    }
}
