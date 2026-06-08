//! Wake-on-LAN: send a magic packet, plus a best-effort host→MAC cache populated
//! from the ARP table after a successful connect (so a later attempt to a powered-
//! off host can wake it). Cache: `%LOCALAPPDATA%\sccm-rc\macs.txt` (`host=MAC`).

use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};

/// Parse a MAC like `AA-BB-CC-DD-EE-FF` / `aa:bb:...` / `aabbccddeeff`.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

pub fn fmt_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Send the Wake-on-LAN magic packet (6×0xFF + 16×MAC) as a UDP broadcast on the
/// usual WoL ports (9 and 7).
pub fn send(mac: [u8; 6]) -> std::io::Result<()> {
    let mut pkt = vec![0xFFu8; 6];
    for _ in 0..16 {
        pkt.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    for port in [9u16, 7] {
        let _ = sock.send_to(&pkt, ("255.255.255.255", port));
    }
    Ok(())
}

fn cache_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("sccm-rc");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("macs.txt")
}

pub fn cached_mac(host: &str) -> Option<[u8; 6]> {
    let data = std::fs::read_to_string(cache_path()).ok()?;
    for line in data.lines() {
        if let Some((h, m)) = line.split_once('=') {
            if h.trim().eq_ignore_ascii_case(host.trim()) {
                return parse_mac(m);
            }
        }
    }
    None
}

pub fn cache_mac(host: &str, mac: [u8; 6]) {
    let host = host.trim();
    let mut lines: Vec<String> = std::fs::read_to_string(cache_path())
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            l.split_once('=')
                .map(|(h, _)| !h.trim().eq_ignore_ascii_case(host))
                .unwrap_or(false)
        })
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{host}={}", fmt_mac(mac)));
    if let Ok(mut f) = std::fs::File::create(cache_path()) {
        let _ = f.write_all(lines.join("\r\n").as_bytes());
    }
}

/// Resolve `host` to an IP and, if it's in the ARP table (i.e. reachable / just
/// contacted), cache its MAC for future Wake-on-LAN. Best-effort, never errors.
pub fn lookup_and_cache(host: &str) {
    let Some(addr) = (host, 2701u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.find(|a| a.is_ipv4()))
    else {
        return;
    };
    let ip = addr.ip().to_string();
    use std::os::windows::process::CommandExt;
    let Ok(out) = std::process::Command::new("arp")
        .creation_flags(0x0800_0000)
        .args(["-a", &ip])
        .output()
    else {
        return;
    };
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if !line.contains(&ip) {
            continue;
        }
        if let Some(mac) = line.split_whitespace().find_map(|t| {
            if t.matches('-').count() == 5 {
                parse_mac(t)
            } else {
                None
            }
        }) {
            cache_mac(host, mac);
            return;
        }
    }
}
