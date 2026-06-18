//! Minimal pcapng parser tailored to our need: reconstruct the first N bytes
//! of the client→server and server→client TCP/2701 byte-streams so we can
//! diff against what our own probe sends.
//!
//! Not a general pcapng library — handles just enough block types to walk
//! Enhanced Packet Blocks (type 0x00000006) and Simple Packet Blocks, parse
//! Ethernet/IPv4/TCP headers, and bucket payloads by direction.
//!
//! Usage: pcap-extract <file.pcapng> [--server-ip 10.0.0.10] [--port 2701]

// Offline RE/diagnostic tool: some parser helpers are kept for ad-hoc use.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;

/// A single TCP segment carrying payload, with capture timestamp + direction.
struct Seg {
    ts: u64, // raw pktmon timestamp (hi<<32 | lo)
    client_port: u16,
    to_server: bool,
    seq: u32,
    payload: Vec<u8>,
}

fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn rd_u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Default)]
struct Stream {
    // seq -> payload, so we can reassemble in order even if packets arrive
    // out of order in the capture.
    segments: BTreeMap<u32, Vec<u8>>,
}

impl Stream {
    fn reassemble(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for data in self.segments.values() {
            out.extend_from_slice(data);
        }
        out
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: pcap-extract <file.pcapng> [--server-ip A.B.C.D] [--port N]");
        std::process::exit(2);
    }
    let path = &args[1];
    let mut server_ip = [10u8, 25, 40, 2];
    let mut port: u16 = 2701;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--server-ip" => {
                let parts: Vec<u8> = args[i + 1].split('.').map(|s| s.parse().unwrap()).collect();
                server_ip.copy_from_slice(&parts[..4]);
                i += 2;
            }
            "--port" => {
                port = args[i + 1].parse().unwrap();
                i += 2;
            }
            _ => i += 1,
        }
    }

    let data = fs::read(path).expect("read pcapng");
    let mut off = 0usize;

    let mut segs: Vec<Seg> = Vec::new();
    let mut pkt_count = 0u64;

    while off + 8 <= data.len() {
        let block_type = rd_u32le(&data, off);
        let block_len = rd_u32le(&data, off + 4) as usize;
        if block_len < 12 || off + block_len > data.len() {
            break;
        }

        let (pkt, ts) = if block_type == 0x06 {
            let ts_hi = rd_u32le(&data, off + 12) as u64;
            let ts_lo = rd_u32le(&data, off + 16) as u64;
            let cap_len = rd_u32le(&data, off + 20) as usize;
            let pkt_off = off + 28;
            if pkt_off + cap_len <= data.len() {
                (
                    Some(&data[pkt_off..pkt_off + cap_len]),
                    (ts_hi << 32) | ts_lo,
                )
            } else {
                (None, 0)
            }
        } else {
            (None, 0)
        };

        if let Some(p) = pkt {
            if let Some(seg) = parse_segment(p, &server_ip, port, ts) {
                segs.push(seg);
            }
            pkt_count += 1;
        }

        off += (block_len + 3) & !3; // 4-byte aligned
    }

    // Group by connection (client port), preserve discovery order.
    let mut conn_order: Vec<u16> = Vec::new();
    for s in &segs {
        if !conn_order.contains(&s.client_port) {
            conn_order.push(s.client_port);
        }
    }

    eprintln!(
        "parsed {pkt_count} packets, {} payload segments across {} connection(s)",
        segs.len(),
        conn_order.len()
    );

    for (idx, &cport) in conn_order.iter().enumerate() {
        let mut conn_segs: Vec<&Seg> = segs.iter().filter(|s| s.client_port == cport).collect();
        conn_segs.sort_by_key(|s| s.ts);

        let c2s_total: usize = conn_segs
            .iter()
            .filter(|s| s.to_server)
            .map(|s| s.payload.len())
            .sum();
        let s2c_total: usize = conn_segs
            .iter()
            .filter(|s| !s.to_server)
            .map(|s| s.payload.len())
            .sum();

        println!("\n\n================================================================");
        println!("=== CONNECTION {idx}  (client port {cport})  c2s={c2s_total} s2c={s2c_total} bytes ===");
        println!("================================================================");

        // Reassemble each direction's framed stream by seq, then walk frames.
        // This handles message-spanning segments + retransmits cleanly.
        let mut c2s_map: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let mut s2c_map: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for s in &conn_segs {
            let m = if s.to_server {
                &mut c2s_map
            } else {
                &mut s2c_map
            };
            m.entry(s.seq).or_insert_with(|| s.payload.clone());
        }
        let c2s: Vec<u8> = c2s_map.values().flatten().copied().collect();
        let s2c: Vec<u8> = s2c_map.values().flatten().copied().collect();

        if std::env::var("TIMELINE").is_ok() {
            dump_timeline_timed(&conn_segs);
        } else {
            dump_framed("CLIENT → SERVER", &c2s);
            dump_framed("SERVER → CLIENT", &s2c);
        }
    }
}

/// Timestamp-ordered frame timeline. Streams segments in time order,
/// maintaining a per-direction rolling buffer, and emits each SCCM frame
/// tagged with the timestamp at which it completed. Merges both directions.
fn dump_timeline_timed(segs: &[&Seg]) {
    // Dedupe: pktmon records each packet at multiple stack layers. Keep one
    // segment per (direction, seq, len).
    let mut seen = std::collections::HashSet::new();
    let mut ordered: Vec<&Seg> = segs
        .iter()
        .filter(|s| seen.insert((s.to_server, s.seq, s.payload.len())))
        .copied()
        .collect();
    ordered.sort_by_key(|s| s.ts);
    let t0 = ordered.first().map(|s| s.ts).unwrap_or(0);

    let mut c_buf: Vec<u8> = Vec::new();
    let mut s_buf: Vec<u8> = Vec::new();
    // (ms, dir, type, len)
    let mut events: Vec<(f64, char, u8, usize)> = Vec::new();

    for seg in &ordered {
        let ms = (seg.ts.saturating_sub(t0)) as f64 / 1000.0; // pktmon ts is microseconds
        let (buf, dir) = if seg.to_server {
            (&mut c_buf, 'C')
        } else {
            (&mut s_buf, 'S')
        };
        buf.extend_from_slice(&seg.payload);
        loop {
            if buf.len() < 4 {
                break;
            }
            let hdr = rd_u32le(buf, 0);
            let body_len = (hdr & 0x00ff_ffff) as usize;
            let msg_type = (hdr >> 24) as u8;
            if body_len == 0 || 4 + body_len > buf.len() {
                break;
            }
            events.push((ms, dir, msg_type, body_len));
            buf.drain(..4 + body_len);
        }
    }

    // Find first large server frame (graphics).
    let mut first_big = None;
    for (i, (_ms, dir, _t, l)) in events.iter().enumerate() {
        if *dir == 'S' && *l > 300 {
            first_big = Some(i);
            break;
        }
    }
    let full = std::env::var("TIMELINE_ALL").is_ok();
    let window_start = if full {
        0
    } else {
        first_big.map(|i| i.saturating_sub(25)).unwrap_or(0)
    };
    let window_end = if full {
        events.len()
    } else {
        first_big.map(|i| i + 8).unwrap_or(events.len())
    };
    println!("\n--- timeline around graphics start (deduped) ---");
    for (i, (ms, dir, t, l)) in events.iter().enumerate() {
        if i >= window_start && i <= window_end {
            let mark = if Some(i) == first_big {
                "  <== FIRST GRAPHICS"
            } else {
                ""
            };
            println!("  [{i:3}] {ms:9.1}ms  {dir}->  type=0x{t:02x} len={l}{mark}");
        }
    }
    println!(
        "\ntotal frames: {} (first graphics at index {:?})",
        events.len(),
        first_big
    );
}

/// Compact per-frame timeline: walk both directions' framed streams and print
/// one line per SCCM frame (direction, type, body_len). Encrypted bodies, so we
/// only see sizes — enough to spot when the server starts streaming graphics
/// (large S->C frames) and which client frames precede it.
fn dump_timeline(c2s: &[u8], s2c: &[u8]) {
    fn frames(stream: &[u8]) -> Vec<(u8, usize)> {
        let mut v = Vec::new();
        let mut off = 0;
        while off + 4 <= stream.len() {
            let hdr = rd_u32le(stream, off);
            let body_len = (hdr & 0x00ff_ffff) as usize;
            let msg_type = (hdr >> 24) as u8;
            if body_len == 0 || off + 4 + body_len > stream.len() {
                break;
            }
            v.push((msg_type, body_len));
            off += 4 + body_len;
        }
        v
    }
    let c = frames(c2s);
    let s = frames(s2c);
    println!("\n--- CLIENT→SERVER frames ({}) ---", c.len());
    for (i, (t, l)) in c.iter().enumerate() {
        println!("  c[{i:3}] type=0x{t:02x} len={l}");
        if i > 60 {
            println!("  … (+{} more)", c.len() - i - 1);
            break;
        }
    }
    println!("\n--- SERVER→CLIENT frames ({}) ---", s.len());
    let mut big_first = None;
    for (i, (t, l)) in s.iter().enumerate() {
        let big = *l > 300;
        if big && big_first.is_none() {
            big_first = Some(i);
        }
        if i <= 60 || big {
            println!(
                "  s[{i:3}] type=0x{t:02x} len={l}{}",
                if big { "   <== large (graphics?)" } else { "" }
            );
        }
        if i > 60 && big_first.is_some() && i > big_first.unwrap() + 3 {
            println!("  … (server streaming; stop)");
            break;
        }
    }
}

fn peek_and_dump(payload: &[u8]) {
    if payload.len() >= 4 {
        let hdr = rd_u32le(payload, 0);
        let body_len = (hdr & 0x00ff_ffff) as usize;
        let msg_type = (hdr >> 24) as u8;
        let kind = match msg_type {
            0x80 => "CONTROL",
            0x00 => "DATA",
            _ => "?",
        };
        let mut note = String::new();
        if msg_type == 0x80 && payload.len() >= 6 {
            let slen = rd_u16le(payload, 4) as usize;
            if 6 + slen <= payload.len() {
                let utf16: Vec<u16> = payload[6..6 + slen]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .collect();
                note = format!(
                    "  \"{}\"",
                    String::from_utf16_lossy(&utf16).trim_end_matches('\u{0}')
                );
            }
        }
        println!(
            "    [{} bytes] hdr=0x{hdr:08x} type=0x{msg_type:02x} {kind} body_len={body_len}{note}",
            payload.len()
        );
    } else {
        println!("    [{} bytes] (short)", payload.len());
    }
    hexdump(payload, 80);
}

fn parse_segment(pkt: &[u8], server_ip: &[u8; 4], port: u16, ts: u64) -> Option<Seg> {
    // pktmon ETL→pcap output is typically raw Ethernet. Detect IPv4.
    if pkt.len() < 14 {
        return None;
    }
    let ethertype = rd_u16be(pkt, 12);
    let ip_off = if ethertype == 0x0800 {
        14
    } else if ethertype == 0x8100 {
        18
    } else {
        return None;
    };
    if pkt.len() < ip_off + 20 {
        return None;
    }
    let ip = &pkt[ip_off..];
    if (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip[9] != 6 {
        return None; // not TCP
    }
    let src_ip = [ip[12], ip[13], ip[14], ip[15]];
    let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
    let total_len = rd_u16be(ip, 2) as usize;
    let tcp_off = ip_off + ihl;
    if pkt.len() < tcp_off + 20 {
        return None;
    }
    let tcp = &pkt[tcp_off..];
    let src_port = rd_u16be(tcp, 0);
    let dst_port = rd_u16be(tcp, 2);
    let seq = rd_u32be(tcp, 4);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    let payload_start = tcp_off + data_off;
    let ip_end = ip_off + total_len;
    if ip_end <= payload_start || ip_end > pkt.len() {
        return None;
    }
    let payload = &pkt[payload_start..ip_end];
    if payload.is_empty() {
        return None;
    }

    let to_server = dst_ip == *server_ip && dst_port == port;
    let from_server = src_ip == *server_ip && src_port == port;
    if to_server {
        Some(Seg {
            ts,
            client_port: src_port,
            to_server: true,
            seq,
            payload: payload.to_vec(),
        })
    } else if from_server {
        Some(Seg {
            ts,
            client_port: dst_port,
            to_server: false,
            seq,
            payload: payload.to_vec(),
        })
    } else {
        None
    }
}

/// Walk the reassembled stream as SCCM-framed messages (u32 LE header where
/// high byte = type, low 24 bits = body length) and dump each.
fn dump_framed(label: &str, stream: &[u8]) {
    println!("\n######## {label} ({} bytes total) ########", stream.len());
    let mut off = 0usize;
    let mut msg_idx = 0;
    while off + 4 <= stream.len() {
        let hdr = rd_u32le(stream, off);
        let body_len = (hdr & 0x00ff_ffff) as usize;
        let msg_type = (hdr >> 24) as u8;
        let body_off = off + 4;
        if body_len == 0 || body_off + body_len > stream.len() {
            println!(
                "\n-- msg {msg_idx}: header=0x{hdr:08x} type=0x{msg_type:02x} body_len={body_len} \
                 (stop — {} bytes left)",
                stream.len() - body_off
            );
            break;
        }
        let body = &stream[body_off..body_off + body_len];
        let kind = match msg_type {
            0x80 => "CONTROL(utf16)",
            0x00 => "DATA/SSPI",
            _ => "OTHER",
        };
        print!("\n-- msg {msg_idx}: type=0x{msg_type:02x} {kind} body_len={body_len}");
        if msg_type == 0x80 && body.len() >= 2 {
            let slen = rd_u16le(body, 0) as usize;
            if 2 + slen <= body.len() {
                let utf16: Vec<u16> = body[2..2 + slen]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .collect();
                print!(
                    "  string=\"{}\"",
                    String::from_utf16_lossy(&utf16).trim_end_matches('\u{0}')
                );
            }
        }
        // Annotate SPNEGO / Kerberos structures + decode SecFilter sub-framing
        let mut full_dump = false;
        if msg_type == 0x00 {
            if body.len() >= 2 && (body[0] == 0xb9 || body[1] == 0x00 && body[0] > 0x80) {
                // inner-len framed handshake token: [u16 len][token]
            }
            if body.first() == Some(&0x60) {
                print!("  [SPNEGO NegTokenInit / GSS — AP-REQ]");
            } else if body.len() >= 3 && body[1] == 0x81 && body[0] == 0xb9 {
                print!("  [inner-framed]");
            } else if body.len() >= 4 {
                // SecFilter data: [u16 lenA][A][u16 lenB][B]
                let len_a = u16::from_le_bytes([body[0], body[1]]) as usize;
                if 2 + len_a + 2 <= body.len() {
                    let off_b = 2 + len_a;
                    let len_b = u16::from_le_bytes([body[off_b], body[off_b + 1]]) as usize;
                    print!("  [SecFilter: lenA={len_a} lenB={len_b}");
                    let b_start = off_b + 2;
                    if b_start + 4 <= body.len()
                        && body[b_start] == 0x05
                        && body[b_start + 1] == 0x04
                    {
                        print!(" B=GSS-wrap-token(flags=0x{:02x})", body[b_start + 2]);
                    }
                    print!("]");
                    full_dump = true;
                }
            }
        }
        println!();
        hexdump(body, if full_dump { 160 } else { 64 });
        off = body_off + body_len;
        msg_idx += 1;
        if msg_idx > 12 {
            println!("\n… (stopping after 12 messages — rest is data phase)");
            break;
        }
    }
}

fn hexdump(bytes: &[u8], max: usize) {
    let n = bytes.len().min(max);
    for (i, chunk) in bytes[..n].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("   {:04x}  {:<48}  {ascii}", i * 16, hex.join(" "));
    }
    if bytes.len() > max {
        println!("   … (+{} more bytes)", bytes.len() - max);
    }
}
