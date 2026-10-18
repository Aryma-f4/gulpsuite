//! Transform, diff, payload-marker and entropy primitives for the Gulpsuite engine.
//!
//! These live here rather than in the UI so there is exactly one implementation of each rule.
//! The UI drives them over the newline-delimited JSON protocol in `main.rs`.

use std::collections::BTreeMap;
/// One entry in the Decoder transform list.
pub struct Op {
    pub name: &'static str,
    pub run: fn(&str) -> Result<String, String>,
}

pub fn decoder_ops() -> Vec<Op> {
    vec![
        op("URL decode", |s| percent_decode(s, false)),
        op("URL encode", |s| percent_encode(s)),
        op("HTML decode", |s| html_decode(s)),
        op("HTML encode", |s| html_encode(s)),
        op("Base64 decode", |s| b64_decode(s, false)),
        op("Base64 encode", |s| b64_encode(s, false)),
        op("Base64 URL-safe decode", |s| b64_decode(s, true)),
        op("Base64 encode URL-safe", |s| b64_encode(s, true)),
        op("Base32 decode", |s| b32_decode(s)),
        op("Base32 encode", |s| Ok(b32_encode(s.as_bytes()))),
        op("Hex decode", |s| hex_decode(s)),
        op("Hex encode", |s| hex_encode(s)),
        op("ASCII decode", |s| ascii_decode(s)),
        op("Binary decode", |s| binary_decode(s)),
        op("Binary encode", |s| binary_encode(s)),
        op("Decimal decode", |s| decimal_decode(s, 10)),
        op("Octal decode", |s| decimal_decode(s, 8)),
        op("ROT13", |s| Ok(rot13(s))),
        op("Case transform: lower", |s| Ok(s.to_lowercase())),
        op("Case transform: upper", |s| Ok(s.to_uppercase())),
        op("Hash: MD5", |s| hash_input("Hash: MD5", s)),
        op("Hash: SHA-1", |s| hash_input("Hash: SHA-1", s)),
        op("Hash: SHA-256", |s| hash_input("Hash: SHA-256", s)),
    ]
}

fn op(name: &'static str, run: fn(&str) -> Result<String, String>) -> Op {
    Op { name, run }
}

pub fn find_op(name: &str) -> Option<Op> {
    decoder_ops().into_iter().find(|o| o.name == name)
}

// ---------------------------------------------------------------- base64 / base32

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b64_encode(input: &str, url_safe: bool) -> Result<String, String> {
    let alphabet = if url_safe { B64URL } else { B64 };
    let data = input.as_bytes();
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { alphabet[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { alphabet[n as usize & 63] as char } else { '=' });
    }
    Ok(out)
}

fn b64_decode(input: &str, url_safe: bool) -> Result<String, String> {
    let alphabet = if url_safe { B64URL } else { B64 };
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out: Vec<u8> = Vec::new();
    for c in input.bytes() {
        if c == b'=' || (c as char).is_whitespace() {
            continue;
        }
        let v = alphabet
            .iter()
            .position(|a| *a == c)
            .ok_or_else(|| format!("not base64: {}", c as char))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|e| format!("not UTF-8: {e}"))
}

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in data {
        acc = (acc << 8) | *byte as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn b32_decode(input: &str) -> Result<String, String> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out: Vec<u8> = Vec::new();
    for c in input.bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let v = B32
            .iter()
            .position(|a| *a == up)
            .ok_or_else(|| format!("not base32: {}", c as char))?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|e| format!("not UTF-8: {e}"))
}

// ---------------------------------------------------------------- url / html

fn percent_encode(s: &str) -> Result<String, String> {
    let mut out = String::new();
    for byte in s.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || "-_.*".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(out)
}

fn percent_decode(s: &str, plus_as_space: bool) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err("truncated percent escape".into());
                }
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "bad percent escape")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad percent escape")?);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| format!("not UTF-8: {e}"))
}

fn named_entity(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        _ => None,
    }
}

fn html_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let semi = s[i + 1..].find(';').map(|p| p + i + 1);
        let Some(semi) = semi.filter(|p| p - i <= 10) else {
            out.push('&');
            i += 1;
            continue;
        };
        let body = &s[i + 1..semi];
        let decoded = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(dec) = body.strip_prefix('#') {
            dec.parse::<u32>().ok().and_then(char::from_u32)
        } else {
            named_entity(body)
        };
        match decoded {
            Some(c) => {
                out.push(c);
                i = semi + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    Ok(out)
}

fn html_encode(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- numeric / text

fn hex_encode(s: &str) -> Result<String, String> {
    Ok(s.bytes().map(|b| format!("{b:02x}")).collect())
}

fn hex_decode(s: &str) -> Result<String, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = if cleaned.len() % 2 == 1 { format!("0{cleaned}") } else { cleaned };
    let bytes = (0..padded.len() / 2)
        .map(|i| u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).map_err(|_| "bad hex pair".to_string()))
        .collect::<Result<Vec<u8>, String>>()?;
    String::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))
}

fn binary_decode(s: &str) -> Result<String, String> {
    let cleaned: String = s.chars().filter(|c| *c == '0' || *c == '1').collect();
    if cleaned.is_empty() || cleaned.len() % 8 != 0 {
        return Err("binary input must be a multiple of 8 bits".into());
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(cleaned.len() / 8);
    for i in 0..cleaned.len() / 8 {
        bytes.push(u8::from_str_radix(&cleaned[i * 8..i * 8 + 8], 2).map_err(|e| e.to_string())?);
    }
    String::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))
}

fn binary_encode(s: &str) -> Result<String, String> {
    Ok(s.bytes().map(|b| format!("{b:08b}")).collect())
}

fn decimal_decode(s: &str, radix: u32) -> Result<String, String> {
    let mut out: Vec<u8> = Vec::new();
    for part in s.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if part.is_empty() {
            continue;
        }
        let text = if radix == 8 { part.strip_prefix('0').unwrap_or(part) } else { part };
        let v = u32::from_str_radix(text, radix).map_err(|_| format!("bad base-{radix} value: {part}"))?;
        if v > 255 {
            return Err(format!("value out of byte range: {part}"));
        }
        out.push(v as u8);
    }
    String::from_utf8(out).map_err(|e| format!("not UTF-8: {e}"))
}

fn ascii_decode(s: &str) -> Result<String, String> {
    Ok(s.bytes().map(|b| format!("{b:03}")).collect())
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (b'a' + ((c as u8 - b'a' + 13) % 26)) as char,
            'A'..='Z' => (b'A' + ((c as u8 - b'A' + 13) % 26)) as char,
            _ => c,
        })
        .collect()
}

/// Best-effort decode detection, tried in the order a person would.
pub fn magic_decode(input: &str) -> Option<&'static str> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    for candidate in decoder_ops() {
        if !candidate.name.ends_with("decode") || candidate.name.starts_with("Hash") {
            continue;
        }
        if candidate.name == "ASCII decode" {
            continue;
        }
        let Ok(out) = (candidate.run)(s) else { continue };
        if out.is_empty() || out == s {
            continue;
        }
        let printable = out.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t').count();
        if printable as f64 / out.chars().count() as f64 > 0.95 && looks_like_text(&out) {
            return Some(candidate.name);
        }
    }
    None
}

fn looks_like_text(s: &str) -> bool {
    let ok = |c: char| {
        c.is_alphanumeric()
            || " .,_-/=&?<>\"':;{}\n\r\t".contains(c)
    };
    let total = s.chars().count();
    total == 0 || s.chars().filter(|c| ok(*c)).count() as f64 / total as f64 > 0.9
}

// ---------------------------------------------------------------- hashes

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn md5_bytes(input: &[u8]) -> Vec<u8> {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let mut k = [0u32; 64];
    for (i, slot) in k.iter_mut().enumerate() {
        *slot = ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
    }
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | ((!b) & d), i),
                1 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    [a0, b0, c0, d0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

pub fn sha1_bytes(input: &[u8]) -> Vec<u8> {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            *slot = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | ((!b) & d), 0x5A827999u32),
                1 => (b ^ c ^ d, 0x6ED9EBA1),
                2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().flat_map(|w| w.to_be_bytes()).collect()
}

pub fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            *slot = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip(v) {
            *slot = slot.wrapping_add(value);
        }
    }
    h.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn hash_input(name: &str, s: &str) -> Result<String, String> {
    match name {
        "Hash: MD5" => Ok(hex(&md5_bytes(s.as_bytes()))),
        "Hash: SHA-1" => Ok(hex(&sha1_bytes(s.as_bytes()))),
        "Hash: SHA-256" => Ok(hex(&sha256_bytes(s.as_bytes()))),
        other => Err(format!("unknown hash: {other}")),
    }
}

// ---------------------------------------------------------------- diff

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DiffKind {
    Same,
    Added,
    Deleted,
    Modified,
}

impl DiffKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DiffKind::Same => "same",
            DiffKind::Added => "added",
            DiffKind::Deleted => "deleted",
            DiffKind::Modified => "modified",
        }
    }
}

#[derive(Clone)]
#[derive(Debug)]
pub struct DiffRow {
    pub kind: DiffKind,
    pub left: Option<String>,
    pub right: Option<String>,
}

/// Line diff: trim the common prefix/suffix, LCS the middle, then pair delete/insert runs.
///
/// ponytail: the LCS table is O(n*m); inputs are trimmed first and capped at MAX_CELLS.
const MAX_CELLS: usize = 4_000_000;

pub fn diff_lines(left: &str, right: &str) -> Vec<DiffRow> {
    let l: Vec<&str> = split_lines(left);
    let r: Vec<&str> = split_lines(right);

    let mut prefix = 0;
    while prefix < l.len() && prefix < r.len() && l[prefix] == r[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < l.len() - prefix && suffix < r.len() - prefix
        && l[l.len() - 1 - suffix] == r[r.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mut rows = Vec::new();
    for line in &l[..prefix] {
        rows.push(DiffRow { kind: DiffKind::Same, left: Some((*line).into()), right: Some((*line).into()) });
    }
    rows.extend(diff_middle(&l[prefix..l.len() - suffix], &r[prefix..r.len() - suffix]));
    for i in 0..suffix {
        rows.push(DiffRow {
            kind: DiffKind::Same,
            left: Some(l[l.len() - suffix + i].into()),
            right: Some(r[r.len() - suffix + i].into()),
        });
    }
    rows
}

fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = text
        .split("\r\n")
        .flat_map(|part| part.split('\n'))
        .collect();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

fn diff_middle(left: &[&str], right: &[&str]) -> Vec<DiffRow> {
    let mut raw: Vec<DiffRow> = Vec::new();
    if left.is_empty() && right.is_empty() {
        return raw;
    }
    if left.len().saturating_mul(right.len()) > MAX_CELLS {
        for line in left {
            raw.push(DiffRow { kind: DiffKind::Deleted, left: Some((*line).into()), right: None });
        }
        for line in right {
            raw.push(DiffRow { kind: DiffKind::Added, left: None, right: Some((*line).into()) });
        }
        return raw;
    }

    let mut table = vec![0u32; (left.len() + 1) * (right.len() + 1)];
    let at = |i: usize, j: usize| i * (right.len() + 1) + j;
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            table[at(i, j)] = if left[i] == right[j] {
                table[at(i + 1, j + 1)] + 1
            } else {
                table[at(i + 1, j)].max(table[at(i, j + 1)])
            };
        }
    }

    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            raw.push(DiffRow {
                kind: DiffKind::Same,
                left: Some(left[i].into()),
                right: Some(right[j].into()),
            });
            i += 1;
            j += 1;
        } else if table[at(i + 1, j)] >= table[at(i, j + 1)] {
            raw.push(DiffRow { kind: DiffKind::Deleted, left: Some(left[i].into()), right: None });
            i += 1;
        } else {
            raw.push(DiffRow { kind: DiffKind::Added, left: None, right: Some(right[j].into()) });
            j += 1;
        }
    }
    while i < left.len() {
        raw.push(DiffRow { kind: DiffKind::Deleted, left: Some(left[i].into()), right: None });
        i += 1;
    }
    while j < right.len() {
        raw.push(DiffRow { kind: DiffKind::Added, left: None, right: Some(right[j].into()) });
        j += 1;
    }
    pair_runs(raw)
}

fn pair_runs(raw: Vec<DiffRow>) -> Vec<DiffRow> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i].kind != DiffKind::Deleted {
            out.push(raw[i].clone());
            i += 1;
            continue;
        }
        let start = i;
        while i < raw.len() && raw[i].kind == DiffKind::Deleted {
            i += 1;
        }
        let deletes = i - start;
        let add_start = i;
        while i < raw.len() && raw[i].kind == DiffKind::Added {
            i += 1;
        }
        let adds = i - add_start;
        if deletes == adds {
            for n in 0..deletes {
                out.push(DiffRow {
                    kind: DiffKind::Modified,
                    left: raw[start + n].left.clone(),
                    right: raw[add_start + n].right.clone(),
                });
            }
        } else {
            out.extend(raw[start..i].iter().cloned());
        }
    }
    out
}

// ---------------------------------------------------------------- payload markers

pub const MARKER: char = '\u{a7}';

#[derive(Debug)]
pub struct Marker {
    pub positions: String,
    pub start: usize,
    pub end: usize,
}

/// A bare `§` is one position, `§ab§` is a cluster, `§§` is two positions.
pub fn markers(template: &str) -> Vec<Marker> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != MARKER {
            i += 1;
            continue;
        }
        let close = chars[i + 1..].iter().position(|c| *c == MARKER).map(|p| p + i + 1);
        let Some(close) = close else {
            out.push(Marker { positions: String::new(), start: i, end: i + 1 });
            i += 1;
            continue;
        };
        let positions: String = chars[i + 1..close].iter().collect();
        if positions.is_empty() {
            out.push(Marker { positions: String::new(), start: i, end: i + 1 });
            out.push(Marker { positions: String::new(), start: i + 1, end: i + 2 });
            i += 2;
            continue;
        }
        out.push(Marker { positions, start: i, end: close + 1 });
        i = close + 1;
    }
    out
}

/// Positions consume successive payload characters across the whole request.
pub fn apply_payload(template: &str, payload: &str) -> String {
    let chars: Vec<char> = template.chars().collect();
    let payload: Vec<char> = payload.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut cursor = 0;
    while i < chars.len() {
        if chars[i] != MARKER {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let close = chars[i + 1..].iter().position(|c| *c == MARKER).map(|p| p + i + 1);
        let Some(close) = close else {
            out.push_str(&slot(&payload, &mut cursor, None));
            i += 1;
            continue;
        };
        let positions: Vec<char> = chars[i + 1..close].to_vec();
        if positions.is_empty() {
            out.push_str(&slot(&payload, &mut cursor, None));
            i += 1;
            continue;
        }
        for placeholder in &positions {
            out.push_str(&slot(&payload, &mut cursor, Some(*placeholder)));
        }
        i = close + 1;
    }
    out
}

fn slot(payload: &[char], cursor: &mut usize, fallback: Option<char>) -> String {
    if *cursor < payload.len() {
        let c = payload[*cursor];
        *cursor += 1;
        return c.to_string();
    }
    fallback.map(|c| c.to_string()).unwrap_or_default()
}

/// Distinct requests produced by the positions and payloads, payload-major.
pub fn enumerate(template: &str, payloads: &[String], cap: usize) -> Vec<String> {
    if markers(template).is_empty() || payloads.is_empty() {
        return Vec::new();
    }
    let mut seen: Vec<String> = Vec::new();
    for payload in payloads {
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request = apply_payload(template, trimmed);
        if !seen.contains(&request) {
            seen.push(request);
        }
        if seen.len() >= cap {
            break;
        }
    }
    seen
}

// ---------------------------------------------------------------- entropy

#[derive(Debug)]
pub struct CharStat {
    pub ch: char,
    pub code: u32,
    pub count: usize,
    pub freq: f64,
}

#[derive(Debug)]
pub struct EntropyReport {
    pub length: usize,
    pub distinct: usize,
    pub entropy: f64,
    pub max_entropy: f64,
    pub chars: Vec<CharStat>,
}

pub fn entropy_of(counts: &[usize]) -> f64 {
    let total: usize = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of a parameter's *value* plus its character-frequency breakdown.
///
/// The key is located, an optional `=`/`:` separator is skipped, and the value runs until the
/// first parameter delimiter — so `id=abcdefgh` under key `id` analyses `abcdefgh`.
pub fn analyse_token(text: &str, key: &str) -> Option<EntropyReport> {
    let at = text.find(key)?;
    let rest = &text[at + key.len()..];
    let rest = rest.strip_prefix(['=', ':']).unwrap_or(rest);
    let subject: String = rest
        .chars()
        .take_while(|c| !matches!(c, '&' | ' ' | '\t' | '\r' | '\n' | '"' | '\'' | ';' | ','))
        .collect();
    if subject.is_empty() {
        return None;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in subject.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let values: Vec<usize> = counts.values().copied().collect();
    let length = subject.chars().count();
    Some(EntropyReport {
        length,
        distinct: counts.len(),
        entropy: entropy_of(&values),
        max_entropy: (counts.len().max(2) as f64).log2(),
        chars: counts
            .into_iter()
            .map(|(ch, count)| CharStat {
                code: ch as u32,
                ch,
                count,
                freq: 100.0 * count as f64 / length.max(1) as f64,
            })
            .collect(),
    })
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, input: &str) -> String {
        (find_op(name).unwrap().run)(input).unwrap()
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(run("Base64 encode", "Gulpsuite"), "R3VscHN1aXRl");
        assert_eq!(run("Base64 decode", "R3VscHN1aXRl"), "Gulpsuite");
    }

    #[test]
    fn url_and_html() {
        assert_eq!(run("URL encode", "a b&c"), "a%20b%26c");
        assert_eq!(run("URL decode", "a%20b%26c"), "a b&c");
        assert_eq!(run("HTML encode", "<b>"), "&lt;b&gt;");
        assert_eq!(run("HTML decode", "&amp;lt;"), "&lt;");
        assert_eq!(run("HTML decode", "no entities here"), "no entities here");
    }

    #[test]
    fn numeric_bases() {
        assert_eq!(run("Hex encode", "Gulp"), "47756c70");
        assert_eq!(run("Hex decode", "47756c70"), "Gulp");
        assert_eq!(run("Base32 encode", "abc"), "MFRGG===");
        assert_eq!(run("Base32 decode", "MFRGG==="), "abc");
        assert_eq!(run("Decimal decode", "65 66 67"), "ABC");
        assert_eq!(run("Octal decode", "101 102 103"), "ABC");
        assert_eq!(run("Binary encode", "Ab"), "0100000101100010");
    }

    #[test]
    fn rot13_is_an_involution() {
        let once = run("ROT13", "Gulpsuite");
        assert_eq!(run("ROT13", &once), "Gulpsuite");
    }

    #[test]
    fn hashes_match_published_vectors() {
        assert_eq!(run("Hash: MD5", "abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(run("Hash: SHA-1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            run("Hash: SHA-256", "abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(run("Hash: MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn hash_input_helper_is_consistent() {
        assert_eq!(
            hash_input("Hash: MD5", "abc").unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn magic_finds_base64_and_leaves_text_alone() {
        assert_eq!(magic_decode("SGVsbG8sIEd1bHBzdWl0ZQ=="), Some("Base64 decode"));
        assert_eq!(magic_decode("just some words"), None);
    }

    #[test]
    fn markers_handle_bare_and_cluster_forms() {
        assert_eq!(markers("a\u{a7}b\u{a7}c").len(), 1);
        assert_eq!(markers("x\u{a7}ab\u{a7}y")[0].positions, "ab");
        assert_eq!(markers("\u{a7}\u{a7}").len(), 2);
        assert_eq!(markers("no markers").len(), 0);
    }

    #[test]
    fn payload_positions_advance_through_the_payload() {
        assert_eq!(apply_payload("a\u{a7}b", "xy"), "axb");
        assert_eq!(apply_payload("\u{a7}\u{a7}\u{a7}", "abc"), "abc");
        assert_eq!(apply_payload("\u{a7}v\u{a7}", "abc"), "a");
        assert_eq!(apply_payload("x\u{a7}ab\u{a7}y", "xy"), "xxyy");
        assert_eq!(apply_payload("\u{a7}ab\u{a7}", "x"), "xb");
    }

    #[test]
    fn enumeration_is_payload_major_and_capped() {
        let got = enumerate("GET /?q=\u{a7}v\u{a7}", &["a".into(), "b".into(), "c".into()], 100);
        assert_eq!(got.len(), 3);
        assert_eq!(enumerate("GET /", &["a".into()], 100).len(), 0);
        assert_eq!(enumerate("§v§", &["a".into(), "b".into()], 1).len(), 1);
    }

    #[test]
    fn diff_classifies_rows() {
        let kinds = |rows: Vec<DiffRow>| {
            rows.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
        };
        assert_eq!(kinds(diff_lines("a\nb", "a\nb")), vec!["same", "same"]);
        assert_eq!(kinds(diff_lines("a\nb\nc", "a\nB\nc")), vec!["same", "modified", "same"]);
        assert_eq!(kinds(diff_lines("a", "a\nb")), vec!["same", "added"]);
        assert_eq!(kinds(diff_lines("a\nb", "a")), vec!["same", "deleted"]);
        assert!(diff_lines("", "").is_empty());
    }

    #[test]
    fn entropy_of_uniform_input_is_maximal() {
        assert!((entropy_of(&[1, 1, 1, 1]) - 2.0).abs() < 1e-9);
        assert_eq!(entropy_of(&[7]), 0.0);
        assert_eq!(entropy_of(&[]), 0.0);
    }

    #[test]
    fn token_analysis_reads_the_value_not_the_name() {
        let report = analyse_token("id=abcdefgh", "id").unwrap();
        assert_eq!(report.length, 8);
        assert!(analyse_token("id=abcdefgh", "zz").is_none());
        assert!(analyse_token("id=", "id").is_none());
    }

    #[test]
    fn token_analysis_reports_counts() {
        let report = analyse_token("a=1&id=abcdefgh", "id").unwrap();
        assert_eq!(report.length, 8);
        assert_eq!(report.distinct, 8);
        assert!((report.entropy - 3.0).abs() < 1e-9);
        assert_eq!(report.chars.len(), 8);
        assert!(analyse_token("nothing here", "zz").is_none());
    }
}
