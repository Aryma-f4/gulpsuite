//! WebSocket frame codec (RFC 6455) and upgrade detection.
//!
//! Only the wire format is handled here: framing, masking and message reassembly. This app proxies
//! HTTP, so it observes frames rather than owning a connection, and a client-to-server frame must
//! arrive masked — that invariant is enforced on decode so a malformed peer cannot smuggle a frame
//! through.

/// Opcodes from RFC 6455 section 5.2.
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// True for opcodes that carry control data rather than message payload.
pub fn is_control(opcode: u8) -> bool {
    opcode & 0x8 != 0
}

/// Largest payload the control opcodes may carry.
const MAX_CONTROL_PAYLOAD: usize = 125;
/// Refuse a single frame larger than this. A 64-bit length field can claim 2^63 bytes; without a
/// ceiling one frame header would ask for an unbounded allocation.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
/// Ceiling on one reassembled message, so a stream of continuation frames cannot grow unbounded.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// One decoded frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    /// Whether the sender masked this frame.
    pub masked: bool,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: u8, payload: Vec<u8>) -> Self {
        Frame { fin: true, opcode, masked: false, payload }
    }

    /// A fragmented first frame.
    pub fn fragment(opcode: u8, payload: Vec<u8>) -> Self {
        Frame { fin: false, opcode, masked: false, payload }
    }

    pub fn continuation(payload: Vec<u8>) -> Self {
        Frame { fin: false, opcode: opcode::CONTINUATION, masked: false, payload }
    }

    pub fn text(payload: &str) -> Self {
        Frame::new(opcode::TEXT, payload.as_bytes().to_vec())
    }

    pub fn close(code: Option<u16>, reason: &str) -> Frame {
        let mut payload = Vec::new();
        if let Some(code) = code {
            payload.extend_from_slice(&code.to_be_bytes());
        }
        payload.extend_from_slice(reason.as_bytes());
        Frame::new(opcode::CLOSE, payload)
    }

    /// The close status code, if this is a close frame carrying one.
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode != opcode::CLOSE || self.payload.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
    }

    /// The close reason, if any.
    pub fn close_reason(&self) -> Option<&str> {
        if self.opcode != opcode::CLOSE || self.payload.len() <= 2 {
            return None;
        }
        std::str::from_utf8(&self.payload[2..]).ok()
    }

    /// Payload as text, when it is valid UTF-8.
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}

/// Applies the RFC 6455 masking transform. XOR is its own inverse, so this both masks and unmasks.
fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % 4];
    }
}

/// Decodes as many whole frames as `bytes` contains, returning them with the length consumed.
///
/// A trailing partial frame is not an error: a read may split mid-frame. The caller feeds the
/// remainder back in once more arrives.
pub fn decode(bytes: &[u8]) -> Result<(Vec<Frame>, usize), String> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let Some((frame, consumed)) = decode_one(&bytes[offset..])? else {
            break;
        };
        frames.push(frame);
        offset += consumed;
    }
    Ok((frames, offset))
}

/// Decodes a single frame, or `None` when `bytes` holds only part of one.
fn decode_one(bytes: &[u8]) -> Result<Option<(Frame, usize)>, String> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let first = bytes[0];
    let second = bytes[1];
    // RSV1-3 must be clear unless an extension negotiated them; nothing here negotiates one.
    if first & 0x70 != 0 {
        return Err("reserved bits set but no extension was negotiated".into());
    }
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0F;
    let masked = second & 0x80 != 0;
    // Only 0x0-0x2 and 0x8-0xA are defined; 0x3-0x7 and 0xB-0xF are reserved and must be refused.
    if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
        return Err(format!("reserved opcode 0x{opcode:x}"));
    }
    if is_control(opcode) {
        if !fin {
            return Err("control frames must not be fragmented".into());
        }
    }

    let short_len = (second & 0x7F) as usize;
    let mut cursor = 2usize;
    let payload_len = match short_len {
        126 => {
            if bytes.len() < cursor + 2 {
                return Ok(None);
            }
            let value = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            value
        }
        127 => {
            if bytes.len() < cursor + 8 {
                return Ok(None);
            }
            let raw = u64::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]);
            // RFC 6455: the high bit of the 64-bit length must be 0.
            if raw & (1 << 63) != 0 {
                return Err("64-bit payload length has its high bit set".into());
            }
            cursor += 8;
            if raw > MAX_FRAME_PAYLOAD as u64 {
                return Err(format!("frame claims {raw} bytes, the limit is {MAX_FRAME_PAYLOAD}"));
            }
            raw as usize
        }
        value => value,
    };
    if is_control(opcode) && payload_len > MAX_CONTROL_PAYLOAD {
        return Err(format!("control frame payload is {payload_len}, the limit is {MAX_CONTROL_PAYLOAD}"));
    }
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(format!("frame claims {payload_len} bytes, the limit is {MAX_FRAME_PAYLOAD}"));
    }

    let mask = if masked {
        if bytes.len() < cursor + 4 {
            return Ok(None);
        }
        let key = [bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3]];
        cursor += 4;
        Some(key)
    } else {
        None
    };

    if bytes.len() < cursor + payload_len {
        return Ok(None);
    }
    let mut payload = bytes[cursor..cursor + payload_len].to_vec();
    if let Some(key) = mask {
        apply_mask(&mut payload, key);
    }
    Ok(Some((
        Frame { fin, opcode, masked, payload },
        cursor + payload_len,
    )))
}

/// Encodes a frame, masking it with `key` when one is supplied.
pub fn encode(frame: &Frame, key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.payload.len() + 14);
    out.push((if frame.fin { 0x80 } else { 0 }) | (frame.opcode & 0x0F));
    let mask_bit = if key.is_some() { 0x80 } else { 0 };
    let len = frame.payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if let Some(key) = key {
        out.extend_from_slice(&key);
        let mut payload = frame.payload.clone();
        apply_mask(&mut payload, key);
        out.extend_from_slice(&payload);
    } else {
        out.extend_from_slice(&frame.payload);
    }
    out
}

/// A message reassembled from one or more frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}

/// Reassembles frames into messages.
///
/// Control frames pass straight through. A new data frame while a fragment is open is a protocol
/// error, which is reported rather than silently discarding the half-finished message.
pub fn assemble(frames: &[Frame]) -> Result<Vec<Message>, String> {
    let mut messages = Vec::new();
    let mut pending: Option<(u8, Vec<u8>)> = None;
    for frame in frames {
        if is_control(frame.opcode) {
            messages.push(Message { opcode: frame.opcode, payload: frame.payload.clone() });
            continue;
        }
        match frame.opcode {
            opcode::CONTINUATION => {
                let Some((opcode, mut buffer)) = pending.take() else {
                    return Err("continuation frame with no message to continue".into());
                };
                if buffer.len() + frame.payload.len() > MAX_MESSAGE {
                    return Err(format!("message exceeds the {MAX_MESSAGE} byte limit"));
                }
                buffer.extend_from_slice(&frame.payload);
                if frame.fin {
                    messages.push(Message { opcode, payload: buffer });
                } else {
                    pending = Some((opcode, buffer));
                }
            }
            opcode::TEXT | opcode::BINARY => {
                if pending.is_some() {
                    return Err("new data frame arrived before the previous message finished".into());
                }
                if frame.payload.len() > MAX_MESSAGE {
                    return Err(format!("message exceeds the {MAX_MESSAGE} byte limit"));
                }
                if frame.fin {
                    messages.push(Message { opcode: frame.opcode, payload: frame.payload.clone() });
                } else {
                    pending = Some((frame.opcode, frame.payload.clone()));
                }
            }
            other => return Err(format!("data opcode 0x{other:x} is not a data frame")),
        }
    }
    if let Some((opcode, buffer)) = pending {
        // An unterminated fragment is normal when a capture window closes mid-message.
        messages.push(Message { opcode, payload: buffer });
    }
    Ok(messages)
}

/// What a parsed handshake says about a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub upgrade: bool,
    pub key: Option<String>,
    pub accept: Option<String>,
}

/// Detects a WebSocket upgrade in an HTTP request or response head.
pub fn handshake(head: &str) -> Handshake {
    let mut upgrade = false;
    let mut key = None;
    let mut accept = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "upgrade" => upgrade = value.eq_ignore_ascii_case("websocket"),
            "sec-websocket-key" => key = Some(value.to_string()),
            "sec-websocket-accept" => accept = Some(value.to_string()),
            _ => {}
        }
    }
    Handshake { upgrade, key, accept }
}

/// True when the head is a WebSocket upgrade request or response.
pub fn is_upgrade(head: &str) -> bool {
    handshake(head).upgrade
}

/// The `Sec-WebSocket-Accept` value a server must return for `key` (RFC 6455 section 4.2.2).
pub fn accept_for(key: &str) -> String {
    let combined = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    // The handshake digest is fixed SHA-1; the base64 is of that digest.
    base64_encode(&sha1(combined.as_bytes()))
}

// --- minimal SHA-1 and base64, kept local so no dependency is added for a handshake check ---

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for (index, word) in chunk.chunks(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (index, word) in h.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let triple = ((buffer[0] as u32) << 16) | ((buffer[1] as u32) << 8) | buffer[2] as u32;
        let symbols = [
            (triple >> 18) & 63,
            (triple >> 12) & 63,
            (triple >> 6) & 63,
            triple & 63,
        ];
        out.push(ALPHABET[symbols[0] as usize] as char);
        out.push(ALPHABET[symbols[1] as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[symbols[2] as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[symbols[3] as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unmasked_text_frame_round_trips() {
        let frame = Frame::text("hello");
        let bytes = encode(&frame, None);
        assert_eq!(bytes, vec![0x81, 0x05, b'h', b'e', b'l', b'l', b'o']);
        let (frames, used) = decode(&bytes).expect("decodes");
        assert_eq!(used, bytes.len());
        assert_eq!(frames, vec![frame]);
    }

    #[test]
    fn a_masked_frame_round_trips() {
        // The RFC 6455 section 5.7 example: a masked "Hello" from client to server.
        let bytes = [
            0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58,
        ];
        let (frames, used) = decode(&bytes).expect("decodes");
        assert_eq!(used, bytes.len());
        assert_eq!(frames[0].masked, true);
        assert_eq!(frames[0].as_text(), Some("Hello"));
    }

    #[test]
    fn encoding_with_the_rfc_key_reproduces_the_wire_bytes() {
        let bytes = encode(&Frame::text("Hello"), Some([0x37, 0xFA, 0x21, 0x3D]));
        assert_eq!(bytes, [0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58]);
    }

    #[test]
    fn several_frames_decode_from_one_buffer() {
        let mut buffer = encode(&Frame::text("one"), None);
        buffer.extend(encode(&Frame::text("two"), None));
        let (frames, used) = decode(&buffer).expect("decodes");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_text(), Some("one"));
        assert_eq!(frames[1].as_text(), Some("two"));
        assert_eq!(used, buffer.len());
    }

    #[test]
    fn a_partial_frame_is_left_for_the_next_read() {
        let full = encode(&Frame::text("hello"), None);
        for cut in 1..full.len() {
            let (frames, used) = decode(&full[..cut]).expect("partial is not an error");
            assert!(frames.is_empty(), "cut at {cut} produced a whole frame");
            assert_eq!(used, 0);
        }
    }

    #[test]
    fn a_16_bit_length_is_encoded_and_decoded() {
        let payload = vec![b'x'; 300];
        let bytes = encode(&Frame::new(opcode::BINARY, payload.clone()), None);
        assert_eq!(bytes[1] & 0x7F, 126, "300 bytes must use the 16-bit form");
        let (frames, _) = decode(&bytes).expect("decodes");
        assert_eq!(frames[0].payload, payload);
    }

    #[test]
    fn a_64_bit_length_is_encoded_and_decoded() {
        let payload = vec![b'x'; 70_000];
        let bytes = encode(&Frame::new(opcode::BINARY, payload.clone()), None);
        assert_eq!(bytes[1] & 0x7F, 127, "70000 bytes must use the 64-bit form");
        let (frames, _) = decode(&bytes).expect("decodes");
        assert_eq!(frames[0].payload, payload);
    }

    #[test]
    fn a_huge_declared_length_is_refused_without_allocating() {
        // Header only: claims 2^62 bytes and carries no payload.
        let mut bytes = vec![0x81, 127];
        bytes.extend_from_slice(&(1u64 << 62).to_be_bytes());
        let error = decode(&bytes).expect_err("must refuse");
        assert!(error.contains("the limit is"), "{error}");
    }

    #[test]
    fn a_set_high_bit_in_the_64_bit_length_is_refused() {
        let mut bytes = vec![0x81, 127];
        bytes.extend_from_slice(&(1u64 << 63).to_be_bytes());
        let error = decode(&bytes).expect_err("must refuse");
        assert!(error.contains("high bit"), "{error}");
    }

    #[test]
    fn a_fragmented_message_is_reassembled() {
        let frames = vec![
            Frame::fragment(opcode::TEXT, b"Hel".to_vec()),
            Frame { ..Frame::continuation(b"lo, ".to_vec()) },
            Frame { fin: true, ..Frame::continuation(b"world".to_vec()) },
        ];
        let messages = assemble(&frames).expect("assembles");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].opcode, opcode::TEXT);
        assert_eq!(messages[0].as_text(), Some("Hello, world"));
    }

    #[test]
    fn control_frames_pass_through_a_fragmented_message() {
        let frames = vec![
            Frame::fragment(opcode::TEXT, b"part".to_vec()),
            Frame::new(opcode::PING, b"ping".to_vec()),
            Frame { fin: true, ..Frame::continuation(b"two".to_vec()) },
        ];
        let messages = assemble(&frames).expect("assembles");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].opcode, opcode::PING);
        assert_eq!(messages[1].as_text(), Some("parttwo"));
    }

    #[test]
    fn a_continuation_without_a_start_is_refused() {
        let error = assemble(&[Frame::continuation(b"orphan".to_vec())]).expect_err("must fail");
        assert!(error.contains("no message to continue"), "{error}");
    }

    #[test]
    fn a_new_data_frame_mid_fragment_is_refused() {
        let frames = vec![
            Frame::fragment(opcode::TEXT, b"part".to_vec()),
            Frame::text("interrupting"),
        ];
        let error = assemble(&frames).expect_err("must fail");
        assert!(error.contains("before the previous message finished"), "{error}");
    }

    #[test]
    fn a_fragmented_control_frame_is_refused() {
        let frames = vec![Frame::fragment(opcode::PING, b"x".to_vec())];
        let error = decode(&encode(&frames[0], None)).expect_err("must refuse");
        assert!(error.contains("control frames must not be fragmented"), "{error}");
    }

    #[test]
    fn an_oversized_control_frame_is_refused() {
        let mut bytes = vec![0x89, 126, 0x01, 0x00];
        bytes.extend_from_slice(&[0u8; 256]);
        let error = decode(&bytes).expect_err("must refuse");
        assert!(error.contains("control frame payload"), "{error}");
    }

    #[test]
    fn a_reserved_opcode_is_refused() {
        for reserved in [0x3u8, 0x7, 0xB, 0xF] {
            let bytes = [0x80 | reserved, 0x00];
            let error = decode(&bytes).expect_err("must refuse");
            assert!(error.contains("reserved opcode"), "0x{reserved:x}: {error}");
        }
    }

    #[test]
    fn every_defined_opcode_is_accepted() {
        for valid in [0x0u8, 0x1, 0x2, 0x8, 0x9, 0xA] {
            // 0x0 alone is a continuation and needs a start; check it decodes as a frame at least.
            let bytes = [0x80 | valid, 0x00];
            decode(&bytes).unwrap_or_else(|e| panic!("0x{valid:x} was refused: {e}"));
        }
    }

    #[test]
    fn reserved_bits_are_refused() {
        let mut bytes = encode(&Frame::text("hi"), None);
        bytes[0] |= 0x40;
        let error = decode(&bytes).expect_err("must refuse");
        assert!(error.contains("reserved bits"), "{error}");
    }

    #[test]
    fn a_close_frame_exposes_its_code_and_reason() {
        let frame = Frame::close(Some(1000), "bye");
        let (frames, _) = decode(&encode(&frame, None)).expect("decodes");
        assert_eq!(frames[0].close_code(), Some(1000));
        assert_eq!(frames[0].close_reason(), Some("bye"));
    }

    #[test]
    fn a_close_frame_without_a_payload_has_no_code() {
        let frame = Frame::new(opcode::CLOSE, Vec::new());
        assert_eq!(frame.close_code(), None);
        assert_eq!(frame.close_reason(), None);
    }

    #[test]
    fn an_upgrade_request_is_detected() {
        let head = "GET /chat HTTP/1.1\r\nHost: x.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let parsed = handshake(head);
        assert!(parsed.upgrade);
        assert_eq!(parsed.key.as_deref(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(parsed.accept, None);
        assert!(is_upgrade(head));
    }

    #[test]
    fn an_upgrade_response_is_detected() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        let parsed = handshake(head);
        assert!(parsed.upgrade);
        assert_eq!(parsed.accept.as_deref(), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert_eq!(parsed.key, None);
    }

    #[test]
    fn a_plain_request_is_not_an_upgrade() {
        assert!(!is_upgrade("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"));
    }

    #[test]
    fn the_header_matching_ignores_case_and_spacing() {
        let head = "GET / HTTP/1.1\r\nUPGRADE:   WebSocket  \r\n\r\n";
        assert!(is_upgrade(head));
    }

    #[test]
    fn the_accept_value_matches_the_rfc_example() {
        // RFC 6455 section 1.3.
        assert_eq!(accept_for("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let mut data = b"the quick brown fox".to_vec();
        apply_mask(&mut data, key);
        assert_ne!(&data[..], b"the quick brown fox");
        apply_mask(&mut data, key);
        assert_eq!(&data[..], b"the quick brown fox");
    }

    #[test]
    fn a_large_binary_message_survives_a_round_trip() {
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let bytes = encode(&Frame::new(opcode::BINARY, payload.clone()), Some([1, 2, 3, 4]));
        let (frames, used) = decode(&bytes).expect("decodes");
        assert_eq!(used, bytes.len());
        assert_eq!(frames[0].payload, payload);
    }
}
