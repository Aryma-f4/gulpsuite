//! DNS message codec (RFC 1035) for the Logger's DNS view.
//!
//! Burp's Logger records DNS alongside HTTP, because an out-of-band lookup is often where a target
//! leaks data. This decodes the wire format far enough to report the question and the answers.

/// Largest message accepted. DNS over UDP is capped at 4096 bytes; anything larger is either TCP or
/// a lie, and reading it whole would let a peer ask for an arbitrary allocation.
pub const MAX_MESSAGE: usize = 65_535;

/// A parsed DNS question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}

/// One answer record. Only the fields a log needs are decoded; the payload is left as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub data_len: usize,
}

/// A decoded DNS message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
}

/// Well-known record types, named because a log of numbers is not useful.
pub mod kind {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
}

/// A readable name for a record type.
/// Named `value` rather than `kind` so it does not shadow the `kind` module.
pub fn kind_name(value: u16) -> &'static str {
    match value {
        kind::A => "A",
        kind::NS => "NS",
        kind::CNAME => "CNAME",
        kind::SOA => "SOA",
        kind::PTR => "PTR",
        kind::MX => "MX",
        kind::TXT => "TXT",
        kind::AAAA => "AAAA",
        _ => "TYPE",
    }
}

/// Reads a length-prefixed domain name, following at most a few compression pointers so a
/// malicious packet cannot make this loop forever.
fn read_name(bytes: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end = offset;
    let mut hops = 0;
    loop {
        let Some(&length) = bytes.get(offset) else {
            return Err("name ran past the end of the message".into());
        };
        if length & 0xC0 == 0xC0 {
            let Some(&low) = bytes.get(offset + 1) else {
                return Err("truncated compression pointer".into());
            };
            let target = (((length & 0x3F) as usize) << 8) | low as usize;
            if !jumped {
                end = offset + 2;
                jumped = true;
            }
            hops += 1;
            if hops > 16 {
                return Err("compression pointers are looping".into());
            }
            if target >= bytes.len() {
                return Err("compression pointer points outside the message".into());
            }
            offset = target;
            continue;
        }
        offset += 1;
        if length == 0 {
            if !jumped {
                end = offset;
            }
            break;
        }
        let stop = offset + length as usize;
        if stop > bytes.len() {
            return Err("label runs past the end of the message".into());
        }
        // Labels are usually ASCII; anything else is shown escaped rather than guessed at.
        let label = bytes[offset..stop]
            .iter()
            .map(|b| {
                if (0x21..=0x7E).contains(b) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        labels.push(label);
        offset = stop;
    }
    let name = if labels.is_empty() { ".".to_string() } else { labels.join(".") };
    Ok((name, end))
}

/// Decodes a DNS message.
pub fn decode(bytes: &[u8]) -> Result<Message, String> {
    if bytes.len() > MAX_MESSAGE {
        return Err(format!("{} bytes is over the {MAX_MESSAGE} limit", bytes.len()));
    }
    if bytes.len() < 12 {
        return Err("message is shorter than a DNS header".into());
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qd_count = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let an_count = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

    let mut offset = 12usize;
    let mut questions = Vec::with_capacity(qd_count.min(64));
    for _ in 0..qd_count {
        let (name, next) = read_name(bytes, offset)?;
        let Some(&kind_hi) = bytes.get(next) else {
            return Err("question type is truncated".into());
        };
        let Some(&kind_lo) = bytes.get(next + 1) else {
            return Err("question type is truncated".into());
        };
        let Some(&class_lo) = bytes.get(next + 3) else {
            return Err("question class is truncated".into());
        };
        questions.push(Question {
            name,
            kind: u16::from_be_bytes([kind_hi, kind_lo]),
            class: u16::from_be_bytes([bytes[next + 2], class_lo]),
        });
        offset = next + 4;
    }

    let mut answers = Vec::with_capacity(an_count.min(256));
    for _ in 0..an_count {
        let (name, next) = read_name(bytes, offset)?;
        if next + 10 > bytes.len() {
            return Err("answer record is truncated".into());
        }
        let rtype = u16::from_be_bytes([bytes[next], bytes[next + 1]]);
        let class = u16::from_be_bytes([bytes[next + 2], bytes[next + 3]]);
        let ttl = u32::from_be_bytes([bytes[next + 4], bytes[next + 5], bytes[next + 6], bytes[next + 7]]);
        let rdlength = u16::from_be_bytes([bytes[next + 8], bytes[next + 9]]) as usize;
        let data_start = next + 10;
        if data_start + rdlength > bytes.len() {
            return Err("record data runs past the end of the message".into());
        }
        answers.push(Record { name, kind: rtype, class, ttl, data_len: rdlength });
        offset = data_start + rdlength;
    }

    Ok(Message { id, is_response: flags & 0x8000 != 0, questions, answers })
}

/// Builds a standard query. Used by the tests and by the local resolver path.
pub fn query(id: u16, name: &str, kind: u16, class: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // one question
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answers, authority or additional
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out
}

/// Builds a response that answers one question with one address record.
///
/// This is what a resolver answers with, and what the local collaborator hands out so a target
/// that looks a hostname up reaches this machine.
pub fn response(id: u16, name: &str, kind: u16, class: u16, ttl: u32, address: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    // Response, recursion available, no error.
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // one question
    out.extend_from_slice(&1u16.to_be_bytes()); // one answer
    out.extend_from_slice(&[0, 0, 0, 0]); // no authority or additional
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    // The answer points back at the question, which starts at offset twelve.
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&address);
    out
}

/// Builds a response that answers one question with nothing.
pub fn empty_response(id: u16, name: &str, kind: u16, class: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_round_trips() {
        let bytes = query(0x1234, "www.example.com", kind::A, 1);
        let message = decode(&bytes).expect("decodes");
        assert_eq!(message.id, 0x1234);
        assert!(!message.is_response);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "www.example.com");
        assert_eq!(message.questions[0].kind, kind::A);
        assert_eq!(message.questions[0].class, 1);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn a_response_answers_with_the_address() {
        let bytes = response(7, "x.burpcollaborator.test", kind::A, 1, 60, [127, 0, 0, 1]);
        let message = decode(&bytes).expect("decodes");
        assert!(message.is_response);
        assert_eq!(message.id, 7);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "x.burpcollaborator.test");
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name, "x.burpcollaborator.test");
        assert_eq!(message.answers[0].kind, kind::A);
        assert_eq!(message.answers[0].ttl, 60);
        assert_eq!(message.answers[0].data_len, 4);
        // The address itself is the last four bytes.
        assert_eq!(&bytes[bytes.len() - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn an_empty_response_answers_with_nothing() {
        let bytes = empty_response(8, "x.burpcollaborator.test", kind::TXT, 1);
        let message = decode(&bytes).expect("decodes");
        assert!(message.is_response);
        assert_eq!(message.questions.len(), 1);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn a_response_with_answers_decodes() {
        let mut bytes = query(1, "example.com", kind::A, 1);
        bytes[2] = 0x81;
        bytes[3] = 0x80; // response bit set
        bytes[6] = 0;
        bytes[7] = 1; // one answer
        // Answer: name pointer to offset 12, type A, class IN, ttl 300, rdlength 4
        bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216, 34]);
        let message = decode(&bytes).expect("decodes");
        assert!(message.is_response);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name, "example.com");
        assert_eq!(message.answers[0].ttl, 300);
        assert_eq!(message.answers[0].data_len, 4);
        assert_eq!(kind_name(message.answers[0].kind), "A");
    }

    #[test]
    fn a_truncated_message_is_refused() {
        let bytes = query(1, "a.test", kind::A, 1);
        assert!(decode(&bytes[..8]).is_err());
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn an_over_long_message_is_refused() {
        let mut bytes = vec![0u8; MAX_MESSAGE + 1];
        assert!(decode(&bytes).expect_err("must refuse").contains("limit"));
        bytes.truncate(64);
    }

    #[test]
    fn a_looping_compression_pointer_is_refused() {
        // A pointer at offset 12 that points at itself.
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&[0xC0, 0x0C]);
        bytes[5] = 0x01; // one question
        let error = decode(&bytes).expect_err("must refuse");
        assert!(error.contains("looping") || error.contains("outside"), "{error}");
    }

    #[test]
    fn a_label_running_past_the_end_is_refused() {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&[40]); // claims a 40-byte label
        bytes.extend_from_slice(b"short");
        bytes[5] = 0x01;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn several_questions_decode() {
        // The first question stays complete; a whole second one is appended after it.
        let mut bytes = query(1, "a.test", kind::A, 1);
        bytes.extend_from_slice(&[0x03, b'b', b'i', b't', 0x04, b't', b'e', b's', b't', 0x00]);
        bytes.extend_from_slice(&kind::AAAA.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes[5] = 0x02;
        let message = decode(&bytes).expect("decodes");
        assert_eq!(message.questions.len(), 2);
        assert_eq!(message.questions[1].name, "bit.test");
        assert_eq!(message.questions[1].kind, kind::AAAA);
    }

    #[test]
    fn kind_names_are_not_all_the_same() {
        let mut seen = std::collections::HashSet::new();
        for k in [kind::A, kind::NS, kind::CNAME, kind::SOA, kind::PTR, kind::MX, kind::TXT, kind::AAAA] {
            assert!(seen.insert(kind_name(k)), "{k} duplicates a name");
        }
    }
}
