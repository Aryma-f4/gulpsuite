//! HTTP message syntax colouring.
//!
//! Burp ships the palette this uses: `ui.editor.message.*` names every token class it recognises
//! (first line, header name, header value, parameter name and value, strings, numbers, tags,
//! comments, CDATA, entities, annotations, operators). Colouring from those keys rather than
//! inventing colours is what makes the editor look like Burp's instead of merely being dark.

use eframe::epaint::text::{LayoutJob, TextFormat};
use eframe::egui::{Color32, FontFamily, FontId, Stroke};

use crate::ui::theme::Theme;

/// A run of text sharing one colour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub colour: Color32,
    pub bold: bool,
}

impl Span {
    fn new(text: impl Into<String>, colour: Color32) -> Self {
        Span { text: text.into(), colour, bold: false }
    }

    fn bold(text: impl Into<String>, colour: Color32) -> Self {
        Span { text: text.into(), colour, bold: true }
    }
}

/// Splits a whole HTTP message into coloured runs.
pub fn spans(message: &str, theme: &Theme) -> Vec<Span> {
    let normalised = message.replace("\r\n", "\n");
    let (head, body) = match normalised.find("\n\n") {
        Some(at) => (&normalised[..at], Some(&normalised[at + 2..])),
        // No blank line: either a head with no body, or a bare body the user is viewing on its own.
        None if starts_http(normalised.lines().next().unwrap_or("")) => (normalised.as_str(), None),
        None => ("", Some(normalised.as_str())),
    };
    let mut out = head_spans(head, theme);
    if let Some(body) = body {
        if !head.is_empty() {
            // The blank line between head and body is part of the message.
            out.push(Span::new("\n\n", theme.color("ui.editor.message.httpFirstLine")));
        }
        out.extend(body_spans(body, content_type_of(head), theme));
    }
    out
}

/// True when a line opens an HTTP message, which is how a head-only message is told from a body.
fn starts_http(line: &str) -> bool {
    line.starts_with("HTTP/")
        || ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "]
            .iter()
            .any(|method| line.starts_with(method))
}

/// The declared body type, defaulting to plain text.
fn content_type_of(head: &str) -> String {
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                return value.trim().to_ascii_lowercase();
            }
        }
    }
    String::new()
}

/// The request or status line plus every header.
fn head_spans(head: &str, theme: &Theme) -> Vec<Span> {
    let first_line = theme.color("ui.editor.message.httpFirstLine");
    let name = theme.color("ui.editor.message.headerName");
    let value = theme.color("ui.editor.message.headerValue");
    let cookie_name = theme.color("ui.editor.message.cookieName");
    let cookie_value = theme.color("ui.editor.message.cookieValue");

    let mut out = Vec::new();
    for (index, line) in head.split('\n').enumerate() {
        if index > 0 {
            out.push(Span::new("\n", first_line));
        }
        if index == 0 {
            out.push(Span::bold(line.to_string(), first_line));
            continue;
        }
        let Some((name_part, value_part)) = line.split_once(':') else {
            out.push(Span::new(line.to_string(), first_line));
            continue;
        };
        let is_cookie = name_part.trim().eq_ignore_ascii_case("cookie")
            || name_part.trim().eq_ignore_ascii_case("set-cookie");
        out.push(Span::new(format!("{name_part}:"), name));
        if is_cookie {
            // A cookie header is name=value pairs, and Burp colours the halves differently.
            out.extend(cookie_spans(value_part, cookie_name, cookie_value));
        } else {
            out.push(Span::new(value_part.to_string(), value));
        }
    }
    out
}

/// Splits a cookie header into names and values.
fn cookie_spans(value: &str, name_colour: Color32, value_colour: Color32) -> Vec<Span> {
    let mut out = Vec::new();
    let mut leading = String::new();
    let mut pair = String::new();
    for ch in value.chars() {
        match ch {
            '=' if !pair.contains('=') => {
                leading.push_str(&pair);
                out.push(Span::new(std::mem::take(&mut leading), name_colour));
                out.push(Span::new("=", value_colour));
                pair.push(ch);
            }
            ';' => {
                let trimmed = std::mem::take(&mut pair);
                let (name_part, value_part) = trimmed.split_once('=').unwrap_or((trimmed.as_str(), ""));
                out.push(Span::new(name_part.to_string(), name_colour));
                if value_part.is_empty() {
                    out.push(Span::new("=", value_colour));
                } else {
                    out.push(Span::new(format!("={value_part}"), value_colour));
                }
                out.push(Span::new(";", name_colour));
            }
            _ => pair.push(ch),
        }
    }
    if !pair.is_empty() {
        out.push(Span::new(pair, value_colour));
    }
    out
}

/// Dispatches the body on its declared type, falling back to a sniff.
/// Caps detailed per-token syntax colouring at 16 KiB so large minified bundles render at 60 FPS.
fn body_spans(body: &str, content_type: String, theme: &Theme) -> Vec<Span> {
    const HIGHLIGHT_CAP: usize = 16 * 1024;
    let (active_body, overflow_tail) = if body.len() > HIGHLIGHT_CAP {
        let mut end = HIGHLIGHT_CAP;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        (&body[..end], Some(&body[end..]))
    } else {
        (body, None)
    };
    let detected = detect(active_body, &content_type);
    let mut out = match detected {
        Body::Json => json_spans(active_body, theme),
        Body::Markup => markup_spans(active_body, theme),
        Body::UrlEncoded => urlencoded_spans(active_body, theme),
        Body::Script => script_spans(active_body, theme),
        Body::Plain => {
            if content_type.contains("form-urlencoded") {
                urlencoded_spans(active_body, theme)
            } else {
                vec![Span::new(
                    active_body.to_string(),
                    theme.color("ui.editor.message.literalString"),
                )]
            }
        }
    };
    if let Some(tail) = overflow_tail {
        out.push(Span::new(
            tail.to_string(),
            theme.color("ui.editor.message.literalString"),
        ));
    }
    out
}

enum Body {
    Json,
    Markup,
    UrlEncoded,
    Script,
    Plain,
}

/// Trust the declared type, but sniff when it is absent or too generic.
fn detect(body: &str, content_type: &str) -> Body {
    let head = body.trim_start();
    if content_type.contains("json") {
        return Body::Json;
    }
    if content_type.contains("html") || content_type.contains("xml") {
        return Body::Markup;
    }
    if content_type.contains("javascript") || content_type.contains("ecmascript") {
        return Body::Script;
    }
    if content_type.contains("form-urlencoded") {
        return Body::UrlEncoded;
    }
    if head.starts_with('{') || head.starts_with('[') {
        return Body::Json;
    }
    if head.starts_with('<') {
        return Body::Markup;
    }
    if body.contains('=') && body.contains('&') && !body.contains(' ') {
        return Body::UrlEncoded;
    }
    Body::Plain
}

/// JSON: keys, string values, numbers, booleans.
fn json_spans(body: &str, theme: &Theme) -> Vec<Span> {
    let key = theme.color("ui.editor.message.paramName");
    let string = theme.color("ui.editor.message.literalString");
    let number = theme.color("ui.editor.message.literalNumber");
    let boolean = theme.color("ui.editor.message.literalBoolean");
    let operator = theme.color("ui.editor.message.operator");
    let punctuation = theme.color("ui.editor.message.separator");

    let chars: Vec<char> = body.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];

        if ch == '"' {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let literal: String = chars[start..i.min(chars.len())].iter().collect();
            // A string followed by a colon is a key; anything else is a value.
            let mut after = i;
            while after < chars.len() && chars[after].is_whitespace() {
                after += 1;
            }
            let is_key = after < chars.len() && chars[after] == ':';
            out.push(Span::new(literal, if is_key { key } else { string }));
            continue;
        }

        if ch.is_ascii_digit() || (ch == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit)) {
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_digit()
                    || matches!(chars[i], '.' | 'e' | 'E' | '+' | '-'))
            {
                i += 1;
            }
            out.push(Span::new(chars[start..i].iter().collect::<String>(), number));
            continue;
        }

        if ch.is_alphabetic() {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let literal = matches!(word.as_str(), "true" | "false" | "null");
            out.push(Span::new(word, if literal { boolean } else { string }));
            continue;
        }

        if matches!(ch, '{' | '}' | '[' | ']') {
            out.push(Span::new(ch.to_string(), punctuation));
            i += 1;
            continue;
        }
        if matches!(ch, ':' | ',') {
            out.push(Span::new(ch.to_string(), operator));
            i += 1;
            continue;
        }

        // Anything left is whitespace, which keeps the run boundaries intact.
        out.push(Span::new(ch.to_string(), string));
        i += 1;
    }
    out
}

/// HTML and XML: comments, CDATA, processing instructions, tags, attributes, entities.
fn markup_spans(body: &str, theme: &Theme) -> Vec<Span> {
    let tag = theme.color("ui.editor.message.tagName");
    // `tagDelimiter` exists in Burp's theme for exactly `<`, `>` and `/`. Painting those with
    // tagName made every angle bracket the same yellow as the tag itself.
    let tag_delimiter = theme.color("ui.editor.message.tagDelimiter");
    let attribute = theme.color("ui.editor.message.paramName");
    // Attribute values pair with paramName, matching the form-encoded path and Burp's own scheme.
    let value = theme.color("ui.editor.message.paramValue");
    let comment = theme.color("ui.editor.message.comment");
    let cdata = theme.color("ui.editor.message.cdata");
    let delimiter = theme.color("ui.editor.message.cdataDelimiter");
    let processing = theme.color("ui.editor.message.processingInstruction");
    let entity = theme.color("ui.editor.message.entityReference");

    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if let Some(at) = rest.find("<!--") {
            push_plain(&mut out, &rest[..at], value);
            let tail = &rest[at..];
            let end = tail.find("-->").map(|e| e + 3).unwrap_or(tail.len());
            out.push(Span::new(tail[..end].to_string(), comment));
            rest = &tail[end..];
            continue;
        }
        if let Some(at) = rest.find("<![CDATA[") {
            push_plain(&mut out, &rest[..at], value);
            let tail = &rest[at..];
            out.push(Span::new("<![CDATA[".to_string(), delimiter));
            if let Some(close_rel) = tail[9..].find("]]>") {
                let cdata_end = 9 + close_rel;
                out.push(Span::new(tail[9..cdata_end].to_string(), cdata));
                out.push(Span::new("]]>".to_string(), delimiter));
                rest = &tail[cdata_end + 3..];
            } else {
                out.push(Span::new(tail[9..].to_string(), cdata));
                rest = "";
            }
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            let end = rest.find('>').map(|e| e + 1).unwrap_or(rest.len());
            out.push(Span::new(rest[..end].to_string(), processing));
            rest = &rest[end..];
            continue;
        }
        if rest.starts_with('<') {
            let end = rest.find('>').map(|e| e + 1).unwrap_or(rest.len());
            out.extend(attribute_spans(&rest[..end], tag_delimiter, tag, attribute, value));
            rest = &rest[end..];
            continue;
        }
        if rest.starts_with('&') {
            let end = rest.find(';').map(|e| e + 1).unwrap_or(rest.len());
            out.push(Span::new(rest[..end].to_string(), entity));
            rest = &rest[end..];
            continue;
        }
        // Whichever comes first, or the entity is skipped when a later tag bracket exists.
        let at = match (rest.find('<'), rest.find('&')) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => rest.len(),
        }
        .max(1)
        .min(rest.len());
        push_plain(&mut out, &rest[..at], value);
        rest = &rest[at..];
    }
    out
}

/// Splits one XML/HTML tag into Burp's four token classes: delimiters, the tag name, attribute
/// names and attribute values. These were previously two colours with the name and delimiter
/// swapped, so `<p id="x">` painted `p` as an attribute and `<`/`>` as the tag name.
fn attribute_spans(
    tag: &str,
    delimiter: Color32,
    tag_name: Color32,
    attribute: Color32,
    value: Color32,
) -> Vec<Span> {
    let bytes = tag.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    // Tag delimiters take the tag colour; names and attributes take theirs.
    while i < bytes.len() && (bytes[i] == b'<' || bytes[i] == b'>' || bytes[i] == b'/') {
        out.push(Span::new((bytes[i] as char).to_string(), delimiter));
        i += 1;
    }

    let name_end = bytes[i..]
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b'=' || *b == b'>' || *b == b'/')
        .map(|at| i + at)
        .unwrap_or(bytes.len());
    if name_end > i {
        // The element's own name, not an attribute name.
        out.push(Span::new(tag[i..name_end].to_string(), tag_name));
        i = name_end;
    }

    while i < bytes.len() {
        // Separators between attributes are still part of the text, so they are emitted.
        let separator_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i > separator_start {
            out.push(Span::new(tag[separator_start..i].to_string(), attribute));
        }
        if i >= bytes.len() {
            break;
        }
        // A stray '=' or '>' here belongs to whatever is left.
        if bytes[i] == b'=' || bytes[i] == b'>' {
            out.push(Span::new((bytes[i] as char).to_string(), delimiter));
            i += 1;
            continue;
        }

        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'>' {
            i += 1;
        }
        if i > start {
            out.push(Span::new(tag[start..i].to_string(), attribute));
        }

        // Optional value.
        let mut probe = i;
        while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
            probe += 1;
        }
        if probe < bytes.len() && bytes[probe] == b'=' {
            if probe > i {
                out.push(Span::new(tag[i..probe].to_string(), attribute));
            }
            out.push(Span::new("=".to_string(), delimiter));
            i = probe + 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let value_start = i;
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                if i < bytes.len() {
                    // Include the closing quote so the rendered text is byte-for-byte identical.
                    i += 1;
                }
                out.push(Span::new(tag[value_start..i].to_string(), value));
            } else {
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                out.push(Span::new(tag[value_start..i].to_string(), value));
            }
        }
    }
    out
}

fn push_plain(out: &mut Vec<Span>, text: &str, colour: Color32) {
    if !text.is_empty() {
        out.push(Span::new(text.to_string(), colour));
    }
}

/// `key=value` pairs, each half in its own colour.
fn urlencoded_spans(body: &str, theme: &Theme) -> Vec<Span> {
    let name = theme.color("ui.editor.message.paramName");
    let value = theme.color("ui.editor.message.paramValue");
    let mut out = Vec::new();
    for (index, pair) in body.split('&').enumerate() {
        if index > 0 {
            out.push(Span::new("&", name));
        }
        match pair.split_once('=') {
            Some((k, v)) => {
                out.push(Span::new(k.to_string(), name));
                out.push(Span::new("=", value));
                out.push(Span::new(v.to_string(), value));
            }
            None => out.push(Span::new(pair.to_string(), name)),
        }
    }
    out
}

/// Strings, comments, numbers and keywords.
fn script_spans(body: &str, theme: &Theme) -> Vec<Span> {
    const KEYWORDS: [&str; 12] = [
        "function", "return", "var", "let", "const", "if", "else", "for", "while", "new", "this",
        "try",
    ];
    let string = theme.color("ui.editor.message.literalString");
    let number = theme.color("ui.editor.message.literalNumber");
    let comment = theme.color("ui.editor.message.comment");
    let keyword = theme.color("ui.editor.message.reservedWord");
    let annotation = theme.color("ui.editor.message.annotation");

    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if rest.starts_with("//") {
            let line_end = rest.find('\n').map(|n| n + 1).unwrap_or(rest.len());
            out.push(Span::new(rest[..line_end].to_string(), comment));
            rest = &rest[line_end..];
            continue;
        }
        if rest.starts_with("/*") {
            let end = rest[2..].find("*/").map(|e| e + 4).unwrap_or(rest.len());
            out.push(Span::new(rest[..end].to_string(), comment));
            rest = &rest[end..];
            continue;
        }
        let first = rest.chars().next().unwrap();
        if first == '"' || first == '\'' || first == '`' {
            let quote = first;
            let mut chars = rest.chars();
            chars.next();
            let mut literal = String::new();
            let mut escaped = false;
            for ch in chars {
                literal.push(ch);
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == quote {
                    break;
                }
            }
            let taken_bytes: usize = quote.len_utf8() + literal.len();
            out.push(Span::new(format!("{quote}{literal}"), string));
            rest = &rest[taken_bytes.min(rest.len())..];
            continue;
        }
        if first == '@' {
            let tail_len: usize = rest[1..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .map(char::len_utf8)
                .sum();
            let consumed = (1 + tail_len).min(rest.len());
            out.push(Span::new(rest[..consumed].to_string(), annotation));
            rest = &rest[consumed..];
            continue;
        }
        if first.is_ascii_digit() {
            let consumed: usize = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .map(char::len_utf8)
                .sum::<usize>()
                .max(1);
            out.push(Span::new(rest[..consumed].to_string(), number));
            rest = &rest[consumed..];
            continue;
        }
        if first.is_alphabetic() || first == '_' || first == '$' {
            let consumed: usize = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .map(char::len_utf8)
                .sum::<usize>()
                .max(first.len_utf8());
            let word = &rest[..consumed];
            let colour = if KEYWORDS.contains(&word) {
                keyword
            } else {
                string
            };
            out.push(Span::new(word.to_string(), colour));
            rest = &rest[consumed..];
            continue;
        }
        // Advance by at least `first.len_utf8()` bytes so multi-byte UTF-8 symbols (e.g. '', '—', emojis)
        // never slice mid-codepoint and every iteration makes strict forward progress.
        let min_step = first.len_utf8();
        let step = rest[min_step..]
            .find(|c: char| {
                c.is_alphanumeric()
                    || matches!(c, '_' | '$' | '"' | '\'' | '`' | '/' | '@')
            })
            .map(|off| min_step + off)
            .unwrap_or(rest.len())
            .max(min_step);
        out.push(Span::new(rest[..step].to_string(), string));
        rest = &rest[step..];
    }
    out
}

/// Renders the spans as an egui text job, caching recent `(hash, LayoutJob)` pairs per thread so
/// 60 FPS redraws of unchanged HTTP messages do zero re-tokenization or heap allocations.
pub fn layout(message: &str, theme: &Theme) -> LayoutJob {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    theme.dark.hash(&mut hasher);
    message.hash(&mut hasher);
    let key = hasher.finish();

    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::VecDeque<(u64, LayoutJob)>> =
            std::cell::RefCell::new(std::collections::VecDeque::with_capacity(16));
    }

    if let Some(cached) = CACHE.with(|cache| {
        cache
            .borrow()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, job)| job.clone())
    }) {
        return cached;
    }

    let job = layout_job(spans(message, theme));
    CACHE.with(|cache| {
        let mut guard = cache.borrow_mut();
        if guard.len() >= 16 {
            guard.pop_front();
        }
        guard.push_back((key, job.clone()));
    });
    job
}

/// Renders pre-computed spans, so callers that colour incrementally can skip the parse.
/// Any `§...§` Intruder payload markers receive a `#CFE8DF` mint-green background highlight
/// and `#A31515` foreground.
pub fn layout_job(spans: Vec<Span>) -> LayoutJob {
    let mut job = LayoutJob::default();
    let mut in_marker = false;
    let marker_bg = Color32::from_rgb(0xCF, 0xE8, 0xDF);
    let marker_fg = Color32::from_rgb(0xA3, 0x15, 0x15);

    for span in spans {
        if !span.text.contains('§') && !in_marker {
            job.append(
                &span.text,
                0.0,
                TextFormat {
                    font_id: FontId::new(12.0, FontFamily::Monospace),
                    color: span.colour,
                    underline: if span.bold {
                        Stroke::new(1.0_f32, span.colour)
                    } else {
                        Stroke::NONE
                    },
                    ..Default::default()
                },
            );
            continue;
        }
        let mut buf = String::new();
        for ch in span.text.chars() {
            if ch == '§' {
                if in_marker {
                    buf.push('§');
                    job.append(
                        &buf,
                        0.0,
                        TextFormat {
                            font_id: FontId::new(12.0, FontFamily::Monospace),
                            color: marker_fg,
                            background: marker_bg,
                            ..Default::default()
                        },
                    );
                    buf.clear();
                    in_marker = false;
                } else {
                    if !buf.is_empty() {
                        job.append(
                            &buf,
                            0.0,
                            TextFormat {
                                font_id: FontId::new(12.0, FontFamily::Monospace),
                                color: span.colour,
                                underline: if span.bold {
                                    Stroke::new(1.0_f32, span.colour)
                                } else {
                                    Stroke::NONE
                                },
                                ..Default::default()
                            },
                        );
                        buf.clear();
                    }
                    buf.push('§');
                    in_marker = true;
                }
            } else {
                buf.push(ch);
            }
        }
        if !buf.is_empty() {
            job.append(
                &buf,
                0.0,
                TextFormat {
                    font_id: FontId::new(12.0, FontFamily::Monospace),
                    color: if in_marker { marker_fg } else { span.colour },
                    background: if in_marker {
                        marker_bg
                    } else {
                        Color32::TRANSPARENT
                    },
                    underline: if span.bold && !in_marker {
                        Stroke::new(1.0_f32, span.colour)
                    } else {
                        Stroke::NONE
                    },
                    ..Default::default()
                },
            );
        }
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: &[Span]) -> String {
        spans.iter().map(|s| s.text.as_str()).collect()
    }

    fn colours(spans: &[Span]) -> Vec<Color32> {
        spans.iter().map(|s| s.colour).collect()
    }

    #[test]
    fn the_first_line_uses_the_first_line_colour() {
        let theme = Theme::load(true);
        let message = "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n";
        let spans = spans(message, &theme);
        let first_line = &spans[0];
        assert_eq!(first_line.colour, theme.color("ui.editor.message.httpFirstLine"));
        assert!(first_line.bold, "the request line is emphasised in Burp");
    }

    #[test]
    fn headers_split_into_name_and_value() {
        let theme = Theme::load(true);
        let spans = spans("GET / HTTP/1.1\r\nHost: a.test\r\n", &theme);
        let joined = text(&spans);
        assert!(joined.contains("Host:"));
        assert!(joined.contains("a.test"));
        let name = theme.color("ui.editor.message.headerName");
        let value = theme.color("ui.editor.message.headerValue");
        assert!(colours(&spans).contains(&name));
        assert!(colours(&spans).contains(&value));
    }

    #[test]
    fn a_cookie_header_colours_its_halves_separately() {
        let theme = Theme::load(true);
        let spans = spans("GET / HTTP/1.1\r\nCookie: sid=abc; theme=dark\r\n\r\n", &theme);
        assert!(colours(&spans).contains(&theme.color("ui.editor.message.cookieName")));
        assert!(colours(&spans).contains(&theme.color("ui.editor.message.cookieValue")));
    }

    #[test]
    fn json_keys_and_values_differ() {
        let theme = Theme::load(true);
        let message = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"user\": \"bob\", \"age\": 42, \"admin\": true}";
        let spans = spans(message, &theme);
        let key = theme.color("ui.editor.message.paramName");
        let string = theme.color("ui.editor.message.literalString");
        let number = theme.color("ui.editor.message.literalNumber");
        let boolean = theme.color("ui.editor.message.literalBoolean");
        let seen = colours(&spans);
        assert!(seen.contains(&key), "the JSON key was not coloured as a key");
        assert!(seen.contains(&string));
        assert!(seen.contains(&number));
        assert!(seen.contains(&boolean));
    }

    #[test]
    fn json_is_detected_without_a_content_type() {
        let theme = Theme::load(true);
        let spans = spans("{\"a\": 1}", &theme);
        assert!(colours(&spans).contains(&theme.color("ui.editor.message.paramName")));
    }

    #[test]
    fn markup_colours_comments_cdata_tags_and_entities() {
        let theme = Theme::load(true);
        let message = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                       <!-- note --><p id=\"x\">a &amp; b</p>";
        let seen = colours(&spans(message, &theme));
        assert!(seen.contains(&theme.color("ui.editor.message.comment")));
        assert!(seen.contains(&theme.color("ui.editor.message.tagName")));
        assert!(seen.contains(&theme.color("ui.editor.message.paramName")));
        // Attribute values pair with paramName; the delimiter gets its own Burp key.
        assert!(seen.contains(&theme.color("ui.editor.message.paramValue")));
        assert!(seen.contains(&theme.color("ui.editor.message.tagDelimiter")));
        assert!(seen.contains(&theme.color("ui.editor.message.entityReference")));
    }

    #[test]
    fn cdata_is_recognised() {
        let theme = Theme::load(true);
        let seen = colours(&spans("<xml><![CDATA[<raw>]]></xml>", &theme));
        assert!(seen.contains(&theme.color("ui.editor.message.cdata")));
    }

    #[test]
    fn urlencoded_bodies_split_name_and_value() {
        let theme = Theme::load(true);
        let seen = colours(&spans("q=hello&page=2", &theme));
        assert!(seen.contains(&theme.color("ui.editor.message.paramName")));
        assert!(seen.contains(&theme.color("ui.editor.message.paramValue")));
    }

    #[test]
    fn a_form_content_type_forces_urlencoding() {
        let theme = Theme::load(true);
        let message = "HTTP/1.1 200 OK\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=bob";
        let seen = colours(&spans(message, &theme));
        assert!(seen.contains(&theme.color("ui.editor.message.paramValue")));
    }

    #[test]
    fn scripts_colour_comments_strings_numbers_and_keywords() {
        let theme = Theme::load(true);
        let message = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n\
                       // note\nvar x = \"s\"; return 42;";
        let seen = colours(&spans(message, &theme));
        assert!(seen.contains(&theme.color("ui.editor.message.comment")));
        assert!(seen.contains(&theme.color("ui.editor.message.literalString")));
        assert!(seen.contains(&theme.color("ui.editor.message.literalNumber")));
        assert!(seen.contains(&theme.color("ui.editor.message.reservedWord")));
    }

    #[test]
    fn no_text_is_ever_lost() {
        let theme = Theme::load(true);
        for message in [
            "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":[1,2,{\"b\":null}]}",
            "<html><!--c--><a href='#'>x</a></html>",
            "q=1&r=2",
            "//c\nfunction f(){return \"x\";}",
        ] {
            let joined = text(&spans(message, &theme));
            let stripped: String = joined.replace("\n", "\r\n").replace('\r', "");
            let expected: String = message.replace("\r\n", "\n").replace('\r', "");
            assert_eq!(stripped, expected, "highlighting lost or added text");
        }
    }

    #[test]
    fn a_message_without_a_body_still_colours_the_head() {
        let theme = Theme::load(true);
        let spans = spans("GET / HTTP/1.1\r\nHost: a.test", &theme);
        assert!(spans.len() >= 3);
        assert!(text(&spans).contains("a.test"));
    }
}
/// Renders a whole HTTP message with syntax colouring, in a scroll area.
pub fn show_message(
    ui: &mut eframe::egui::Ui,
    message: &str,
    theme: &Theme,
    background: eframe::egui::Color32,
) {
    show_message_in(ui, "msg-default", 260.0, message, theme, background);
}

/// Renders a syntax-highlighted HTTP message inside a scroll area of explicit `height`.
pub fn show_message_in(
    ui: &mut eframe::egui::Ui,
    id: &str,
    height: f32,
    message: &str,
    theme: &Theme,
    background: eframe::egui::Color32,
) -> eframe::egui::Response {
    let job = layout(message, theme);
    let no_drag_scroll = eframe::egui::containers::scroll_area::ScrollSource {
        scroll_bar: true,
        drag: false,
        mouse_wheel: true,
    };
    let frame = eframe::egui::Frame::new()
        .fill(background)
        .inner_margin(6.0)
        .stroke(eframe::egui::Stroke::new(1.0_f32, theme.color("ui.background.3")));
    let frame_out = frame.show(ui, |ui| {
        ui.set_min_height(height.max(80.0));
        eframe::egui::ScrollArea::both()
            .id_salt(id)
            .scroll_source(no_drag_scroll)
            .max_height(height.max(80.0))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    eframe::egui::Label::new(job)
                        .selectable(true)
                        .sense(eframe::egui::Sense::click()),
                )
            })
            .inner
    });
    let mut resp = frame_out.inner;
    resp.rect = frame_out.response.rect;
    resp
}

/// Renders an editable message, coloured by highlighting the text around the caret.
///
/// egui's text edit cannot colour per character, so the editor stays plain and the coloured view
/// sits beside it. Burp has the same pairing: a raw editor over a highlighted view.
pub fn show_editable(
    ui: &mut eframe::egui::Ui,
    text: &mut String,
    theme: &Theme,
    background: eframe::egui::Color32,
) {
    let _ = show_editable_in(ui, "edit-default", 260.0, text, theme, background);
}

/// Renders an editable HTTP message inside a scroll area of explicit `height`.
pub fn show_editable_in(
    ui: &mut eframe::egui::Ui,
    id: &str,
    height: f32,
    text: &mut String,
    theme: &Theme,
    background: eframe::egui::Color32,
) -> eframe::egui::Response {
    let rows = ((height / 16.0) as usize).clamp(6, 60);
    let no_drag_scroll = eframe::egui::containers::scroll_area::ScrollSource {
        scroll_bar: true,
        drag: false,
        mouse_wheel: true,
    };
    let edit_id = ui.make_persistent_id((id, "msg-edit-body"));
    let prev_range = eframe::egui::text_edit::TextEditState::load(ui.ctx(), edit_id)
        .and_then(|s| s.cursor.char_range())
        .filter(|r| r.primary != r.secondary);
    let right_mouse_event = ui.input(|i| {
        i.pointer
            .button_pressed(eframe::egui::PointerButton::Secondary)
            || i.pointer
                .button_down(eframe::egui::PointerButton::Secondary)
            || i.pointer
                .button_released(eframe::egui::PointerButton::Secondary)
    });

    let frame_out = eframe::egui::Frame::new()
        .fill(background)
        .inner_margin(6.0)
        .stroke(eframe::egui::Stroke::new(1.0_f32, theme.color("ui.background.3")))
        .show(ui, |ui| {
            ui.set_min_height(height.max(80.0));
            eframe::egui::ScrollArea::vertical()
                .id_salt(id)
                .scroll_source(no_drag_scroll)
                .max_height(height.max(80.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let mut layouter =
                        |ui: &eframe::egui::Ui, buf: &dyn eframe::egui::TextBuffer, width: f32| {
                            let mut job = layout(buf.as_str(), theme);
                            job.wrap.max_width = width.max(40.0);
                            ui.fonts_mut(|fonts| fonts.layout_job(job))
                        };
                    let mut out = eframe::egui::TextEdit::multiline(text)
                        .id(edit_id)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(rows)
                        .frame(false)
                        .layouter(&mut layouter)
                        .show(ui);
                    if right_mouse_event {
                        if let Some(saved) = prev_range {
                            out.state.cursor.set_char_range(Some(saved));
                            out.state.store(ui.ctx(), edit_id);
                            out.cursor_range = Some(saved);
                        }
                    }
                    if let Some(cr) = out.cursor_range {
                        let sorted = cr.as_sorted_char_range();
                        if sorted.start < sorted.end {
                            crate::ui::panels::record_message_selection(id, sorted, text);
                        }
                    }
                    out.response
                })
                .inner
        });
    let mut resp = frame_out.inner;
    resp.rect = frame_out.response.rect;
    resp
}

#[cfg(test)]
mod burp_key_tests {
    use super::*;
    use crate::ui::theme::Theme;

    /// Distinct colours present in a span list.
    fn colours(spans: &[Span]) -> Vec<eframe::egui::Color32> {
        let mut seen: Vec<eframe::egui::Color32> = Vec::new();
        for span in spans {
            if !seen.contains(&span.colour) {
                seen.push(span.colour);
            }
        }
        seen
    }

    /// Every token colour the highlighter uses must exist in Burp's own theme. A key that resolves to
    /// the grey fallback is invisible at runtime, so this is checked rather than assumed.
    #[test]
    fn every_highlighter_colour_is_a_real_burp_key() {
        for dark in [true, false] {
            let theme = Theme::load(dark);
            let keys = [
                "ui.editor.message.annotation",
                "ui.editor.message.cdata",
                "ui.editor.message.cdataDelimiter",
                "ui.editor.message.comment",
                "ui.editor.message.cookieName",
                "ui.editor.message.cookieValue",
                "ui.editor.message.entityReference",
                "ui.editor.message.headerName",
                "ui.editor.message.headerValue",
                "ui.editor.message.httpFirstLine",
                "ui.editor.message.literalBoolean",
                "ui.editor.message.literalNumber",
                "ui.editor.message.literalString",
                "ui.editor.message.operator",
                "ui.editor.message.paramName",
                "ui.editor.message.paramValue",
                "ui.editor.message.processingInstruction",
                "ui.editor.message.reservedWord",
                "ui.editor.message.separator",
                "ui.editor.message.tagDelimiter",
                "ui.editor.message.tagName",
                "ui.editor.message.text",
            ];
            for key in keys {
                assert!(
                    theme.has(key),
                    "{key} does not exist in Burp's theme (dark={dark})"
                );
            }
        }
    }

    /// Burp distinguishes tag delimiters from tag names, and attribute values from plain strings.
    /// Getting these wrong is invisible in a unit test but obvious on screen.
    #[test]
    fn markup_delimiters_and_values_use_burp_distinct_keys() {
        let theme = Theme::load(true);
        assert_ne!(
            theme.color("ui.editor.message.tagDelimiter"),
            theme.color("ui.editor.message.tagName"),
            "angle brackets must not share the tag-name colour"
        );
        assert_ne!(
            theme.color("ui.editor.message.paramValue"),
            theme.color("ui.editor.message.literalString"),
            "attribute values must not share the plain-string colour"
        );
    }

    /// The rendered markup must actually use those colours, not merely define them.
    #[test]
    fn markup_spans_carry_the_delimiter_and_value_colours() {
        let theme = Theme::load(true);
        let spans = markup_spans(r#"<a href='x'>t</a>"#, &theme);
        let seen = colours(&spans);
        assert!(seen.contains(&theme.color("ui.editor.message.tagDelimiter")));
        assert!(seen.contains(&theme.color("ui.editor.message.paramValue")));
        assert!(seen.contains(&theme.color("ui.editor.message.paramName")));
        assert_eq!(
            spans.iter().map(|s| s.text.as_str()).collect::<String>(),
            r#"<a href='x'>t</a>"#
        );
    }

    /// Both of Burp's bundled themes must resolve, since Burp ships a light mode too.
    #[test]
    fn both_bundled_themes_resolve() {
        for dark in [true, false] {
            let theme = Theme::load(dark);
            assert_eq!(theme.dark, dark);
            assert!(theme.keys().count() > 100, "theme looks truncated");
            assert_ne!(
                theme.color("ui.background.1"),
                theme.color("ui.icon.default"),
                "background.1 unresolved"
            );
        }
    }

    #[test]
    fn script_and_markup_highlighting_never_panics_on_multibyte_utf8_or_binary_replacement_chars() {
        let theme = Theme::load(false);
        for msg in [
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n\u{FFFD}X9\u{FFFD}Q\u{FFFD}{\u{FFFD} \"hello\u{FFFD}world\" /*\u{FFFD}*/ //\u{FFFD}\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n@decorator const email = \"a\\\"b@c.com\"; @\nfunction f() { return @foo; }",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<![CDATA[\u{FFFD}unclosed<div data-\u{FFFD}=\"\u{FFFD}\">\u{FFFD}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"k\u{FFFD}\": \"v\u{FFFD}\", \"n\": 123}",
        ] {
            let out = spans(msg, &theme);
            assert!(!out.is_empty());
        }
    }
}
