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
fn body_spans(body: &str, content_type: String, theme: &Theme) -> Vec<Span> {
    let detected = detect(body, &content_type);
    match detected {
        Body::Json => json_spans(body, theme),
        Body::Markup => markup_spans(body, theme),
        Body::UrlEncoded => urlencoded_spans(body, theme),
        Body::Script => script_spans(body, theme),
        Body::Plain => {
            if content_type.contains("form-urlencoded") {
                urlencoded_spans(body, theme)
            } else {
                vec![Span::new(body.to_string(), theme.color("ui.editor.message.literalString"))]
            }
        }
    }
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
            let end = tail.find("]]>").map(|e| e + 3).unwrap_or(tail.len());
            out.push(Span::new("<![CDATA[".to_string(), delimiter));
            out.push(Span::new(tail[9..end.saturating_sub(3)].to_string(), cdata));
            out.push(Span::new("]]>".to_string(), delimiter));
            rest = &tail[end..];
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
        if let Some(at) = rest.find("//") {
            push_plain(&mut out, &rest[..at], string);
            let line_end = rest[at..].find('\n').map(|n| n + 1).unwrap_or(rest.len());
            out.push(Span::new(rest[at..at + line_end].to_string(), comment));
            rest = &rest[at + line_end..];
            continue;
        }
        if let Some(at) = rest.find("/*") {
            push_plain(&mut out, &rest[..at], string);
            let end = rest[at..].find("*/").map(|e| e + 2).unwrap_or(rest.len());
            out.push(Span::new(rest[at..at + end].to_string(), comment));
            rest = &rest[at + end..];
            continue;
        }
        let first = rest.chars().next().unwrap();
        if first == '"' || first == '\'' || first == '`' {
            let quote = first;
            let mut chars = rest.chars();
            chars.next();
            let mut literal = String::new();
            for ch in chars {
                literal.push(ch);
                if ch == '\\' {
                    continue;
                }
                if ch == quote {
                    break;
                }
            }
            let taken: usize = literal.chars().count();
            out.push(Span::new(format!("{quote}{literal}"), string));
            rest = &rest[(1 + taken).min(rest.len())..];
            continue;
        }
        if first == '@' {
            let word: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            let consumed = word.len();
            out.push(Span::new(word, annotation));
            rest = &rest[consumed..];
            continue;
        }
        if first.is_ascii_digit() {
            let word: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            let consumed = word.len();
            out.push(Span::new(word, number));
            rest = &rest[consumed..];
            continue;
        }
        if first.is_alphabetic() || first == '_' || first == '$' {
            let word: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            let colour = if KEYWORDS.contains(&word.as_str()) { keyword } else { string };
            let consumed = word.len();
            out.push(Span::new(word, colour));
            rest = &rest[consumed..];
            continue;
        }
        // Always advance: a zero-width step here would loop forever while appending spans, which
        // hangs the UI and eats all available memory.
        let step = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '"' || c == '\'' || c == '`'))
            .unwrap_or(rest.len())
            .max(1)
            .min(rest.len());
        out.push(Span::new(rest[..step].to_string(), string));
        rest = &rest[step..];
    }
    out
}

/// Renders the spans as an egui text job.
pub fn layout(message: &str, theme: &Theme) -> LayoutJob {
    layout_job(spans(message, theme))
}

/// Renders pre-computed spans, so callers that colour incrementally can skip the parse.
pub fn layout_job(spans: Vec<Span>) -> LayoutJob {
    let mut job = LayoutJob::default();
    for span in spans {
        job.append(
            &span.text,
            0.0,
            TextFormat {
                font_id: FontId::new(12.0, FontFamily::Monospace),
                color: span.colour,
                // Underline stands in for bold, which a monospace layout job cannot express.
                underline: if span.bold {
                    Stroke::new(1.0, span.colour)
                } else {
                    Stroke::NONE
                },
                ..Default::default()
            },
        );
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
    let job = layout(message, theme);
    let frame = eframe::egui::Frame::new()
        .fill(background)
        .inner_margin(6.0)
        .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.background.3")));
    frame.show(ui, |ui| {
        eframe::egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            ui.add(
                eframe::egui::Label::new(job).selectable(true),
            );
        });
    });
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
    eframe::egui::Frame::new()
        .fill(background)
        .inner_margin(6.0)
        .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.background.3")))
        .show(ui, |ui| {
            ui.add(
                eframe::egui::TextEdit::multiline(text)
                    .font(eframe::egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(10),
            );
        });
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
}
