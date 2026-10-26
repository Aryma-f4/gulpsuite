//! Response analysis.
//!
//! Gulp models this as `http/message/responses/analysis/*`: a keywords analyser, a variations
//! analyser and attribute extraction. The variations analyser is the useful one for testing — it
//! shows which parts of a response are shared across a group and which are unique, which is where an
//! injected value can land.

use std::collections::HashMap;

/// A keyword found in a response, with how many times it occurs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keyword {
    pub text: String,
    pub count: usize,
}

/// An HTML/XML attribute name seen in a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub count: usize,
}

/// Splits a raw response into its head and body, tolerating a body without a blank-line separator.
pub fn split_message(raw: &str) -> (&str, &str) {
    match raw.find("\r\n\r\n") {
        Some(at) => (&raw[..at], &raw[at + 4..]),
        None => match raw.find("\n\n") {
            Some(at) => (&raw[..at], &raw[at + 2..]),
            None => (raw, ""),
        },
    }
}

/// Whether a body looks like HTML or XML, so markup analysis is not run on plain text.
pub fn is_markup(content_type: &str, body: &str) -> bool {
    let lowered = content_type.to_lowercase();
    if lowered.contains("html") || lowered.contains("xml") || lowered.contains("+xml") {
        return true;
    }
    body.trim_start().starts_with('<')
}

/// Interesting tokens in a body: words, numbers, and quoted strings, ranked by how notable they are.
///
/// Gulp surfaces these so an operator can see identifiers, prices and codes without reading the whole
/// response. Very common words are dropped because they drown out everything else.
pub fn keywords(body: &str, limit: usize) -> Vec<Keyword> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for token in tokens(body) {
        if token.chars().count() < 3 || token.len() > 80 {
            continue;
        }
        // Pure English filler never matters and always dominates the counts.
        if STOP_WORDS.contains(&token.to_lowercase().as_str()) {
            continue;
        }
        *counts.entry(token).or_default() += 1;
    }
    let mut found: Vec<Keyword> = counts
        .into_iter()
        .map(|(text, count)| Keyword { text, count })
        .collect();
    // Most frequent first; ties broken by text so the order is stable between runs.
    found.sort_by(|a, b| b.count.cmp(&a.count).then(a.text.cmp(&b.text)));
    found.truncate(limit);
    found
}

/// Splits a body into candidate tokens: quoted strings, words, and numbers.
fn tokens(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = body.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '"' || ch == '\'' {
            let quote = ch;
            let mut literal = String::new();
            index += 1;
            while index < chars.len() && chars[index] != quote {
                if chars[index].is_control() {
                    break;
                }
                literal.push(chars[index]);
                index += 1;
            }
            index += 1;
            if !literal.is_empty() && literal.chars().count() <= 80 {
                out.push(literal);
            }
            continue;
        }
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '@' {
            let mut token = String::new();
            while index < chars.len()
                && (chars[index].is_alphanumeric()
                    || matches!(chars[index], '_' | '-' | '.' | '@'))
            {
                token.push(chars[index]);
                index += 1;
            }
            // A trailing separator is punctuation, not part of the token.
            let trimmed = token.trim_end_matches(['.', '-', '_']);
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
            continue;
        }
        index += 1;
    }
    out
}

const STOP_WORDS: [&str; 24] = [
    "the", "and", "for", "that", "with", "this", "from", "have", "has", "was", "were", "not", "but",
    "you", "all", "can", "will", "one", "our", "out", "are", "its", "his", "her",
];

/// Attribute names in a markup body, with occurrence counts.
///
/// Each tag is scanned as a whole: the element name is skipped and then `name = value` triples are
/// read until the closing `>`. Only parsing the first word after `<` would find at most one
/// attribute per tag and silently miss every one after it.
pub fn attributes(body: &str, limit: usize) -> Vec<Attribute> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != '<' {
            index += 1;
            continue;
        }
        // Skip comments, declarations and closing tags: they carry no attributes to report.
        let next = bytes.get(index + 1).copied().unwrap_or(' ');
        if next == '!' || next == '/' || next == '?' {
            index = skip_to_tag_end(&bytes, index).saturating_add(1);
            continue;
        }
        let end = skip_to_tag_end(&bytes, index);
        scan_attributes(&bytes[index + 1..end], &mut counts);
        index = end.saturating_add(1);
    }
    let mut found: Vec<Attribute> = counts
        .into_iter()
        .map(|(name, count)| Attribute { name, count })
        .collect();
    found.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    found.truncate(limit);
    found
}

/// Index of the `>` closing the tag that starts at `start`, or the end of input.
fn skip_to_tag_end(chars: &[char], start: usize) -> usize {
    let mut index = start;
    while index < chars.len() && chars[index] != '>' {
        index += 1;
    }
    index.min(chars.len())
}

/// Reads `name = value` triples out of the inside of one tag.
fn scan_attributes(inside: &[char], counts: &mut HashMap<String, usize>) {
    let mut index = 0;
    // The element name is not an attribute.
    while index < inside.len() && !inside[index].is_whitespace() {
        index += 1;
    }
    while index < inside.len() {
        while index < inside.len() && (inside[index].is_whitespace() || inside[index] == '/') {
            index += 1;
        }
        let name_start = index;
        while index < inside.len()
            && (inside[index].is_alphanumeric()
                || matches!(inside[index], '-' | '_' | ':' | '.'))
        {
            index += 1;
        }
        if index == name_start {
            index += 1;
            continue;
        }
        let name: String = inside[name_start..index].iter().collect::<String>().to_lowercase();
        while index < inside.len() && inside[index].is_whitespace() {
            index += 1;
        }
        if index < inside.len() && inside[index] == '=' {
            *counts.entry(name).or_default() += 1;
            // Step over `=` and the quoted or bare value.
            index += 1;
            while index < inside.len() && inside[index].is_whitespace() {
                index += 1;
            }
            if index < inside.len() && (inside[index] == '"' || inside[index] == '\'') {
                let quote = inside[index];
                index += 1;
                while index < inside.len() && inside[index] != quote {
                    index += 1;
                }
                index += 1;
            } else {
                while index < inside.len()
                    && !inside[index].is_whitespace()
                    && inside[index] != '>'
                {
                    index += 1;
                }
            }
            continue;
        }
        // A bare word with no `=` is not an attribute; the scanner already moved past it.
    }
}

/// How a response differs from the rest of its group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Variation {
    /// Present in every response in the group.
    Shared(usize),
    /// Present in some but not all.
    Partial(usize, usize),
    /// Present in exactly one.
    Unique,
}

/// Gulp's variations analyser, simplified: compare one body against a group of others by splitting
/// both into lines and reporting which lines are shared.
///
/// `baseline` is the body to analyse; `others` are its siblings.
pub fn variations(baseline: &str, others: &[String]) -> Vec<Variation> {
    let baseline_lines: Vec<&str> = baseline.lines().map(str::trim_end).collect();
    let other_sets: Vec<HashMap<&str, usize>> = others
        .iter()
        .map(|body| {
            body.lines()
                .map(str::trim_end)
                .filter(|line| !line.is_empty())
                .fold(HashMap::new(), |mut acc, line| {
                    *acc.entry(line).or_default() += 1;
                    acc
                })
        })
        .collect();

    let mut out = Vec::new();
    for line in baseline_lines {
        if line.trim().is_empty() {
            continue;
        }
        let containing = other_sets
            .iter()
            .filter(|set| set.contains_key(line))
            .count();
        match containing {
            0 => out.push(Variation::Unique),
            n if n == others.len() => out.push(Variation::Shared(containing)),
            n => out.push(Variation::Partial(n, others.len())),
        }
    }
    out
}

/// Counts of each variation kind, for a summary line.
pub fn variation_summary(rows: &[Variation]) -> (usize, usize, usize) {
    let mut unique = 0;
    let mut partial = 0;
    let mut shared = 0;
    for row in rows {
        match row {
            Variation::Unique => unique += 1,
            Variation::Partial(_, _) => partial += 1,
            Variation::Shared(_) => shared += 1,
        }
    }
    (unique, partial, shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_splits_into_head_and_body() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>hi</h1>";
        let (head, body) = split_message(raw);
        assert!(head.starts_with("HTTP/1.1"));
        assert_eq!(body, "<h1>hi</h1>");
    }

    #[test]
    fn a_body_without_a_separator_does_not_panic() {
        let (head, body) = split_message("HTTP/1.1 204 No Content");
        assert_eq!(head, "HTTP/1.1 204 No Content");
        assert_eq!(body, "");
    }

    #[test]
    fn keywords_rank_by_frequency() {
        let body = "order 12345 total 12345 token ABCDEF order";
        let found = keywords(body, 10);
        assert_eq!(found[0], Keyword { text: "12345".into(), count: 2 });
        assert!(found.iter().any(|k| k.text == "order" && k.count == 2));
        assert!(found.iter().any(|k| k.text == "ABCDEF"));
    }

    #[test]
    fn stop_words_are_dropped() {
        let found = keywords("the quick brown fox and the lazy dog", 20);
        assert!(!found.iter().any(|k| k.text == "the"));
        assert!(!found.iter().any(|k| k.text == "and"));
        assert!(found.iter().any(|k| k.text == "quick"));
    }

    #[test]
    fn quoted_strings_are_treated_as_one_token() {
        let found = keywords("name=\"Alexander Smith\" city=Paris", 20);
        assert!(
            found.iter().any(|k| k.text == "Alexander Smith"),
            "got {found:?}"
        );
    }

    #[test]
    fn very_short_tokens_are_ignored() {
        let found = keywords("a bb ccc", 20);
        assert!(!found.iter().any(|k| k.text.len() < 3));
    }

    #[test]
    fn the_keyword_limit_is_respected() {
        let body = (0..200).map(|i| format!("tok{i} ")).collect::<String>();
        assert_eq!(keywords(&body, 5).len(), 5);
    }

    #[test]
    fn attributes_are_extracted_with_counts() {
        let body = r#"<a href="x" class="y"><img src="z" alt="q" class="w"></a>"#;
        let found = attributes(body, 10);
        let class = found.iter().find(|a| a.name == "class").expect("class attribute");
        assert_eq!(class.count, 2);
        assert!(found.iter().any(|a| a.name == "href"));
        assert!(found.iter().any(|a| a.name == "src"));
    }

    #[test]
    fn tag_names_are_not_mistaken_for_attributes() {
        let found = attributes("<html><body><p>text</p></body></html>", 10);
        assert!(found.is_empty(), "no attributes present, got {found:?}");
    }

    #[test]
    fn markup_is_detected_from_content_type_and_shape() {
        assert!(is_markup("text/html; charset=utf-8", ""));
        assert!(is_markup("", "<html>"));
        assert!(!is_markup("application/json", "{}"));
    }

    #[test]
    fn a_line_unique_to_one_response_is_unique() {
        let baseline = "header\ncommon\nunique-token";
        let others = vec!["header\ncommon\nother".to_string()];
        let rows = variations(baseline, &others);
        assert!(rows.contains(&Variation::Unique));
    }

    #[test]
    fn a_line_in_every_response_is_shared() {
        let baseline = "shared\nmine";
        let others = vec!["shared\ntheirs".to_string()];
        let rows = variations(baseline, &others);
        assert!(rows.contains(&Variation::Shared(1)));
    }

    #[test]
    fn a_line_in_some_responses_is_partial() {
        let baseline = "sometimes";
        let others = vec!["sometimes".to_string(), "something else".to_string()];
        let rows = variations(baseline, &others);
        assert!(rows.contains(&Variation::Partial(1, 2)), "got {rows:?}");
    }

    #[test]
    fn with_no_comparators_everything_is_unique() {
        let rows = variations("only line", &[]);
        assert_eq!(rows, vec![Variation::Unique]);
    }

    #[test]
    fn the_summary_counts_each_kind() {
        let rows = vec![Variation::Unique, Variation::Shared(2), Variation::Partial(1, 3)];
        assert_eq!(variation_summary(&rows), (1, 1, 1));
    }

    #[test]
    fn analysis_does_not_run_out_of_handles_on_large_input() {
        // The analyzer must stay bounded on a large body rather than allocating per character.
        let body = "x".repeat(200_000);
        assert!(keywords(&body, 5).len() <= 5);
        assert!(attributes(&body, 5).len() <= 5);
    }
}
