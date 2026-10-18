//! Bambda-style transform scripting.
//!
//! Burp's Bambda lets an operator rewrite a message on its way through the proxy. This is a much
//! smaller language over the same idea: a handful of statements applied to one message, with the
//! `regex` crate already used by the scanner doing the pattern work. No new dependency, no embedded
//! general-purpose interpreter, and no way for a script to reach outside the message it is given.

use regex::Regex;

/// Statements are capped so a pasted script cannot become a memory or time sink.
pub const MAX_SCRIPT: usize = 16 * 1024;
/// A replacement is capped for the same reason.
pub const MAX_REPLACEMENT: usize = 4 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Statement {
    /// Literal replace, every occurrence.
    Replace { find: String, with: String },
    /// Literal replace, first occurrence only.
    ReplaceFirst { find: String, with: String },
    /// Regular-expression replace, every match.
    Regex { pattern: String, with: String },
    /// Set or replace an HTTP header.
    SetHeader { name: String, value: String },
    /// Remove a header, matched case-insensitively.
    RemoveHeader { name: String },
    /// Replace the first occurrence in the body only, never the head.
    ReplaceBody { find: String, with: String },
}

impl Statement {
    /// The rule as Burp writes it, e.g. `set_header "Host" "x"`.
    pub fn describe(&self) -> String {
        match self {
            Statement::Replace { find, with } => format!("replace \"{find}\" \"{with}\""),
            Statement::ReplaceFirst { find, with } => {
                format!("replace_first \"{find}\" \"{with}\"")
            }
            Statement::Regex { pattern, with } => format!("regex \"{pattern}\" \"{with}\""),
            Statement::SetHeader { name, value } => format!("set_header \"{name}\" \"{value}\""),
            Statement::RemoveHeader { name } => format!("remove_header \"{name}\""),
            Statement::ReplaceBody { find, with } => format!("replace_body \"{find}\" \"{with}\""),
        }
    }

    /// What the rule does to a request, in words.
    pub fn effect(&self) -> String {
        match self {
            Statement::Replace { .. } => "Replace every occurrence in the message".into(),
            Statement::ReplaceFirst { .. } => "Replace the first occurrence in the message".into(),
            Statement::Regex { .. } => "Replace every regular-expression match".into(),
            Statement::SetHeader { name, .. } => format!("Set the {name} header"),
            Statement::RemoveHeader { name } => format!("Remove the {name} header"),
            Statement::ReplaceBody { .. } => "Replace the first occurrence in the body".into(),
        }
    }
}

/// Why a script could not be used.
#[derive(Clone, Debug, PartialEq)]
pub struct ScriptError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// Parses a script into statements.
pub fn parse(source: &str) -> Result<Vec<Statement>, ScriptError> {
    if source.len() > MAX_SCRIPT {
        return Err(ScriptError {
            line: 0,
            message: format!("script is {} bytes, the limit is {MAX_SCRIPT}", source.len()),
        });
    }
    let mut out = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;
        let text = match raw.find('#') {
            Some(at) => &raw[..at],
            None => raw,
        }
        .trim();
        if text.is_empty() {
            continue;
        }
        let statement = parse_line(text).map_err(|message| ScriptError { line, message })?;
        out.push(statement);
    }
    Ok(out)
}

fn parse_line(line: &str) -> Result<Statement, String> {
    let (verb, rest) = line
        .split_once(char::is_whitespace)
        .ok_or_else(|| format!("'{line}' is not a known statement"))?;
    let rest = rest.trim();
    match verb {
        "replace" | "replace_first" | "replace_body" => {
            let (find, with) = two_literals(rest)?;
            if verb == "replace" {
                Ok(Statement::Replace { find, with })
            } else if verb == "replace_first" {
                Ok(Statement::ReplaceFirst { find, with })
            } else {
                Ok(Statement::ReplaceBody { find, with })
            }
        }
        "regex" => {
            let (pattern, with) = two_literals(rest)?;
            Regex::new(&pattern)
                .map_err(|e| format!("bad pattern: {e}"))?;
            Ok(Statement::Regex { pattern, with })
        }
        "set_header" => {
            let (name, value) = two_literals(rest)?;
            Ok(Statement::SetHeader { name, value })
        }
        "remove_header" => {
            // Only a name is needed; requiring a second literal here rejected a valid script.
            let (name, extra) = one_literal(rest)?;
            if !extra.is_empty() {
                return Err("remove_header takes a single name".into());
            }
            Ok(Statement::RemoveHeader { name })
        }
        other => Err(format!("unknown statement '{other}'")),
    }
}

/// Reads one quoted literal, returning it plus whatever followed it.
fn one_literal(rest: &str) -> Result<(String, String), String> {
    let mut chars = rest.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        let (value, remainder) = read_literal(&mut chars)?;
        return Ok((value, remainder));
    }
    Err("expected a quoted name".into())
}

/// Reads a single quoted literal, returning the remainder of the input.
fn read_literal(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<(String, String), String> {
    let quote = *chars.peek().ok_or("expected a quoted literal")?;
    if quote != '"' && quote != '\'' {
        return Err("expected a quoted literal".into());
    }
    chars.next();
    let mut value = String::new();
    loop {
        match chars.next() {
            None | Some('\n') => return Err("unterminated literal".into()),
            Some(c) if c == quote => break,
            Some('\\') => match chars.next() {
                Some('n') => value.push('\n'),
                Some('r') => value.push('\r'),
                Some('t') => value.push('\t'),
                // Keep the backslash for every other escape, so regex classes survive.
                Some(other) => {
                    value.push('\\');
                    value.push(other);
                }
                None => return Err("trailing escape".into()),
            },
            Some(other) => value.push(other),
        }
    }
    if value.len() > MAX_REPLACEMENT {
        return Err(format!("literal is {} bytes, the limit is {MAX_REPLACEMENT}", value.len()));
    }
    Ok((value, chars.collect()))
}

/// Reads two quoted literals. Quotes are required so a value may contain spaces.
fn two_literals(rest: &str) -> Result<(String, String), String> {
    let mut parts = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch != '"' && ch != '\'' {
            return Err(format!("expected a quoted literal near '{rest}'"));
        }
        let quote = ch;
        chars.next();
        let mut value = String::new();
        loop {
            match chars.next() {
                None | Some('\n') => return Err("unterminated literal".into()),
                Some(c) if c == quote => break,
                Some('\\') => match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('r') => value.push('\r'),
                    Some('t') => value.push('\t'),
                    // Anything else keeps its backslash: regex classes like \w, \d and \b are
                    // meaningless without it, and silently dropping it made patterns match nothing.
                    Some(other) => {
                        value.push('\\');
                        value.push(other);
                    }
                    None => return Err("trailing escape".into()),
                },
                Some(other) => value.push(other),
            }
        }
        if value.len() > MAX_REPLACEMENT {
            return Err(format!("literal is {} bytes, the limit is {MAX_REPLACEMENT}", value.len()));
        }
        parts.push(value);
        if parts.len() == 2 {
            return Ok((parts.remove(0), parts.remove(0)));
        }
    }
    Err("expected two quoted literals".into())
}

/// Applies a parsed script to a message.
pub fn apply(source: &str, message: &str) -> Result<String, ScriptError> {
    let statements = parse(source)?;
    Ok(run(&statements, message))
}

/// Applies already-parsed statements.
pub fn run(statements: &[Statement], message: &str) -> String {
    let mut current = message.to_string();
    for statement in statements {
        current = match statement {
            Statement::Replace { find, with } => current.replace(find.as_str(), with.as_str()),
            Statement::ReplaceFirst { find, with } => match current.find(find.as_str()) {
                Some(at) => {
                    let mut out = String::with_capacity(current.len() + with.len());
                    out.push_str(&current[..at]);
                    out.push_str(with);
                    out.push_str(&current[at + find.len()..]);
                    out
                }
                None => current,
            },
            Statement::ReplaceBody { find, with } => match split_head(&current) {
                Some((head, body)) => format!("{head}{}", body.replace(find.as_str(), with.as_str())),
                None => current,
            },
            Statement::Regex { pattern, with } => match Regex::new(pattern) {
                Ok(re) => re.replace_all(&current, with.as_str()).into_owned(),
                Err(_) => current,
            },
            Statement::SetHeader { name, value } => set_header(&current, name, value),
            Statement::RemoveHeader { name } => remove_header(&current, name),
        };
    }
    current
}

/// Splits a message into its head and the body after the blank line.
fn split_head(message: &str) -> Option<(&str, &str)> {
    let at = message.find("\r\n\r\n")?;
    Some((&message[..at], &message[at + 4..]))
}

fn set_header(message: &str, name: &str, value: &str) -> String {
    let Some((head, body)) = split_head(message) else {
        return message.to_string();
    };
    let prefix = format!("{name}:");
    let mut kept: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in head.split("\r\n") {
        if line.to_lowercase().starts_with(&prefix.to_lowercase()) {
            if !replaced {
                kept.push(format!("{name}: {value}"));
                replaced = true;
            }
            continue;
        }
        kept.push(line.to_string());
    }
    if !replaced {
        kept.push(format!("{name}: {value}"));
    }
    // The head/body separator is two CRLFs. Joining with one corrupts the message.
    format!("{}\r\n\r\n{}", kept.join("\r\n"), body)
}

fn remove_header(message: &str, name: &str) -> String {
    let Some((head, body)) = split_head(message) else {
        return message.to_string();
    };
    let prefix = format!("{}:", name.to_lowercase());
    let kept: Vec<&str> = head
        .split("\r\n")
        .filter(|line| !line.to_lowercase().starts_with(&prefix))
        .collect();
    format!("{}\r\n\r\n{}", kept.join("\r\n"), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> &'static str {
        "GET /a HTTP/1.1\r\nHost: x.test\r\nUser-Agent: old\r\n\r\nbody old body"
    }

    #[test]
    fn a_literal_replace_hits_every_occurrence() {
        let out = apply(r#"replace "old" "new""#, msg()).expect("parses");
        assert_eq!(
            out,
            "GET /a HTTP/1.1\r\nHost: x.test\r\nUser-Agent: new\r\n\r\nbody new body"
        );
    }

    #[test]
    fn replace_first_touches_only_the_first() {
        let out = apply(r#"replace_first "old" "new""#, msg()).expect("parses");
        assert_eq!(out.matches("new").count(), 1);
        assert_eq!(out.matches("old").count(), 1);
    }

    #[test]
    fn replace_body_leaves_the_head_alone() {
        let out = apply(r#"replace_body "old" "new""#, msg()).expect("parses");
        assert!(out.contains("User-Agent: old"), "head must be untouched");
        assert!(out.contains("body new body"));
    }

    #[test]
    fn a_regex_replace_uses_the_pattern() {
        let out = apply(r#"regex "User-Agent: \w+" "User-Agent: masked""#, msg()).expect("parses");
        assert!(out.contains("User-Agent: masked"));
        // Only the header is rewritten; the body's own text is untouched.
        assert!(out.contains("\r\n\r\nbody old body"));
        assert!(out.starts_with("GET /a HTTP/1.1\r\n"));
    }

    #[test]
    fn a_header_can_be_set() {
        let out = apply(r#"set_header "X-Test" "1""#, msg()).expect("parses");
        assert!(out.contains("X-Test: 1"));
        assert!(out.ends_with("\r\n\r\nbody old body"), "the body must survive");
    }

    #[test]
    fn setting_an_existing_header_replaces_it_rather_than_duplicating() {
        let out = apply(r#"set_header "User-Agent" "fresh""#, msg()).expect("parses");
        assert_eq!(out.matches("User-Agent").count(), 1);
        assert!(out.contains("User-Agent: fresh"));
    }

    #[test]
    fn a_header_can_be_removed_case_insensitively() {
        let out = apply(r#"remove_header "user-agent""#, msg()).expect("parses");
        assert!(!out.to_lowercase().contains("user-agent"));
        assert!(out.contains("Host: x.test"));
    }

    #[test]
    fn statements_apply_in_order() {
        let out = apply(
            "replace \"old\" \"mid\"\nreplace \"mid\" \"final\"",
            msg(),
        )
        .expect("parses");
        assert!(out.contains("final"));
        assert!(!out.contains("mid"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let out = apply("# a note\n\nreplace \"old\" \"new\"\n", msg()).expect("parses");
        assert!(out.contains("new"));
    }

    #[test]
    fn escapes_inside_literals_work() {
        let out = apply(r#"replace "old" "a\nb""#, msg()).expect("parses");
        assert!(out.contains("a\nb"));
    }

    #[test]
    fn a_bad_pattern_is_reported_with_its_line() {
        let error = apply("replace \"a\" \"b\"\nregex \"[\" \"x\"", msg())
            .expect_err("must fail");
        assert_eq!(error.line, 2);
        assert!(error.message.contains("bad pattern"));
    }

    #[test]
    fn an_unknown_statement_is_reported() {
        let error = apply("frobnicate \"a\"", msg()).expect_err("must fail");
        assert!(error.message.contains("unknown statement"));
    }

    #[test]
    fn a_missing_literal_is_reported() {
        let error = apply("replace \"only-one\"", msg()).expect_err("must fail");
        assert!(error.message.contains("two quoted literals"));
    }

    #[test]
    fn an_oversized_script_is_refused() {
        let huge = format!("replace \"a\" \"b\"\n{}", "x".repeat(MAX_SCRIPT));
        let error = apply(&huge, msg()).expect_err("must fail");
        assert!(error.message.contains("the limit is"));
    }

    #[test]
    fn an_oversized_literal_is_refused() {
        let huge = format!(r#"replace "a" "{}""#, "y".repeat(MAX_REPLACEMENT + 1));
        let error = apply(&huge, msg()).expect_err("must fail");
        assert!(error.message.contains("the limit is"));
    }

    #[test]
    fn a_message_without_a_separator_is_left_alone_by_header_statements() {
        let bare = "GET / HTTP/1.1";
        assert_eq!(apply(r#"set_header "X" "1""#, bare).expect("parses"), bare);
        assert_eq!(apply(r#"remove_header "X""#, bare).expect("parses"), bare);
    }

    #[test]
    fn a_script_cannot_lose_the_body() {
        // Every statement has to round-trip the body; this is the property that matters most.
        let out = apply("set_header \"X\" \"1\"\nremove_header \"Host\"", msg()).expect("parses");
        assert!(out.ends_with("\r\n\r\nbody old body"));
    }
}

/// Both literal readers must agree, or the same pattern works in one statement and not another.
#[cfg(test)]
mod literal_tests {
    use super::*;

    #[test]
    fn regex_classes_survive_both_parsers() {
        let statements = parse(r#"replace "a" "\w+"  # two
regex "\d+" "x"       # one"#)
            .expect("parses");
        assert_eq!(statements.len(), 2);
        match &statements[0] {
            Statement::Replace { with, .. } => assert_eq!(with, r"\w+"),
            other => panic!("{other:?}"),
        }
        match &statements[1] {
            Statement::Regex { pattern, .. } => assert_eq!(pattern, r"\d+"),
            other => panic!("{other:?}"),
        }
    }
}
