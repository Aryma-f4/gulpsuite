//! Recorded login replayer.
//!
//! Gulp's `RECORDED_LOGIN_REPLAYER` tool records a login exchange and replays it later, optionally
//! with the captured session state. That is what this does: capture the request/response pairs for
//! one host from the proxy history, then send them again through the proxy and report where the
//! replay diverged from the recording.

use std::time::Duration;

/// One recorded request/response pair.
#[derive(Clone, Debug)]
pub struct Step {
    pub method: String,
    pub url: String,
    pub request: String,
    pub response: String,
    pub status: u16,
}

impl Step {
    /// The status line of the recorded response, if there is one.
    pub fn recorded_status_line(&self) -> String {
        self.response.lines().next().unwrap_or("").trim().to_string()
    }
}

/// A named recording of a login exchange.
#[derive(Clone, Debug, Default)]
pub struct Recording {
    pub name: String,
    pub host: String,
    pub steps: Vec<Step>,
}

impl Recording {
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// What happened when a recorded step was sent again.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// The replay returned the same status as the recording.
    Matched,
    /// The replay succeeded but with a different status.
    Changed { recorded: u16, replayed: u16 },
    /// The replay could not be sent at all.
    Failed(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Matched => "matched".into(),
            Outcome::Changed { recorded, replayed } => format!("{recorded} -> {replayed}"),
            Outcome::Failed(why) => format!("failed: {why}"),
        }
    }

    pub fn is_problem(&self) -> bool {
        !matches!(self, Outcome::Matched)
    }
}

/// The result of replaying a whole recording.
#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub outcomes: Vec<Outcome>,
}

impl ReplayReport {
    pub fn matched(&self) -> usize {
        self.outcomes.iter().filter(|o| !o.is_problem()).count()
    }

    pub fn problems(&self) -> usize {
        self.outcomes.iter().filter(|o| o.is_problem()).count()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} of {} step(s) matched, {} diverged",
            self.matched(),
            self.outcomes.len(),
            self.problems()
        )
    }
}

/// Picks the steps belonging to one host, oldest first, so a login flow replays in the order it ran.
pub fn steps_for_host<'a>(
    steps: impl Iterator<Item = &'a Step>,
    host: &str,
) -> Vec<Step> {
    let mut chosen: Vec<Step> = steps.filter(|s| s.url.contains(host)).cloned().collect();
    // A login flow is short; the most recent exchange is the one worth replaying.
    if chosen.len() > 50 {
        chosen.drain(..chosen.len() - 50);
    }
    chosen
}

/// Substitutes session placeholders into a recorded request.
///
/// A recorded login usually carries a CSRF token or a session cookie in its body or headers. Those
/// are captured values, so replaying them verbatim usually fails. Markers of the form
/// `{{csrf}}` / `{{cookie:name}}` in a recording are replaced here with live values where available.
pub fn substitute(request: &str, live: &[(String, String)]) -> String {
    let mut out = request.to_string();
    for (name, value) in live {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
    }
    crate::intruder::sync_content_length(&out)
}

/// Extracts a token from a response body given a field name (JSON `"name": "val"` or HTML `<input name="..." value="...">`), for `{{name}}` substitution.
pub fn token_from(body: &str, name: &str) -> Option<String> {
    let marker = format!("\"{name}\"");
    if let Some(at) = body.find(&marker) {
        let rest = &body[at + marker.len()..];
        if let Some(colon) = rest.find(':') {
            let after = rest[colon + 1..].trim_start();
            if let Some(quote) = after.chars().next().filter(|&q| q == '"' || q == '\'') {
                let after = &after[1..];
                if let Some(end) = after.find(quote) {
                    return Some(after[..end].to_string());
                }
            }
        }
    }
    // Fallback: HTML `<input ... name="<name>" ... value="<val>">`
    let lower = body.to_ascii_lowercase();
    let name_lc = name.to_ascii_lowercase();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find("<input") {
        let start = pos + rel;
        let Some(end_rel) = lower[start..].find('>') else {
            break;
        };
        let tag = &body[start..start + end_rel + 1];
        let tag_lc = &lower[start..start + end_rel + 1];
        let matches_name = [
            format!("name=\"{name_lc}\""),
            format!("name='{name_lc}'"),
            format!("name={name_lc} "),
            format!("name={name_lc}>"),
        ]
        .iter()
        .any(|pat| tag_lc.contains(pat));
        if matches_name {
            if let Some(val_idx) = tag_lc.find("value=") {
                let after_val = tag[val_idx + 6..].trim_start();
                if let Some(q) = after_val.chars().next().filter(|&c| c == '"' || c == '\'') {
                    let inner = &after_val[1..];
                    if let Some(end_q) = inner.find(q) {
                        return Some(inner[..end_q].to_string());
                    }
                } else {
                    let token: String = after_val
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != '>' && *c != '/')
                        .collect();
                    if !token.is_empty() {
                        return Some(token);
                    }
                }
            }
        }
        pos = start + end_rel + 1;
    }
    None
}

/// The placeholder names a recording uses, in the order they first appear.
///
/// A recording marks a value it wants filled at replay time as `{{name}}`, so the names here are
/// what the replayer has to look for in each response.
pub fn markers(requests: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for request in requests {
        let mut rest = request.as_str();
        while let Some(start) = rest.find("{{") {
            let Some(offset) = rest[start + 2..].find("}}") else { break };
            let name = rest[start + 2..start + 2 + offset].trim().to_string();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
            rest = &rest[start + 2 + offset + 2..];
        }
    }
    out
}

/// The value of a `Set-Cookie` header in a response.
pub fn cookie_from(response: &str, name: &str) -> Option<String> {
    for line in response.lines() {
        let Some((header, value)) = line.split_once(':') else { continue };
        if !header.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let pair = value.trim();
        let Some((cookie_name, cookie_value)) = pair.split_once('=') else { continue };
        if cookie_name.trim() == name {
            return Some(cookie_value.split(';').next().unwrap_or("").trim().to_string());
        }
    }
    None
}

/// How long to wait between replayed steps. Gulp exposes this; a default keeps a flow from tripping
/// rate limiting while still being fast.
pub fn default_pace() -> Duration {
    Duration::from_millis(250)
}

/// A recording is only worth replaying if it actually contains a login: something that returns a
/// session cookie, or a redirect into an authenticated area.
pub fn looks_like_login(recording: &Recording) -> bool {
    recording.steps.iter().any(|step| {
        step.response.to_lowercase().contains("set-cookie")
            || (300..400).contains(&step.status)
            || step.url.contains("login")
            || step.url.contains("signin")
            || step.url.contains("auth")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(url: &str, status: u16, response: &str) -> Step {
        Step {
            method: "POST".into(),
            url: url.into(),
            request: format!("POST {url} HTTP/1.1\r\n\r\n"),
            response: response.into(),
            status,
        }
    }

    #[test]
    fn only_the_chosen_host_is_recorded() {
        let all = vec![
            step("https://a.test/login", 200, ""),
            step("https://b.test/other", 200, ""),
            step("https://a.test/home", 200, ""),
        ];
        let chosen = steps_for_host(all.iter(), "a.test");
        assert_eq!(chosen.len(), 2);
        assert!(chosen.iter().all(|s| s.url.contains("a.test")));
    }

    #[test]
    fn a_long_history_is_trimmed_to_the_most_recent() {
        let all: Vec<Step> = (0..80).map(|i| step(&format!("https://a.test/{i}"), 200, "")).collect();
        let chosen = steps_for_host(all.iter(), "a.test");
        assert_eq!(chosen.len(), 50);
        // The newest is kept.
        assert!(chosen.last().unwrap().url.ends_with("/79"));
    }

    #[test]
    fn matching_steps_are_reported_as_matched() {
        let report = ReplayReport {
            outcomes: vec![Outcome::Matched, Outcome::Matched],
        };
        assert_eq!(report.matched(), 2);
        assert_eq!(report.problems(), 0);
        assert!(report.summary().contains("2 of 2"));
    }

    #[test]
    fn a_changed_status_is_a_problem() {
        let report = ReplayReport {
            outcomes: vec![Outcome::Matched, Outcome::Changed { recorded: 302, replayed: 401 }],
        };
        assert_eq!(report.problems(), 1);
        assert_eq!(
            Outcome::Changed { recorded: 302, replayed: 401 }.label(),
            "302 -> 401"
        );
    }

    #[test]
    fn a_failure_is_a_problem() {
        let outcome = Outcome::Failed("connection refused".into());
        assert!(outcome.is_problem());
        assert!(outcome.label().starts_with("failed:"));
    }

    #[test]
    fn placeholders_are_substituted() {
        let request = "POST /login HTTP/1.1\r\n\r\ncsrf={{csrf}}&token={{token}}";
        let live = vec![("csrf".to_string(), "ABC".to_string()), ("token".to_string(), "XYZ".to_string())];
        let out = substitute(request, &live);
        assert!(out.contains("csrf=ABC"));
        assert!(out.contains("token=XYZ"));
        assert!(!out.contains("{{"));
    }

    #[test]
    fn substitution_leaves_unknown_placeholders_alone() {
        let out = substitute("value={{unknown}}", &[]);
        assert_eq!(out, "value={{unknown}}");
    }

    #[test]
    fn tokens_are_read_out_of_a_json_body() {
        let body = r#"{"csrfToken":"abc123","other":"x"}"#;
        assert_eq!(token_from(body, "csrfToken").as_deref(), Some("abc123"));
        assert_eq!(token_from(body, "missing"), None);
    }

    #[test]
    fn tokens_are_read_from_html_input_tags_and_substitute_updates_content_length() {
        let html = r#"<form><input type="hidden" name="csrf" value="tok_9876543210"></form>"#;
        assert_eq!(token_from(html, "csrf").as_deref(), Some("tok_9876543210"));
        let req = "POST /login HTTP/1.1\r\nHost: a.test\r\nContent-Length: 13\r\n\r\ncsrf={{csrf}}";
        let sub = substitute(req, &[("csrf".into(), "tok_9876543210".into())]);
        assert!(sub.contains("Content-Length: 19\r\n"), "got: {sub}");
        assert!(sub.ends_with("\r\n\r\ncsrf=tok_9876543210"));
    }

    #[test]
    fn a_token_with_the_wrong_shape_is_not_returned() {
        assert_eq!(token_from(r#"{"n":123}"#, "n"), None);
    }

    #[test]
    fn a_login_is_recognised_by_a_session_cookie() {
        let recording = Recording {
            name: "x".into(),
            host: "a.test".into(),
            steps: vec![step("https://a.test/", 200, "Set-Cookie: sid=1\r\n\r\n")],
        };
        assert!(looks_like_login(&recording));
    }

    #[test]
    fn a_login_is_recognised_by_a_redirect_or_a_login_path() {
        let by_redirect = Recording { steps: vec![step("https://a.test/", 302, "")], ..Default::default() };
        assert!(looks_like_login(&by_redirect));
        let by_path = Recording { steps: vec![step("https://a.test/login", 200, "")], ..Default::default() };
        assert!(looks_like_login(&by_path));
    }

    #[test]
    fn ordinary_traffic_is_not_a_login() {
        let recording = Recording {
            steps: vec![step("https://a.test/style.css", 200, "body{}")],
            ..Default::default()
        };
        assert!(!looks_like_login(&recording));
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    #[test]
    fn placeholders_are_listed_in_the_order_they_appear() {
        let requests = vec![
            "POST /login HTTP/1.1\r\n\r\nuser=a&token={{csrf}}\r\n".to_string(),
            "GET /x {{token}} {{csrf}}".to_string(),
        ];
        assert_eq!(markers(requests.into_iter()), vec!["csrf", "token"]);
    }

    #[test]
    fn a_request_without_placeholders_has_no_markers() {
        assert!(markers(vec!["GET / HTTP/1.1\r\n\r\n".to_string()].into_iter()).is_empty());
    }

    #[test]
    fn an_unclosed_placeholder_is_ignored() {
        assert!(markers(vec!["value={{oops".to_string()].into_iter()).is_empty());
    }

    #[test]
    fn a_set_cookie_value_is_read_out_of_a_response() {
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/; HttpOnly\r\n\r\nbody";
        assert_eq!(cookie_from(response, "session").as_deref(), Some("abc123"));
        assert_eq!(cookie_from(response, "missing"), None);
    }

    #[test]
    fn a_cookie_without_a_value_is_not_returned() {
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie: session\r\n\r\n";
        assert_eq!(cookie_from(response, "session"), None);
    }

    #[test]
    fn a_cookie_name_is_matched_exactly() {
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=abc; Path=/\r\n\r\n";
        assert_eq!(cookie_from(response, "sessionid").as_deref(), Some("abc"));
        assert_eq!(cookie_from(response, "session"), None);
    }
}
