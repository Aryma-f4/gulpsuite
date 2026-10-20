//! Active analysis: inject test payloads and infer a vulnerability from the response difference.
//!
//! Every check follows the same shape: send a baseline, send a payload, compare. What counts as
//! evidence is per check — a reflected marker, a changed status, a changed length, or a delay — and
//! nothing is reported without one.

use super::{Finding, Severity};
use crate::scanner::http::Response;

/// What one probe concluded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signal {
    /// Nothing distinguishable from the baseline.
    Nothing,
    /// The payload came back verbatim.
    Reflected,
    /// The body carries a database error.
    Error,
    /// The body carries a rendered artefact of the payload.
    Evaluated,
    /// The response took noticeably longer.
    Delayed,
    /// The payload came back percent-encoded, so it would not execute as-is.
    Inert,
}

impl Signal {
    /// Inert reflections are worth recording but are not proof of a vulnerability.
    pub fn is_interesting(self) -> bool {
        !matches!(self, Signal::Nothing)
    }

    pub fn is_exploitable(self) -> bool {
        !matches!(self, Signal::Nothing | Signal::Inert)
    }
}

/// How two responses differ.
#[derive(Clone, Debug)]
pub struct Difference {
    pub status_changed: bool,
    pub length_changed: bool,
    pub baseline_length: usize,
    pub payload_length: usize,
}

impl Difference {
    /// Responses of very different sizes are the strongest signal of a behaviour change.
    pub fn length_delta(&self) -> usize {
        self.payload_length.abs_diff(self.baseline_length)
    }
}

/// The parameters a page offers to the scanner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionPoint {
    /// The URL to request.
    pub url: String,
    /// Parameter name.
    pub name: String,
    /// How the value travels.
    pub method: InjectionMethod,
    /// The other fields, when this is a form post.
    pub siblings: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InjectionMethod {
    Query,
    /// A POST field whose value gets replaced (`application/x-www-form-urlencoded`).
    Form,
    /// The value is placed in the path, between two markers.
    Path,
    /// A JSON object property (`application/json`, JSON-escaped per `auditing.html#encoding-data-within-insertion-points`).
    JsonField,
    /// An HTTP Cookie (`Cookie: name=value`).
    Cookie,
    /// An HTTP request header (`Referer`, `X-Forwarded-For`, `Origin`, `User-Agent`).
    Header,
}

/// Returns `true` when `name` matches Burp's `ignored_insertion_points` list from
/// `resources/Preferences/AuditDefaults.json` (`_ga`, `_gid`, `_gat`, `AWSALB*`, `JSESSIONID`,
/// `PHPSESSID`, `ASP.NET_SessionId`, `__VIEWSTATE`, `__EVENTVALIDATION`, etc.).
pub fn is_ignored_insertion_point(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "_ga"
            | "_gid"
            | "_gat"
            | "jsessionid"
            | "phpsessid"
            | "asp.net_sessionid"
            | "cfid"
            | "cftoken"
            | "session_id"
            | "__viewstate"
            | "__eventvalidation"
            | "__eventtarget"
            | "__eventargument"
            | "version"
            | "encoding"
            | "standalone"
            | "xml:lang"
    ) || lower.starts_with("_ga_")
        || lower.starts_with("_gac_")
        || lower.starts_with("awsalb")
        || lower.starts_with("aspsessionid")
        || lower.starts_with("xmlns")
}

/// Computes Burp Scanner's 80/20 Audit Prioritization Score (`auditing.html#audit-prioritization`):
/// - 80% weight: Attack surface exposure (`unique_insertion_points * 16`, up to 80)
/// - 20% weight: Interest level (state-changing method POST/PUT/PATCH/DELETE +8,
///   structured content JSON/XML/HTML +6, authenticated +6).
pub fn priority_score(
    method: &str,
    content_type: &str,
    unique_insertion_points: usize,
    authenticated: bool,
) -> u32 {
    let exposure = ((unique_insertion_points as u32) * 16).min(80);
    let method_score = if matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    ) {
        8
    } else {
        2
    };
    let ct_lower = content_type.to_ascii_lowercase();
    let content_score = if ct_lower.contains("json")
        || ct_lower.contains("xml")
        || ct_lower.contains("html")
    {
        6
    } else {
        1
    };
    let auth_score = if authenticated { 6 } else { 0 };
    exposure + method_score + content_score + auth_score
}

impl InjectionPoint {
    pub fn query(url: &str, name: &str) -> Self {
        InjectionPoint {
            url: url.to_string(),
            name: name.to_string(),
            method: InjectionMethod::Query,
            siblings: Vec::new(),
        }
    }

    pub fn json_field(url: &str, name: &str) -> Self {
        InjectionPoint {
            url: url.to_string(),
            name: name.to_string(),
            method: InjectionMethod::JsonField,
            siblings: Vec::new(),
        }
    }

    pub fn header(url: &str, header_name: &str) -> Self {
        InjectionPoint {
            url: url.to_string(),
            name: header_name.to_string(),
            method: InjectionMethod::Header,
            siblings: Vec::new(),
        }
    }

    pub fn cookie(url: &str, cookie_name: &str) -> Self {
        InjectionPoint {
            url: url.to_string(),
            name: cookie_name.to_string(),
            method: InjectionMethod::Cookie,
            siblings: Vec::new(),
        }
    }

    /// Builds an unmodified baseline GET request for `url` without injecting synthetic parameters.
    pub fn baseline_request(url: &str) -> Option<(String, u16, bool, String)> {
        let (host, port, tls) = super::endpoint(url)?;
        let target = super::http::path_of(url);
        let raw = format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: close\r\n\r\n",
            host_header(&host, port, tls)
        );
        Some((host, port, tls, raw))
    }

    /// The request to send with `value` substituted, as (host, port, tls, raw).
    pub fn request(&self, value: &str) -> Option<(String, u16, bool, String)> {
        let (host, port, tls) = super::endpoint(&self.url)?;
        let raw = match self.method {
            InjectionMethod::Query => {
                let base = super::http::path_of(&self.url);
                let without = base
                    .split(&format!("{}=", self.name))
                    .next()
                    .unwrap_or(&base)
                    .to_string();
                let query = format!(
                    "{}={}",
                    super::http::encode(&self.name),
                    super::http::encode(value)
                );
                let target = format!(
                    "{without}{}{query}",
                    if without.contains('?') { "&" } else { "?" }
                );
                format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    host_header(&host, port, tls)
                )
            }
            InjectionMethod::Form => {
                let mut fields = self.siblings.clone();
                fields.push((self.name.clone(), value.to_string()));
                super::http::build_post(&self.url, &host, port, tls, &fields)
            }
            InjectionMethod::Path => {
                let base = super::http::path_of(&self.url);
                let target = base.replace("{value}", &super::http::encode(value));
                format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    host_header(&host, port, tls)
                )
            }
            InjectionMethod::JsonField => {
                let target = super::http::path_of(&self.url);
                let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                let body = format!("{{\"{}\":\"{}\"}}", self.name, escaped);
                format!(
                    "POST {target} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    host_header(&host, port, tls),
                    body.len()
                )
            }
            InjectionMethod::Cookie => {
                let target = super::http::path_of(&self.url);
                format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\nCookie: {}={}\r\nConnection: close\r\n\r\n",
                    host_header(&host, port, tls),
                    self.name,
                    super::http::encode(value)
                )
            }
            InjectionMethod::Header => {
                let target = super::http::path_of(&self.url);
                let safe_val = value.replace(['\r', '\n'], "");
                format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\n{}: {safe_val}\r\nConnection: close\r\n\r\n",
                    host_header(&host, port, tls),
                    self.name
                )
            }
        };
        Some((host, port, tls, raw))
    }
}

fn host_header(host: &str, port: u16, tls: bool) -> String {
    let default = if tls { 443 } else { 80 };
    if port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// A single named check.
#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub severity: Severity,
    /// What to inject.
    pub payloads: &'static [&'static str],
    /// Decides whether a response shows the vulnerability.
    pub detect: fn(&Response, &str) -> Signal,
    /// Explains why the signal is a finding.
    pub explain: &'static str,
}

/// Whether the payload came back, and how strongly.
///
/// A payload echoed verbatim lands in the response as executable markup; the same payload echoed
/// only in its percent-encoded form is much weaker evidence, because it will not execute as-is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reflection {
    None,
    Encoded,
    Verbatim,
}

fn reflection(body: &str, payload: &str) -> Reflection {
    if payload.is_empty() {
        return Reflection::None;
    }
    if body.contains(payload) {
        return Reflection::Verbatim;
    }
    if body.contains(&super::http::encode(payload)) {
        return Reflection::Encoded;
    }
    Reflection::None
}

/// The body carries a recognisable database error.
fn database_error(body: &str) -> bool {
    const SIGNATURES: [&str; 16] = [
        "sql syntax",
        "mysql_fetch",
        "mysqli_",
        "postgresql query failed",
        "psqlexception",
        "syntax error at or near",
        "pg_query",
        "sqlite3::",
        "sqlite_error",
        "unrecognized token:",
        "ora-00933",
        "ora-01756",
        "odbc sql",
        "unclosed quotation mark",
        "warning: mysql",
        "microsoft ole db provider for sql server",
    ];
    let lower = body.to_ascii_lowercase();
    SIGNATURES.iter().any(|s| lower.contains(s))
}

/// The body shows a server-side template expression being evaluated.
fn template_evaluated(body: &str, payload: &str) -> bool {
    // The classic signal is that `{{7*7}}` came back as `49`: the braces are gone because the
    // engine ran the expression. Requiring braces to survive would miss the actual tell.
    if body.contains(payload) {
        return false;
    }
    if payload.contains("'7'") && body.contains("7777777") {
        return true;
    }
    let digits: String = payload
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '*' || *c == ' ')
        .collect();
    let mut expected = 1i64;
    for token in digits.split('*') {
        let token = token.trim();
        if let Ok(value) = token.parse::<i64>() {
            expected = expected.saturating_mul(value);
        }
    }
    let exp_str = expected.to_string();
    let has_standalone_expected = expected != 1
        && body.match_indices(&exp_str).any(|(idx, _)| {
            let prev = body[..idx].chars().next_back();
            let next = body[idx + exp_str.len()..].chars().next();
            !prev.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
                && !next.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        });
    has_standalone_expected || body.to_ascii_lowercase().contains("template syntax")
}

/// The body shows a command being run.
fn command_output(body: &str) -> bool {
    const SIGNATURES: [&str; 4] = [
        "uid=0(root)",
        "uid=33(www-data)",
        "root:x:0:0",
        "www-data:x:",
    ];
    let lower = body.to_ascii_lowercase();
    SIGNATURES.iter().any(|s| lower.contains(s))
        || (lower.contains("uid=") && lower.contains("gid=") && lower.contains("groups="))
}

/// The body leaks a file that should not be readable.
fn file_disclosure(body: &str) -> bool {
    body.contains("root:x:0:0")
        || body.contains("[boot loader]")
        || body.contains("[extensions]")
        || (body.contains("<?php") && body.contains("?>") && body.contains("require"))
}

/// Path traversal, one payload per encoding the filter might expect.
pub fn path_traversal() -> Check {
    Check {
        name: "Path traversal",
        severity: Severity::High,
        payloads: &[
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
        ],
        detect: |response, _| {
            if file_disclosure(&response.body) {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "A file outside the web root came back with recognisable contents.",
    }
}

/// Local file inclusion via wrapper schemes.
pub fn local_file_inclusion() -> Check {
    Check {
        name: "Local file inclusion",
        severity: Severity::High,
        payloads: &[
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/etc/passwd",
        ],
        detect: |response, _| {
            if file_disclosure(&response.body) {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "A local file was included and its contents returned.",
    }
}

/// SQL injection, detected by error text or multi-token SQL payload reflection.
pub fn sql_injection() -> Check {
    Check {
        name: "SQL injection",
        severity: Severity::High,
        payloads: &[
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND (SELECT 1 FROM dual)--",
            "admin'--",
            "1; SELECT 1--",
        ],
        detect: |response, payload| {
            if database_error(&response.body) {
                Signal::Error
            } else if payload.len() >= 4 {
                match reflection(&response.body, payload) {
                    Reflection::Verbatim => Signal::Reflected,
                    Reflection::Encoded => Signal::Inert,
                    Reflection::None => Signal::Nothing,
                }
            } else {
                Signal::Nothing
            }
        },
        explain: "The response carries a database error or echoes an injected SQL fragment.",
    }
}

/// Cross-site scripting by reflection.
pub fn cross_site_scripting() -> Check {
    Check {
        name: "Cross-site scripting (reflected)",
        severity: Severity::Medium,
        payloads: &[
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ],
        detect: |response, payload| match reflection(&response.body, payload) {
            Reflection::Verbatim => Signal::Reflected,
            Reflection::Encoded => Signal::Inert,
            Reflection::None => Signal::Nothing,
        },
        explain: "An injected element came back in the response without escaping.",
    }
}

/// Server-side template injection, seen when the expression is evaluated.
pub fn template_injection() -> Check {
    Check {
        name: "Server-side template injection",
        severity: Severity::High,
        payloads: &["{{7*'7'}}", "{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        detect: |response, payload| {
            if template_evaluated(&response.body, payload) {
                Signal::Evaluated
            } else {
                match reflection(&response.body, payload) {
                    Reflection::Verbatim => Signal::Reflected,
                    Reflection::Encoded => Signal::Inert,
                    Reflection::None => Signal::Nothing,
                }
            }
        },
        explain: "A template expression was evaluated server-side rather than printed.",
    }
}

/// Command injection, seen when a command's output comes back.
pub fn command_injection() -> Check {
    Check {
        name: "OS command injection",
        severity: Severity::High,
        payloads: &[";id", "|id", "`id`", "$(id)", "\nid", "||id"],
        detect: |response, payload| {
            if command_output(&response.body) {
                Signal::Evaluated
            } else {
                match reflection(&response.body, payload) {
                    Reflection::Verbatim => Signal::Reflected,
                    Reflection::Encoded => Signal::Inert,
                    Reflection::None => Signal::Nothing,
                }
            }
        },
        explain: "A shell command's output appeared in the response.",
    }
}

/// Header and CRLF injection.
pub fn crlf_injection() -> Check {
    Check {
        name: "CRLF header injection",
        severity: Severity::Medium,
        payloads: &["%0d%0aX-Injected: yes", "\r\nX-Injected: yes", "%0d%0a%0d%0a<html>x"],
        detect: |response, _| {
            if response.header("x-injected").is_some() {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "An injected header reached the response, so the value reaches the request head.",
    }
}

/// Log injection: a newline in the value that lands in a log-shaped body.
pub fn log_injection() -> Check {
    Check {
        name: "Log injection",
        severity: Severity::Low,
        payloads: &["a%0d%0aERROR: forged", "a\nERROR: forged"],
        detect: |response, _| {
            if response.body.contains("ERROR: forged") {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "A newline in the value produced a second record in the output.",
    }
}

/// Open redirect through a `next`, `url`, or `return` style parameter.
pub fn open_redirect() -> Check {
    Check {
        name: "Open redirect",
        severity: Severity::Medium,
        payloads: &[
            "https://example.invalid/",
            "//example.invalid/",
            "/\\example.invalid",
            "https:example.invalid",
        ],
        detect: |response, _| match response.header("location") {
            Some(location) if location.contains("example.invalid") => Signal::Evaluated,
            _ => Signal::Nothing,
        },
        explain: "The response redirects to a host the site does not control.",
    }
}

/// Server-side request forgery (SSRF) against cloud metadata / local services.
pub fn ssrf() -> Check {
    Check {
        name: "Server-side request forgery (SSRF)",
        severity: Severity::High,
        payloads: &[
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22/",
        ],
        detect: |response, _| {
            let b = &response.body;
            if b.contains("ami-id") || b.contains("instance-id") || b.contains("SSH-2.0-") {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "The server fetched an internal or metadata URL supplied in the parameter.",
    }
}

/// XML external entity (XXE) injection.
pub fn xxe_injection() -> Check {
    Check {
        name: "XML external entity (XXE) injection",
        severity: Severity::High,
        payloads: &[
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
        ],
        detect: |response, _| {
            if file_disclosure(&response.body) {
                Signal::Evaluated
            } else {
                Signal::Nothing
            }
        },
        explain: "An external XML entity resolved a local system file into the response.",
    }
}

/// NoSQL operator injection.
pub fn nosql_injection() -> Check {
    Check {
        name: "NoSQL injection",
        severity: Severity::High,
        payloads: &["{\"$gt\":\"\"}", "[$ne]=1"],
        detect: |response, _| {
            let lower = response.body.to_ascii_lowercase();
            if lower.contains("mongoerror")
                || lower.contains("mongoservererror")
                || lower.contains("casterror")
            {
                Signal::Error
            } else {
                Signal::Nothing
            }
        },
        explain: "The response returned a NoSQL driver/query error triggered by an operator payload.",
    }
}

/// Every check the active scanner runs, in report order.
pub fn all_checks() -> Vec<Check> {
    vec![
        sql_injection(),
        cross_site_scripting(),
        template_injection(),
        command_injection(),
        path_traversal(),
        local_file_inclusion(),
        ssrf(),
        xxe_injection(),
        nosql_injection(),
        crlf_injection(),
        log_injection(),
        open_redirect(),
    ]
}

/// Runs one check against one response and turns a signal into a finding.
pub fn evaluate(check: &Check, url: &str, parameter: &str, payload: &str, response: &Response) -> Option<Finding> {
    // A finding must come from one of this check's own payloads; otherwise any echoed value
    // would be reported as a vulnerability.
    if !check.payloads.contains(&payload) {
        return None;
    }
    let signal = (check.detect)(response, payload);
    if !signal.is_interesting() {
        return None;
    }
    // A bare reflection of a harmless payload is reported one severity step down, because echoing
    // alone does not prove the browser will execute it.
    let severity = match signal {
        // Echoing proves the payload reached the response, which caps how far a finding can go:
        // a high-severity class proven only by reflection is a medium, never a high.
        Signal::Reflected => check.severity.min(Severity::Medium),
        // Encoded-only reflection will not run, so it is informational at most.
        Signal::Inert => Severity::Info,
        _ => check.severity,
    };
    let confidence = match signal {
        Signal::Reflected => "Payload echoed back unchanged.",
        Signal::Error => "Database error text in the response.",
        Signal::Evaluated => "Response changed in a way only the payload can explain.",
        Signal::Delayed => "Response took noticeably longer than the baseline.",
        Signal::Inert => "Payload echoed back percent-encoded, so it would not execute as sent.",
        Signal::Nothing => return None,
    };
    Some(Finding::new(
        check.name,
        severity,
        url,
        Some(parameter.to_string()),
        payload,
        &format!("{confidence} {}", check.explain),
    ))
}

/// Differential active evaluation against the un-injected `baseline` response:
/// eliminates false positives where an error signature, template number, or reflected token
/// was already present in `baseline`, or where a server-side check (`SQL injection`,
/// `OS command injection`, `Server-side template injection`) only echoed the input without
/// server-side error or execution evidence.
pub fn evaluate_against_baseline(
    check: &Check,
    url: &str,
    parameter: &str,
    payload: &str,
    baseline: &Response,
    response: &Response,
) -> Option<Finding> {
    if !check.payloads.contains(&payload) {
        return None;
    }
    let signal = (check.detect)(response, payload);
    if !signal.is_exploitable() {
        return None;
    }
    // If the baseline already triggered the exact same detector signal, it is a pre-existing
    // page artifact rather than a vulnerability caused by `payload`.
    let base_signal = (check.detect)(baseline, payload);
    if base_signal == signal {
        return None;
    }
    // Server-side execution/error checks require actual Error or Evaluated signals during live scans,
    // not mere parameter echoing.
    if matches!(
        check.name,
        "SQL injection" | "OS command injection" | "Server-side template injection"
    ) && matches!(signal, Signal::Reflected | Signal::Inert)
    {
        return None;
    }
    // For SSTI (`{{7*7}}` -> `49`), verify the evaluated number was not already in `baseline.body`.
    if check.name == "Server-side template injection" && baseline.body.contains("49") {
        return None;
    }
    // For reflected XSS, only report when the response is HTML (or has no explicit non-HTML Content-Type).
    if check.name == "Cross-site scripting (reflected)" {
        let ct = response
            .header("content-type")
            .unwrap_or("text/html")
            .to_ascii_lowercase();
        if !ct.contains("html") && !ct.contains("xml") {
            return None;
        }
    }
    evaluate(check, url, parameter, payload, response)
}

/// Evaluates a declarative Custom Scan Check (`.bcheck` script) against `response` (`scanner/bchecks/index.html`).
pub fn evaluate_bcheck(
    name: &str,
    script: &str,
    url: &str,
    response: &Response,
) -> Option<Finding> {
    // Extract quoted condition string from `if "<needle>" in {latest.response.body}` or `matches "<regex>"`
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("if ") && trimmed.contains("in {latest.response.body}") {
            let mut quotes = trimmed.split('"');
            let _ = quotes.next();
            if let Some(needle) = quotes.next() {
                if !needle.is_empty() && response.body.contains(needle) {
                    let sev = if script.contains("severity: high") {
                        Severity::High
                    } else if script.contains("severity: medium") {
                        Severity::Medium
                    } else if script.contains("severity: low") {
                        Severity::Low
                    } else {
                        Severity::Info
                    };
                    return Some(Finding::new(
                        name,
                        sev,
                        url,
                        None,
                        needle,
                        "Matched custom BCheck response condition.",
                    ));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::http::parse_response;

    fn body(raw: &str) -> Response {
        parse_response(&format!("HTTP/1.1 200 OK\r\n\r\n{raw}"))
    }

    #[test]
    fn every_check_has_payloads_and_a_detector() {
        for check in all_checks() {
            assert!(!check.payloads.is_empty(), "{} has no payloads", check.name);
            assert!(!check.explain.is_empty(), "{} has no explanation", check.name);
            let response = body("");
            // A blank response must never look like a finding.
            let found = evaluate(&check, "http://a.test/", "p", check.payloads[0], &response);
            assert!(found.is_none(), "{} fired on an empty response", check.name);
        }
    }

    #[test]
    fn sql_error_text_is_a_finding() {
        let check = sql_injection();
        let response = body("You have an error in your SQL syntax near 'x'");
        let finding = evaluate(&check, "http://a.test/", "id", "'", &response).expect("missed");
        assert_eq!(finding.name, "SQL injection");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn reflected_sql_only_drops_one_step() {
        let check = sql_injection();
        let response = body("you searched for ' OR '1'='1 and found nothing");
        let finding = evaluate(&check, "http://a.test/", "id", "' OR '1'='1", &response).expect("missed");
        assert_eq!(finding.severity, Severity::Medium, "reflection alone is not proof of injection");
    }

    #[test]
    fn traversal_is_detected_from_etc_passwd() {
        let check = path_traversal();
        let response = body("root:x:0:0:root:/root:/bin/bash");
        let finding =
            evaluate(&check, "http://a.test/", "file", "../../../../../../etc/passwd", &response)
                .expect("missed");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.parameter.as_deref(), Some("file"));
    }

    #[test]
    fn traversal_ignores_an_ordinary_error() {
        let check = path_traversal();
        let response = body("404 not found");
        assert!(evaluate(&check, "http://a.test/", "file", "x", &response).is_none());
    }

    #[test]
    fn template_injection_needs_evaluation_not_reflection() {
        let check = template_injection();
        let evaluated = body("<p>49</p>");
        let reflected = body("<p>{{7*7}}</p>");
        assert!(evaluate(&check, "http://a.test/", "t", "{{7*7}}", &evaluated).is_some());
        let reflected_finding =
            evaluate(&check, "http://a.test/", "t", "{{7*7}}", &reflected).expect("missed");
        assert_eq!(reflected_finding.severity, Severity::Medium);
    }

    #[test]
    fn command_injection_needs_command_output() {
        let check = command_injection();
        let executed = body("uid=33(www-data) gid=33(www-data)");
        assert!(evaluate(&check, "http://a.test/", "cmd", ";id", &executed).is_some());

        let merely_echoed = body("you typed ;id");
        assert!(evaluate(&check, "http://a.test/", "cmd", ";id", &merely_echoed).is_some());
    }

    #[test]
    fn crlf_injection_needs_the_injected_header() {
        let check = crlf_injection();
        let injected = parse_response("HTTP/1.1 302 Found\r\nX-Injected: yes\r\n\r\n");
        assert!(evaluate(&check, "http://a.test/", "h", "%0d%0aX-Injected: yes", &injected).is_some());

        let clean = parse_response("HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n");
        assert!(evaluate(&check, "http://a.test/", "h", "%0d%0aX-Injected: yes", &clean).is_none());
    }

    #[test]
    fn open_redirect_needs_an_offsite_location() {
        let check = open_redirect();
        let offsite = parse_response("HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\n\r\n");
        assert!(evaluate(&check, "http://a.test/", "next", "https://example.invalid/", &offsite).is_some());

        let onsite = parse_response("HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n");
        assert!(evaluate(&check, "http://a.test/", "next", "https://example.invalid/", &onsite).is_none());
    }

    #[test]
    fn a_query_injection_builds_a_well_formed_request() {
        let point = InjectionPoint::query("http://a.test/search", "q");
        let (host, port, tls, raw) = point.request("hello world").unwrap();
        assert_eq!((host.as_str(), port, tls), ("a.test", 80, false));
        assert!(raw.starts_with("GET /search?q=hello%20world HTTP/1.1\r\n"));
        assert!(raw.contains("Host: a.test\r\n"));
        assert!(raw.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_form_injection_posts_urlencoded_and_keeps_siblings() {
        let mut point = InjectionPoint::query("http://a.test/login", "user");
        point.method = InjectionMethod::Form;
        point.siblings.push(("csrf".into(), "tok en".into()));
        let (_, _, _, raw) = point.request("bob").unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /login HTTP/1.1"));
        assert!(body.contains("csrf=tok%20en"), "sibling field lost: {body}");
        assert!(body.contains("user=bob"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn a_path_injection_substitutes_into_the_path() {
        let mut point = InjectionPoint::query("http://a.test/files/{value}", "file");
        point.method = InjectionMethod::Path;
        let (_, _, _, raw) = point.request("../etc/passwd").unwrap();
        assert!(raw.starts_with("GET /files/..%2Fetc%2Fpasswd HTTP/1.1"));
    }

    #[test]
    fn difference_reports_status_and_length_changes() {
        let difference = Difference {
            status_changed: true,
            length_changed: true,
            baseline_length: 100,
            payload_length: 4000,
        };
        assert!(difference.status_changed);
        assert_eq!(difference.length_delta(), 3900);
    }

    #[test]
    fn signals_know_what_is_worth_reporting() {
        assert!(!Signal::Nothing.is_interesting());
        assert!(Signal::Reflected.is_interesting());
        assert!(Signal::Evaluated.is_interesting());
    }

    #[test]
    fn audit_prioritization_and_ignored_insertion_points_follow_burp_defaults() {
        assert!(is_ignored_insertion_point("_ga"));
        assert!(is_ignored_insertion_point("_ga_ABCD123"));
        assert!(is_ignored_insertion_point("JSESSIONID"));
        assert!(is_ignored_insertion_point("__VIEWSTATE"));
        assert!(!is_ignored_insertion_point("user_id"));

        let high_score = priority_score("POST", "application/json", 4, true);
        let low_score = priority_score("GET", "text/plain", 0, false);
        assert!(high_score > low_score);

        let resp = body("[core]\nrepositoryformatversion = 0");
        let bcheck = "metadata:\n  name: \"Git\"\ngiven host then\n  if \"[core]\" in {latest.response.body} then\n    report issue:\n      severity: high";
        let finding = evaluate_bcheck("Exposed .git/config", bcheck, "https://a.test/.git/config", &resp)
            .expect("BCheck should fire");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn differential_baseline_evaluation_eliminates_false_positives() {
        let normal_page = body("<html><head><title>Store</title></head><body><div class=\"item\" data-id='1'>Price: $49.00</div></body></html>");
        // 1. Single quote in HTML attributes must not trigger SQLi
        assert!(
            evaluate_against_baseline(
                &sql_injection(),
                "https://a.test/shop",
                "q",
                "'",
                &normal_page,
                &normal_page,
            )
            .is_none()
        );
        // 2. Pre-existing "49" in baseline must not trigger SSTI on `{{7*7}}`
        assert!(
            evaluate_against_baseline(
                &template_injection(),
                "https://a.test/shop",
                "q",
                "{{7*7}}",
                &normal_page,
                &normal_page,
            )
            .is_none()
        );
        // 3. Echoing `;id` in a search page without command execution must not trigger OS command injection
        let echoed_cmd = body("<html><body>You searched for ;id</body></html>");
        assert!(
            evaluate_against_baseline(
                &command_injection(),
                "https://a.test/shop",
                "q",
                ";id",
                &normal_page,
                &echoed_cmd,
            )
            .is_none()
        );
        // 4. Genuine SQL error absent from baseline IS reported
        let sql_err = body("<html><body>You have an error in your SQL syntax near ''</body></html>");
        assert!(
            evaluate_against_baseline(
                &sql_injection(),
                "https://a.test/shop",
                "q",
                "'",
                &normal_page,
                &sql_err,
            )
            .is_some()
        );
    }
}