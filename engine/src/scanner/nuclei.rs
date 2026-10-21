//! Native Rust ProjectDiscovery Nuclei YAML Template & DSL Expression Engine.
//!
//! Parses and executes standard Nuclei `.yaml` HTTP templates (`id`, `info`, `variables`, `flow`,
//! `http`/`requests` with `raw` or `method`+`path`+`headers`+`body`, `matchers`, and `extractors`)
//! and evaluates the full Nuclei DSL expression language (`contains`, `contains_all`, `contains_any`,
//! `regex`, `len`, `to_lower`/`tolower`, `to_upper`/`toupper`, `base64`, `base64_decode`, `base64_py`,
//! `mmh3`, `md5`, `sha1`, `sha256`, `url_encode`, `url_decode`, `html_escape`, `html_unescape`,
//! `replace`, `trim`, `starts_with`, `ends_with`, `compare_versions`, boolean `&&`/`||`/`!`, and
//! comparison operators `==`/`!=`/`>=`/`<=`/`>`/`<`/`=~`).

use std::collections::BTreeMap;

use super::http::{parse_response, Response};
use super::{Finding, Severity};
use base64::Engine;

#[derive(Clone, Debug, Default)]
pub struct NucleiClassification {
    pub cve_id: String,
    pub cwe_id: String,
    pub cvss_metrics: String,
    pub cvss_score: String,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiInfo {
    pub name: String,
    pub author: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub classification: NucleiClassification,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum MatcherType {
    #[default]
    Word,
    Regex,
    Status,
    Dsl,
    Binary,
    Size,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Condition {
    #[default]
    Or,
    And,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiMatcher {
    pub matcher_type: MatcherType,
    pub part: String,
    pub words: Vec<String>,
    pub regex: Vec<String>,
    pub status: Vec<u16>,
    pub dsl: Vec<String>,
    pub binary: Vec<String>,
    pub size: Vec<usize>,
    pub condition: Condition,
    pub negative: bool,
    pub case_insensitive: bool,
    pub internal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiExtractor {
    pub extractor_type: String,
    pub name: String,
    pub part: String,
    pub group: usize,
    pub regex: Vec<String>,
    pub kval: Vec<String>,
    pub dsl: Vec<String>,
    pub internal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiHttpRequest {
    pub method: String,
    pub paths: Vec<String>,
    pub raw: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub matchers_condition: Condition,
    pub stop_at_first_match: bool,
    pub matchers: Vec<NucleiMatcher>,
    pub extractors: Vec<NucleiExtractor>,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: NucleiInfo,
    pub variables: BTreeMap<String, String>,
    pub flow: String,
    pub http: Vec<NucleiHttpRequest>,
}

/// Execution context for Nuclei DSL expressions (`type: dsl`) and variable interpolation.
#[derive(Clone, Debug, Default)]
pub struct DslContext {
    pub status_code: i64,
    pub body: String,
    pub header: String,
    pub content_type: String,
    pub content_length: i64,
    pub duration: f64,
    pub host: String,
    pub matched: String,
    pub interactsh_protocol: String,
    pub vars: BTreeMap<String, String>,
    pub step_history: Vec<(i64, String, String, String, i64)>,
}

impl DslContext {
    pub fn from_response(
        url: &str,
        response: &Response,
        elapsed_ms: u128,
        vars: BTreeMap<String, String>,
    ) -> Self {
        let mut header_str = format!("HTTP/1.1 {}\r\n", response.status);
        for (k, v) in &response.headers {
            header_str.push_str(&format!("{k}: {v}\r\n"));
        }
        let content_type = response
            .header("content-type")
            .unwrap_or("")
            .to_string();
        let host = url
            .split_once("://")
            .map(|(_, r)| r.split('/').next().unwrap_or(r).to_string())
            .unwrap_or_default();
        Self {
            status_code: response.status as i64,
            body: response.body.clone(),
            header: header_str,
            content_type,
            content_length: response.body.len() as i64,
            duration: (elapsed_ms as f64) / 1000.0,
            host,
            matched: url.to_string(),
            interactsh_protocol: String::new(),
            vars,
            step_history: Vec::new(),
        }
    }

    pub fn push_step(&mut self, status: i64, body: String, header: String, content_type: String) {
        let len = body.len() as i64;
        self.status_code = status;
        self.body = body.clone();
        self.header = header.clone();
        self.content_type = content_type.clone();
        self.content_length = len;
        self.step_history.push((status, body, header, content_type, len));
    }
}

/// Returns `true` if `script` looks like a Nuclei YAML template (`id:` + `info:` + `http:`/`requests:`/`matchers:`).
pub fn is_nuclei_template(script: &str) -> bool {
    let has_id = script.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("id:") && l.len() == t.len()
    });
    let has_info = script.lines().any(|l| l.trim() == "info:");
    let has_http = script.lines().any(|l| {
        let t = l.trim();
        t == "http:" || t == "requests:" || t.starts_with("matchers:")
    });
    has_id && (has_info || has_http)
}

fn unquote_yaml(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\''))) {
        let quote = t.chars().next().unwrap();
        let inner = &t[1..t.len() - 1];
        if quote == '\'' {
            return inner.replace("''", "'");
        }
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        // Strip trailing inline YAML comment if unquoted
        if let Some((before, _)) = t.split_once(" #") {
            before.trim().to_string()
        } else {
            t.to_string()
        }
    }
}

fn parse_inline_yaml_list(s: &str) -> Vec<String> {
    let t = s.trim();
    let Some(inner) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else {
        return Vec::new();
    };
    split_comma_args(inner)
        .into_iter()
        .map(|item| unquote_yaml(&item))
        .filter(|item| !item.is_empty())
        .collect()
}

/// Parses a ProjectDiscovery Nuclei `.yaml` template into a `NucleiTemplate`.
pub fn parse_nuclei_template(yaml: &str) -> Result<NucleiTemplate, String> {
    let mut tmpl = NucleiTemplate {
        info: NucleiInfo {
            severity: Severity::Info,
            ..Default::default()
        },
        ..Default::default()
    };

    let lines: Vec<&str> = yaml.lines().collect();
    let mut i = 0usize;
    let mut section = "";
    let mut info_sub = "";

    while i < lines.len() {
        let raw_line = lines[i];
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start().len();

        if indent == 0 {
            info_sub = "";
            if let Some(rest) = trimmed.strip_prefix("id:") {
                tmpl.id = unquote_yaml(rest);
                section = "";
            } else if let Some(rest) = trimmed.strip_prefix("flow:") {
                tmpl.flow = unquote_yaml(rest);
                section = "";
            } else if trimmed == "info:" {
                section = "info";
            } else if trimmed == "variables:" {
                section = "variables";
            } else if trimmed == "http:" || trimmed == "requests:" {
                section = "http";
                i += 1;
                i = parse_http_section(&lines, i, &mut tmpl.http);
                continue;
            } else {
                section = "";
            }
            i += 1;
            continue;
        }

        match section {
            "info" => {
                if indent == 2 {
                    info_sub = "";
                    if let Some((k, v)) = trimmed.split_once(':') {
                        let k = k.trim();
                        let v_trim = v.trim();
                        if v_trim == "|" || v_trim == ">" || v_trim == "|-" || v_trim == ">-" {
                            let (block, next_i) = read_block_scalar(&lines, i + 1, indent);
                            match k {
                                "description" => tmpl.info.description = block,
                                "remediation" => tmpl.info.remediation = block,
                                _ => {}
                            }
                            i = next_i;
                            continue;
                        }
                        match k {
                            "name" => tmpl.info.name = unquote_yaml(v_trim),
                            "author" => tmpl.info.author = unquote_yaml(v_trim),
                            "severity" => {
                                tmpl.info.severity = match unquote_yaml(v_trim)
                                    .to_ascii_lowercase()
                                    .as_str()
                                {
                                    "critical" | "high" => Severity::High,
                                    "medium" => Severity::Medium,
                                    "low" => Severity::Low,
                                    _ => Severity::Info,
                                };
                            }
                            "description" => tmpl.info.description = unquote_yaml(v_trim),
                            "remediation" => tmpl.info.remediation = unquote_yaml(v_trim),
                            "tags" => {
                                tmpl.info.tags = unquote_yaml(v_trim)
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                            }
                            "reference" => {
                                if v_trim.starts_with('[') {
                                    tmpl.info.references.extend(parse_inline_yaml_list(v_trim));
                                } else {
                                    info_sub = "reference";
                                }
                            }
                            "classification" => {
                                info_sub = "classification";
                            }
                            _ => {}
                        }
                    }
                } else if indent >= 4 {
                    match info_sub {
                        "reference" => {
                            if let Some(item) = trimmed.strip_prefix('-') {
                                let u = unquote_yaml(item);
                                if !u.is_empty() {
                                    tmpl.info.references.push(u);
                                }
                            }
                        }
                        "classification" => {
                            if let Some((ck, cv)) = trimmed.split_once(':') {
                                let val = unquote_yaml(cv);
                                match ck.trim() {
                                    "cve-id" => tmpl.info.classification.cve_id = val,
                                    "cwe-id" => tmpl.info.classification.cwe_id = val,
                                    "cvss-metrics" => tmpl.info.classification.cvss_metrics = val,
                                    "cvss-score" => tmpl.info.classification.cvss_score = val,
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            "variables" => {
                if let Some((vk, vv)) = trimmed.split_once(':') {
                    tmpl.variables
                        .insert(vk.trim().to_string(), unquote_yaml(vv));
                }
            }
            _ => {}
        }
        i += 1;
    }

    if tmpl.id.is_empty() {
        return Err("Nuclei template missing `id:`".into());
    }
    Ok(tmpl)
}

fn read_block_scalar(lines: &[&str], start_idx: usize, parent_indent: usize) -> (String, usize) {
    let mut out = Vec::new();
    let mut i = start_idx;
    let mut block_indent: Option<usize> = None;
    while i < lines.len() {
        let raw = lines[i];
        if raw.trim().is_empty() {
            out.push(String::new());
            i += 1;
            continue;
        }
        let ind = raw.len() - raw.trim_start().len();
        if ind <= parent_indent {
            break;
        }
        let base = *block_indent.get_or_insert(ind);
        let slice = if raw.len() >= base { &raw[base..] } else { raw.trim_start() };
        out.push(slice.to_string());
        i += 1;
    }
    while out.last().is_some_and(|s| s.is_empty()) {
        out.pop();
    }
    (out.join("\n"), i)
}

fn parse_http_section(lines: &[&str], mut i: usize, out: &mut Vec<NucleiHttpRequest>) -> usize {
    let mut cur_req: Option<NucleiHttpRequest> = None;
    let mut list_mode = "";

    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            break;
        }

        // New HTTP request item (`  - method: GET` or `  - raw:`)
        if indent == 2 && trimmed.starts_with("- ") {
            if let Some(prev) = cur_req.take() {
                out.push(prev);
            }
            let mut req = NucleiHttpRequest {
                method: "GET".into(),
                ..Default::default()
            };
            list_mode = "";
            let after_dash = trimmed[2..].trim();
            if let Some((k, v)) = after_dash.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "method" => req.method = unquote_yaml(v).to_ascii_uppercase(),
                    "path" => {
                        if v.starts_with('[') {
                            req.paths.extend(parse_inline_yaml_list(v));
                        } else {
                            list_mode = "path";
                        }
                    }
                    "raw" => list_mode = "raw",
                    "headers" => list_mode = "headers",
                    _ => {}
                }
            }
            cur_req = Some(req);
            i += 1;
            continue;
        }

        let req = cur_req.get_or_insert_with(|| NucleiHttpRequest {
            method: "GET".into(),
            ..Default::default()
        });

        if indent == 4 && !trimmed.starts_with('-') {
            list_mode = "";
            if let Some((k, v)) = trimmed.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "method" => req.method = unquote_yaml(v).to_ascii_uppercase(),
                    "body" => {
                        if v == "|" || v == ">" || v == "|-" || v == ">-" {
                            let (blk, next_i) = read_block_scalar(lines, i + 1, indent);
                            req.body = blk;
                            i = next_i;
                            continue;
                        } else {
                            req.body = unquote_yaml(v);
                        }
                    }
                    "matchers-condition" => {
                        req.matchers_condition = if unquote_yaml(v).eq_ignore_ascii_case("and") {
                            Condition::And
                        } else {
                            Condition::Or
                        };
                    }
                    "stop-at-first-match" => {
                        req.stop_at_first_match = unquote_yaml(v).eq_ignore_ascii_case("true");
                    }
                    "path" | "paths" => {
                        if v.starts_with('[') {
                            req.paths.extend(parse_inline_yaml_list(v));
                        } else {
                            list_mode = "path";
                        }
                    }
                    "raw" => {
                        list_mode = "raw";
                    }
                    "headers" => {
                        list_mode = "headers";
                    }
                    "matchers" => {
                        i = parse_matchers_list(lines, i + 1, indent, &mut req.matchers);
                        continue;
                    }
                    "extractors" => {
                        i = parse_extractors_list(lines, i + 1, indent, &mut req.extractors);
                        continue;
                    }
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if indent >= 4 {
            match list_mode {
                "path" => {
                    if let Some(item) = trimmed.strip_prefix('-') {
                        let p = unquote_yaml(item);
                        if !p.is_empty() {
                            req.paths.push(p);
                        }
                    }
                }
                "raw" => {
                    if let Some(item) = trimmed.strip_prefix('-') {
                        let item_trim = item.trim();
                        if item_trim == "|" || item_trim == "|-" || item_trim == ">" || item_trim == ">-" {
                            let (blk, next_i) = read_block_scalar(lines, i + 1, indent);
                            if !blk.is_empty() {
                                req.raw.push(blk);
                            }
                            i = next_i;
                            continue;
                        } else {
                            let r = unquote_yaml(item_trim);
                            if !r.is_empty() {
                                req.raw.push(r);
                            }
                        }
                    }
                }
                "headers" => {
                    let h_line = trimmed.strip_prefix('-').map(str::trim).unwrap_or(trimmed);
                    let unq = unquote_yaml(h_line);
                    if let Some((hk, hv)) = unq.split_once(':') {
                        req.headers.push((hk.trim().to_string(), hv.trim().to_string()));
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    if let Some(prev) = cur_req {
        out.push(prev);
    }
    i
}

fn parse_matchers_list(
    lines: &[&str],
    mut i: usize,
    parent_indent: usize,
    out: &mut Vec<NucleiMatcher>,
) -> usize {
    let mut cur: Option<NucleiMatcher> = None;
    let mut list_key = "";

    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= parent_indent {
            break;
        }

        if indent == parent_indent + 2 && trimmed.starts_with("- ") {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            let mut m = NucleiMatcher {
                part: "body".into(),
                ..Default::default()
            };
            list_key = "";
            let after = trimmed[2..].trim();
            apply_matcher_kv(&mut m, after, &mut list_key);
            cur = Some(m);
            i += 1;
            continue;
        }

        let m = cur.get_or_insert_with(|| NucleiMatcher {
            part: "body".into(),
            ..Default::default()
        });

        if indent == parent_indent + 4 && !trimmed.starts_with('-') {
            list_key = "";
            apply_matcher_kv(m, trimmed, &mut list_key);
            i += 1;
            continue;
        }

        if let Some(item) = trimmed.strip_prefix('-') {
            let item_t = item.trim();
            let val = if item_t == "|" || item_t == "|-" || item_t == ">" || item_t == ">-" {
                let (blk, next_i) = read_block_scalar(lines, i + 1, indent);
                i = next_i - 1;
                blk
            } else {
                unquote_yaml(item_t)
            };
            match list_key {
                "words" => m.words.push(val),
                "regex" => m.regex.push(val),
                "dsl" => m.dsl.push(val),
                "binary" => m.binary.push(val),
                "status" => {
                    if let Ok(code) = val.parse::<u16>() {
                        m.status.push(code);
                    }
                }
                "size" => {
                    if let Ok(sz) = val.parse::<usize>() {
                        m.size.push(sz);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    if let Some(prev) = cur {
        out.push(prev);
    }
    i
}

fn apply_matcher_kv<'a>(m: &mut NucleiMatcher, line: &'a str, list_key: &mut &'a str) {
    let Some((k, v)) = line.split_once(':') else {
        return;
    };
    let k = k.trim();
    let v = v.trim();
    match k {
        "type" => {
            m.matcher_type = match unquote_yaml(v).to_ascii_lowercase().as_str() {
                "word" => MatcherType::Word,
                "regex" => MatcherType::Regex,
                "status" => MatcherType::Status,
                "dsl" => MatcherType::Dsl,
                "binary" => MatcherType::Binary,
                "size" => MatcherType::Size,
                _ => MatcherType::Word,
            };
        }
        "part" => m.part = unquote_yaml(v).to_ascii_lowercase(),
        "condition" => {
            m.condition = if unquote_yaml(v).eq_ignore_ascii_case("and") {
                Condition::And
            } else {
                Condition::Or
            };
        }
        "negative" => m.negative = unquote_yaml(v).eq_ignore_ascii_case("true"),
        "case-insensitive" => m.case_insensitive = unquote_yaml(v).eq_ignore_ascii_case("true"),
        "internal" => m.internal = unquote_yaml(v).eq_ignore_ascii_case("true"),
        "words" => {
            if v.starts_with('[') {
                m.words.extend(parse_inline_yaml_list(v));
            } else {
                *list_key = "words";
            }
        }
        "regex" => {
            if v.starts_with('[') {
                m.regex.extend(parse_inline_yaml_list(v));
            } else {
                *list_key = "regex";
            }
        }
        "dsl" => {
            if v.starts_with('[') {
                m.dsl.extend(parse_inline_yaml_list(v));
            } else {
                *list_key = "dsl";
            }
        }
        "binary" => {
            if v.starts_with('[') {
                m.binary.extend(parse_inline_yaml_list(v));
            } else {
                *list_key = "binary";
            }
        }
        "status" => {
            if v.starts_with('[') {
                for item in parse_inline_yaml_list(v) {
                    if let Ok(c) = item.parse::<u16>() {
                        m.status.push(c);
                    }
                }
            } else {
                *list_key = "status";
            }
        }
        "size" => {
            if v.starts_with('[') {
                for item in parse_inline_yaml_list(v) {
                    if let Ok(s) = item.parse::<usize>() {
                        m.size.push(s);
                    }
                }
            } else {
                *list_key = "size";
            }
        }
        _ => {}
    }
}

fn parse_extractors_list(
    lines: &[&str],
    mut i: usize,
    parent_indent: usize,
    out: &mut Vec<NucleiExtractor>,
) -> usize {
    let mut cur: Option<NucleiExtractor> = None;
    let mut list_key = "";

    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= parent_indent {
            break;
        }

        if indent == parent_indent + 2 && trimmed.starts_with("- ") {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            let mut ex = NucleiExtractor {
                part: "body".into(),
                group: 1,
                ..Default::default()
            };
            list_key = "";
            apply_extractor_kv(&mut ex, trimmed[2..].trim(), &mut list_key);
            cur = Some(ex);
            i += 1;
            continue;
        }

        let ex = cur.get_or_insert_with(|| NucleiExtractor {
            part: "body".into(),
            group: 1,
            ..Default::default()
        });

        if indent == parent_indent + 4 && !trimmed.starts_with('-') {
            list_key = "";
            apply_extractor_kv(ex, trimmed, &mut list_key);
            i += 1;
            continue;
        }

        if let Some(item) = trimmed.strip_prefix('-') {
            let val = unquote_yaml(item);
            match list_key {
                "regex" => ex.regex.push(val),
                "kval" => ex.kval.push(val),
                "dsl" => ex.dsl.push(val),
                _ => {}
            }
        }
        i += 1;
    }

    if let Some(prev) = cur {
        out.push(prev);
    }
    i
}

fn apply_extractor_kv<'a>(ex: &mut NucleiExtractor, line: &'a str, list_key: &mut &'a str) {
    let Some((k, v)) = line.split_once(':') else {
        return;
    };
    let k = k.trim();
    let v = v.trim();
    match k {
        "type" => ex.extractor_type = unquote_yaml(v).to_ascii_lowercase(),
        "name" => ex.name = unquote_yaml(v),
        "part" => ex.part = unquote_yaml(v).to_ascii_lowercase(),
        "group" => ex.group = unquote_yaml(v).parse().unwrap_or(1),
        "internal" => ex.internal = unquote_yaml(v).eq_ignore_ascii_case("true"),
        "regex" => *list_key = "regex",
        "kval" => *list_key = "kval",
        "dsl" => *list_key = "dsl",
        _ => {}
    }
}

/// Interpolates `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`, `{{Path}}`,
/// `{{Scheme}}`, `{{interactsh-url}}`, `{{randstr}}`, custom template `variables`, and inline
/// helper expressions like `{{to_lower(rand_base(5))}}`.
pub fn interpolate_template_vars(
    input: &str,
    target_url: &str,
    vars: &BTreeMap<String, String>,
) -> String {
    let parsed = url::Url::parse(target_url);
    let scheme = parsed
        .as_ref()
        .map(|u| u.scheme().to_string())
        .unwrap_or_else(|_| "http".into());
    let host = parsed
        .as_ref()
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "localhost".into());
    let port = parsed
        .as_ref()
        .ok()
        .and_then(|u| u.port_or_known_default())
        .unwrap_or(80);
    let hostname = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let root_url = format!("{scheme}://{hostname}");
    let base_url = target_url.trim_end_matches('/').to_string();
    let path = parsed
        .as_ref()
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();

    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let token = after[..end].trim();
        let replacement = match token {
            "BaseURL" => base_url.clone(),
            "RootURL" => root_url.clone(),
            "Hostname" => hostname.clone(),
            "Host" => host.clone(),
            "Port" => port.to_string(),
            "Path" => path.clone(),
            "Scheme" => scheme.clone(),
            "interactsh-url" | "interactsh_url" => vars
                .get("interactsh-url")
                .cloned()
                .unwrap_or_else(|| "oast.gulpsuite.local".into()),
            "randstr" => vars
                .get("randstr")
                .cloned()
                .unwrap_or_else(|| "gulp7f9a2b".into()),
            other => {
                if let Some(val) = vars.get(other) {
                    val.clone()
                } else {
                    let dummy_ctx = DslContext {
                        vars: vars.clone(),
                        host: hostname.clone(),
                        ..Default::default()
                    };
                    eval_dsl_value(other, &dummy_ctx).as_string()
                }
            }
        };
        out.push_str(&replacement);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

// ============================================================================
// Complete Nuclei DSL Expression Evaluator (`type: dsl`)
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum DslValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl DslValue {
    pub fn as_bool(&self) -> bool {
        match self {
            DslValue::Bool(b) => *b,
            DslValue::Int(n) => *n != 0,
            DslValue::Float(f) => *f != 0.0,
            DslValue::Str(s) => !s.is_empty() && !s.eq_ignore_ascii_case("false") && s != "0",
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            DslValue::Int(n) => Some(*n),
            DslValue::Float(f) => Some(*f as i64),
            DslValue::Bool(b) => Some(if *b { 1 } else { 0 }),
            DslValue::Str(s) => s.trim().parse::<i64>().ok(),
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            DslValue::Float(f) => Some(*f),
            DslValue::Int(n) => Some(*n as f64),
            DslValue::Str(s) => s.trim().parse::<f64>().ok(),
            DslValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            DslValue::Str(s) => s.clone(),
            DslValue::Int(n) => n.to_string(),
            DslValue::Float(f) => f.to_string(),
            DslValue::Bool(b) => b.to_string(),
        }
    }
}

/// Evaluates a Nuclei DSL boolean expression (e.g. `status_code == 200 && contains_all(body, "id", "admin")`).
pub fn evaluate_dsl(expr: &str, ctx: &DslContext) -> bool {
    eval_dsl_value(expr, ctx).as_bool()
}

pub fn eval_dsl_value(expr: &str, ctx: &DslContext) -> DslValue {
    let s = strip_outer_parens(expr.trim());
    if s.is_empty() {
        return DslValue::Bool(false);
    }

    // 1. Logical OR (`||`) at top-level depth 0
    if let Some((left, right)) = split_top_level_op(s, "||") {
        return DslValue::Bool(
            eval_dsl_value(left, ctx).as_bool() || eval_dsl_value(right, ctx).as_bool(),
        );
    }

    // 2. Logical AND (`&&`) at top-level depth 0
    if let Some((left, right)) = split_top_level_op(s, "&&") {
        return DslValue::Bool(
            eval_dsl_value(left, ctx).as_bool() && eval_dsl_value(right, ctx).as_bool(),
        );
    }

    // 3. Unary NOT (`!expr`)
    if let Some(rest) = s.strip_prefix('!') {
        if !rest.starts_with('=') {
            return DslValue::Bool(!eval_dsl_value(rest, ctx).as_bool());
        }
    }

    // 4. Comparison operators (`==`, `!=`, `>=`, `<=`, `=~`, `>`, `<`) at top-level depth 0
    for op in ["==", "!=", ">=", "<=", "=~", ">", "<"] {
        if let Some((left, right)) = split_top_level_op(s, op) {
            let lv = eval_dsl_value(left, ctx);
            let rv = eval_dsl_value(right, ctx);
            let res = match op {
                "==" => match (lv.as_int(), rv.as_int()) {
                    (Some(a), Some(b)) => a == b,
                    _ => lv.as_string() == rv.as_string(),
                },
                "!=" => match (lv.as_int(), rv.as_int()) {
                    (Some(a), Some(b)) => a != b,
                    _ => lv.as_string() != rv.as_string(),
                },
                ">=" => match (lv.as_float(), rv.as_float()) {
                    (Some(a), Some(b)) => a >= b,
                    _ => lv.as_string() >= rv.as_string(),
                },
                "<=" => match (lv.as_float(), rv.as_float()) {
                    (Some(a), Some(b)) => a <= b,
                    _ => lv.as_string() <= rv.as_string(),
                },
                ">" => match (lv.as_float(), rv.as_float()) {
                    (Some(a), Some(b)) => a > b,
                    _ => lv.as_string() > rv.as_string(),
                },
                "<" => match (lv.as_float(), rv.as_float()) {
                    (Some(a), Some(b)) => a < b,
                    _ => lv.as_string() < rv.as_string(),
                },
                "=~" => regex::Regex::new(&rv.as_string())
                    .map(|re| re.is_match(&lv.as_string()))
                    .unwrap_or(false),
                _ => false,
            };
            return DslValue::Bool(res);
        }
    }

    // 5. Addition / string concatenation (`+`) at top-level depth 0
    if let Some((left, right)) = split_top_level_op(s, "+") {
        let lv = eval_dsl_value(left, ctx);
        let rv = eval_dsl_value(right, ctx);
        if let (Some(a), Some(b)) = (lv.as_int(), rv.as_int()) {
            return DslValue::Int(a + b);
        }
        return DslValue::Str(format!("{}{}", lv.as_string(), rv.as_string()));
    }

    // 6. String literals (`"..."`, `'...'`, `` `...` ``)
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\''))
            || (s.starts_with('`') && s.ends_with('`')))
    {
        return DslValue::Str(unquote_yaml(s));
    }

    // 7. Boolean & numeric literals
    if s.eq_ignore_ascii_case("true") {
        return DslValue::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return DslValue::Bool(false);
    }
    if let Ok(n) = s.parse::<i64>() {
        return DslValue::Int(n);
    }
    if let Ok(f) = s.parse::<f64>() {
        return DslValue::Float(f);
    }

    // 8. Function calls: `func_name(arg1, arg2, ...)`
    if let Some(open_paren) = s.find('(') {
        if s.ends_with(')') {
            let fn_name = s[..open_paren].trim().to_ascii_lowercase();
            if fn_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                let args_str = &s[open_paren + 1..s.len() - 1];
                let raw_args = split_comma_args(args_str);
                let args: Vec<DslValue> = raw_args
                    .iter()
                    .map(|a| eval_dsl_value(a, ctx))
                    .collect();
                return eval_dsl_function(&fn_name, &args, ctx);
            }
        }
    }

    // 9. Context variables (`body`, `header`, `status_code`, `content_type`, `content_length`, `body_1`, `status_code_2`, etc.)
    resolve_dsl_variable(s, ctx)
}

fn resolve_dsl_variable(name: &str, ctx: &DslContext) -> DslValue {
    let trimmed = name.trim();
    match trimmed {
        "status_code" => return DslValue::Int(ctx.status_code),
        "body" | "response" => return DslValue::Str(ctx.body.clone()),
        "header" | "headers" | "all_headers" => return DslValue::Str(ctx.header.clone()),
        "content_type" => return DslValue::Str(ctx.content_type.clone()),
        "content_length" => return DslValue::Int(ctx.content_length),
        "duration" => return DslValue::Float(ctx.duration),
        "host" | "hostname" => return DslValue::Str(ctx.host.clone()),
        "matched" => return DslValue::Str(ctx.matched.clone()),
        "interactsh_protocol" => return DslValue::Str(ctx.interactsh_protocol.clone()),
        _ => {}
    }

    // Indexed step variables (`status_code_1`, `body_2`, `header_1`, `content_length_1`, `content_type_1`)
    for (prefix, field) in [
        ("status_code_", 0usize),
        ("body_", 1),
        ("header_", 2),
        ("all_headers_", 2),
        ("content_type_", 3),
        ("content_length_", 4),
    ] {
        if let Some(idx_str) = trimmed.strip_prefix(prefix) {
            if let Ok(step_1based) = idx_str.parse::<usize>() {
                if let Some(step) = ctx.step_history.get(step_1based.saturating_sub(1)) {
                    return match field {
                        0 => DslValue::Int(step.0),
                        1 => DslValue::Str(step.1.clone()),
                        2 => DslValue::Str(step.2.clone()),
                        3 => DslValue::Str(step.3.clone()),
                        _ => DslValue::Int(step.4),
                    };
                }
            }
        }
    }

    if let Some(v) = ctx.vars.get(trimmed) {
        if let Ok(n) = v.parse::<i64>() {
            return DslValue::Int(n);
        }
        return DslValue::Str(v.clone());
    }
    DslValue::Str(trimmed.to_string())
}

fn eval_dsl_function(name: &str, args: &[DslValue], _ctx: &DslContext) -> DslValue {
    match name {
        "contains" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let hay = args[0].as_string();
            let needle = args[1].as_string();
            DslValue::Bool(hay.contains(&needle))
        }
        "contains_all" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let hay = args[0].as_string();
            DslValue::Bool(args[1..].iter().all(|a| hay.contains(&a.as_string())))
        }
        "contains_any" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let hay = args[0].as_string();
            DslValue::Bool(args[1..].iter().any(|a| hay.contains(&a.as_string())))
        }
        "starts_with" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let hay = args[0].as_string();
            DslValue::Bool(args[1..].iter().any(|a| hay.starts_with(&a.as_string())))
        }
        "ends_with" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let hay = args[0].as_string();
            DslValue::Bool(args[1..].iter().any(|a| hay.ends_with(&a.as_string())))
        }
        "regex" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let pat = args[0].as_string();
            let target = args[1].as_string();
            let matched = regex::Regex::new(&pat)
                .map(|re| re.is_match(&target))
                .unwrap_or(false);
            DslValue::Bool(matched)
        }
        "len" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Int(s.len() as i64)
        }
        "tolower" | "to_lower" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.to_lowercase())
        }
        "toupper" | "to_upper" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.to_uppercase())
        }
        "trim" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let cut = args.get(1).map(DslValue::as_string).unwrap_or_else(|| " \t\r\n".into());
            let chars: Vec<char> = cut.chars().collect();
            DslValue::Str(s.trim_matches(&chars[..]).to_string())
        }
        "trim_space" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.trim().to_string())
        }
        "trim_left" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let cut = args.get(1).map(DslValue::as_string).unwrap_or_else(|| " \t\r\n".into());
            let chars: Vec<char> = cut.chars().collect();
            DslValue::Str(s.trim_start_matches(&chars[..]).to_string())
        }
        "trim_right" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let cut = args.get(1).map(DslValue::as_string).unwrap_or_else(|| " \t\r\n".into());
            let chars: Vec<char> = cut.chars().collect();
            DslValue::Str(s.trim_end_matches(&chars[..]).to_string())
        }
        "trim_prefix" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let pre = args.get(1).map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.strip_prefix(&pre).unwrap_or(&s).to_string())
        }
        "trim_suffix" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let suf = args.get(1).map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.strip_suffix(&suf).unwrap_or(&s).to_string())
        }
        "replace" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let old = args.get(1).map(DslValue::as_string).unwrap_or_default();
            let new = args.get(2).map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(s.replace(&old, &new))
        }
        "base64" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Str(base64::engine::general_purpose::STANDARD.encode(s.as_bytes()))
        }
        "base64_py" => {
            // Python `codecs.encode(b, "base64")` splits into 76-char lines ending with `\n`
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let raw = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
            let mut py = String::with_capacity(raw.len() + raw.len() / 76 + 2);
            for chunk in raw.as_bytes().chunks(76) {
                py.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                py.push('\n');
            }
            DslValue::Str(py)
        }
        "base64_decode" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(cleaned.as_bytes())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            DslValue::Str(decoded)
        }
        "url_encode" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let enc = crate::logic::find_op("URL encode")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or(s);
            DslValue::Str(enc)
        }
        "url_decode" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let dec = crate::logic::find_op("URL decode")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or(s);
            DslValue::Str(dec)
        }
        "html_escape" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let enc = crate::logic::find_op("HTML encode")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or(s);
            DslValue::Str(enc)
        }
        "html_unescape" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let dec = crate::logic::find_op("HTML decode")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or(s);
            DslValue::Str(dec)
        }
        "md5" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let digest = crate::logic::md5_bytes(s.as_bytes());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            DslValue::Str(hex)
        }
        "sha1" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let hex = crate::logic::find_op("Hash: SHA-1")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or_default();
            DslValue::Str(hex)
        }
        "sha256" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            let hex = crate::logic::find_op("Hash: SHA-256")
                .and_then(|op| (op.run)(&s).ok())
                .unwrap_or_default();
            DslValue::Str(hex)
        }
        "mmh3" => {
            let s = args.first().map(DslValue::as_string).unwrap_or_default();
            DslValue::Int(murmurhash3_x86_32(s.as_bytes(), 0) as i64)
        }
        "rand_base" | "rand_text_alpha" | "rand_text_alphanumeric" => {
            let len = args
                .first()
                .and_then(DslValue::as_int)
                .unwrap_or(8)
                .clamp(1, 64) as usize;
            let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
            let mut out = String::with_capacity(len);
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x517cc1b727220a95);
            let mut state = seed ^ (len as u64);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let idx = ((state >> 32) as usize) % alphabet.len();
                out.push(alphabet[idx] as char);
            }
            DslValue::Str(out)
        }
        "rand_int" => {
            let min = args.first().and_then(DslValue::as_int).unwrap_or(1000);
            let max = args.get(1).and_then(DslValue::as_int).unwrap_or(9999);
            let span = (max - min).max(1) as u64;
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(42);
            DslValue::Int(min + (seed % span) as i64)
        }
        "compare_versions" => {
            if args.len() < 2 {
                return DslValue::Bool(false);
            }
            let Some(v_actual) = super::passive::parse_semver(&args[0].as_string()) else {
                return DslValue::Bool(false);
            };
            for constraint_arg in &args[1..] {
                let c_str = constraint_arg.as_string();
                for part in c_str.split(',') {
                    let t = part.trim();
                    let (op, ver_part) = if let Some(r) = t.strip_prefix("<=") {
                        ("<=", r)
                    } else if let Some(r) = t.strip_prefix(">=") {
                        (">=", r)
                    } else if let Some(r) = t.strip_prefix("!=") {
                        ("!=", r)
                    } else if let Some(r) = t.strip_prefix("==") {
                        ("==", r)
                    } else if let Some(r) = t.strip_prefix('<') {
                        ("<", r)
                    } else if let Some(r) = t.strip_prefix('>') {
                        (">", r)
                    } else if let Some(r) = t.strip_prefix('=') {
                        ("==", r)
                    } else {
                        ("==", t)
                    };
                    let Some(v_target) = super::passive::parse_semver(ver_part) else {
                        return DslValue::Bool(false);
                    };
                    let ok = match op {
                        "<=" => v_actual <= v_target,
                        ">=" => v_actual >= v_target,
                        "<" => v_actual < v_target,
                        ">" => v_actual > v_target,
                        "!=" => v_actual != v_target,
                        _ => v_actual == v_target,
                    };
                    if !ok {
                        return DslValue::Bool(false);
                    }
                }
            }
            DslValue::Bool(true)
        }
        _ => DslValue::Bool(false),
    }
}

/// MurmurHash3 32-bit x86 signed hash (`mmh3` in Nuclei / Shodan favicon hashes).
pub fn murmurhash3_x86_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut h1 = seed;
    let nblocks = data.len() / 4;
    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let tail = &data[nblocks * 4..];
    let mut k1 = 0u32;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1 as i32
}

fn strip_outer_parens(mut s: &str) -> &str {
    loop {
        let t = s.trim();
        if t.len() >= 2 && t.starts_with('(') && t.ends_with(')') {
            let mut depth = 0i32;
            let mut in_quote: Option<char> = None;
            let mut escaped = false;
            let mut encloses_all = true;
            for (idx, ch) in t.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' && in_quote.is_some() {
                    escaped = true;
                    continue;
                }
                if let Some(q) = in_quote {
                    if ch == q {
                        in_quote = None;
                    }
                    continue;
                }
                if matches!(ch, '"' | '\'' | '`') {
                    in_quote = Some(ch);
                    continue;
                }
                if ch == '(' {
                    depth += 1;
                } else if ch == ')' {
                    depth -= 1;
                    if depth == 0 && idx + ch.len_utf8() < t.len() {
                        encloses_all = false;
                        break;
                    }
                }
            }
            if encloses_all && depth == 0 {
                s = &t[1..t.len() - 1];
                continue;
            }
        }
        return t;
    }
}

fn split_top_level_op<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0i32;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let ch = s[i..].chars().next()?;
        let ch_len = ch.len_utf8();
        if escaped {
            escaped = false;
            i += ch_len;
            continue;
        }
        if ch == '\\' && in_quote.is_some() {
            escaped = true;
            i += ch_len;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            i += ch_len;
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            in_quote = Some(ch);
            i += ch_len;
            continue;
        }
        if ch == '(' || ch == '[' {
            depth += 1;
        } else if ch == ')' || ch == ']' {
            depth -= 1;
        } else if depth == 0 && bytes[i..].starts_with(op_bytes) {
            // Avoid matching `>` inside `>=` or `<` inside `<=` or `=` inside `==`/`!=`/`>=`/`<=`/`=~`
            if (op == ">" || op == "<") && bytes.get(i + 1) == Some(&b'=') {
                i += 2;
                continue;
            }
            let left = s[..i].trim();
            let right = s[i + op.len()..].trim();
            if !left.is_empty() && !right.is_empty() {
                return Some((left, right));
            }
        }
        i += ch_len;
    }
    None
}

fn split_comma_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;

    for ch in s.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quote.is_some() {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if let Some(q) = in_quote {
            cur.push(ch);
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            in_quote = Some(ch);
            cur.push(ch);
            continue;
        }
        if ch == '(' || ch == '[' {
            depth += 1;
            cur.push(ch);
        } else if ch == ')' || ch == ']' {
            depth -= 1;
            cur.push(ch);
        } else if ch == ',' && depth == 0 {
            let trimmed = cur.trim().to_string();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    let tail = cur.trim().to_string();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Evaluates one `NucleiMatcher` against `ctx`, returning `Some(evidence_string)` if it matches.
pub fn evaluate_matcher(matcher: &NucleiMatcher, ctx: &DslContext) -> Option<String> {
    let target_text = match matcher.part.as_str() {
        "header" | "headers" | "all_headers" => ctx.header.clone(),
        "all" | "response" => format!("{}\r\n{}", ctx.header, ctx.body),
        "status_code" => ctx.status_code.to_string(),
        "interactsh_protocol" => ctx.interactsh_protocol.clone(),
        other => ctx
            .vars
            .get(other)
            .cloned()
            .unwrap_or_else(|| ctx.body.clone()),
    };

    let (raw_matched, evidence) = match matcher.matcher_type {
        MatcherType::Status => {
            let code = ctx.status_code as u16;
            let ok = matcher.status.contains(&code);
            (ok, format!("HTTP status {code}"))
        }
        MatcherType::Size => {
            let sz = target_text.len();
            let ok = matcher.size.contains(&sz);
            (ok, format!("Response size {sz} bytes"))
        }
        MatcherType::Word => {
            if matcher.words.is_empty() {
                return None;
            }
            let hay = if matcher.case_insensitive {
                target_text.to_lowercase()
            } else {
                target_text.clone()
            };
            let mut matched_words = Vec::new();
            let ok = match matcher.condition {
                Condition::And => matcher.words.iter().all(|w| {
                    let w_interp = interpolate_template_vars(w, &ctx.matched, &ctx.vars);
                    let needle = if matcher.case_insensitive {
                        w_interp.to_lowercase()
                    } else {
                        w_interp.clone()
                    };
                    let hit = hay.contains(&needle);
                    if hit {
                        matched_words.push(w_interp);
                    }
                    hit
                }),
                Condition::Or => matcher.words.iter().any(|w| {
                    let w_interp = interpolate_template_vars(w, &ctx.matched, &ctx.vars);
                    let needle = if matcher.case_insensitive {
                        w_interp.to_lowercase()
                    } else {
                        w_interp.clone()
                    };
                    let hit = hay.contains(&needle);
                    if hit {
                        matched_words.push(w_interp);
                    }
                    hit
                }),
            };
            (ok, matched_words.join(", "))
        }
        MatcherType::Regex => {
            if matcher.regex.is_empty() {
                return None;
            }
            let mut matched_re = Vec::new();
            let ok = match matcher.condition {
                Condition::And => matcher.regex.iter().all(|pat| {
                    let Ok(re) = regex::Regex::new(pat) else {
                        return false;
                    };
                    if let Some(m) = re.find(&target_text) {
                        matched_re.push(m.as_str().to_string());
                        true
                    } else {
                        false
                    }
                }),
                Condition::Or => matcher.regex.iter().any(|pat| {
                    let Ok(re) = regex::Regex::new(pat) else {
                        return false;
                    };
                    if let Some(m) = re.find(&target_text) {
                        matched_re.push(m.as_str().to_string());
                        true
                    } else {
                        false
                    }
                }),
            };
            (ok, matched_re.join(", "))
        }
        MatcherType::Binary => {
            if matcher.binary.is_empty() {
                return None;
            }
            let raw_bytes = target_text.as_bytes();
            let mut matched_hex = Vec::new();
            let ok = match matcher.condition {
                Condition::And => matcher.binary.iter().all(|hex_str| {
                    let needle = decode_hex_bytes(hex_str);
                    let hit = !needle.is_empty()
                        && raw_bytes.windows(needle.len()).any(|w| w == needle.as_slice());
                    if hit {
                        matched_hex.push(hex_str.clone());
                    }
                    hit
                }),
                Condition::Or => matcher.binary.iter().any(|hex_str| {
                    let needle = decode_hex_bytes(hex_str);
                    let hit = !needle.is_empty()
                        && raw_bytes.windows(needle.len()).any(|w| w == needle.as_slice());
                    if hit {
                        matched_hex.push(hex_str.clone());
                    }
                    hit
                }),
            };
            (ok, matched_hex.join(", "))
        }
        MatcherType::Dsl => {
            if matcher.dsl.is_empty() {
                return None;
            }
            let mut matched_exprs = Vec::new();
            let ok = match matcher.condition {
                Condition::And => matcher.dsl.iter().all(|expr| {
                    let interp = interpolate_template_vars(expr, &ctx.matched, &ctx.vars);
                    let hit = evaluate_dsl(&interp, ctx);
                    if hit {
                        matched_exprs.push(interp);
                    }
                    hit
                }),
                Condition::Or => matcher.dsl.iter().any(|expr| {
                    let interp = interpolate_template_vars(expr, &ctx.matched, &ctx.vars);
                    let hit = evaluate_dsl(&interp, ctx);
                    if hit {
                        matched_exprs.push(interp);
                    }
                    hit
                }),
            };
            (ok, matched_exprs.join(" && "))
        }
    };

    let final_ok = if matcher.negative {
        !raw_matched
    } else {
        raw_matched
    };
    if final_ok {
        Some(if evidence.is_empty() {
            "Nuclei matcher satisfied".into()
        } else {
            evidence
        })
    } else {
        None
    }
}

fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .filter_map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Runs all `extractors` on `ctx`, storing named extractions in `ctx.vars` and returning non-internal ones.
pub fn run_extractors(extractors: &[NucleiExtractor], ctx: &mut DslContext) -> Vec<String> {
    let mut extracted = Vec::new();
    for ex in extractors {
        let target_text = match ex.part.as_str() {
            "header" | "headers" | "all_headers" => ctx.header.clone(),
            "all" => format!("{}\r\n{}", ctx.header, ctx.body),
            _ => ctx.body.clone(),
        };
        match ex.extractor_type.as_str() {
            "regex" => {
                for pat in &ex.regex {
                    if let Ok(re) = regex::Regex::new(pat) {
                        if let Some(caps) = re.captures(&target_text) {
                            if let Some(m) = caps.get(ex.group).or_else(|| caps.get(0)) {
                                let val = m.as_str().to_string();
                                if !ex.name.is_empty() {
                                    ctx.vars.insert(ex.name.clone(), val.clone());
                                }
                                if !ex.internal {
                                    extracted.push(val);
                                }
                            }
                        }
                    }
                }
            }
            "kval" => {
                for key in &ex.kval {
                    for line in ctx.header.lines() {
                        if let Some((hk, hv)) = line.split_once(':') {
                            if hk.trim().eq_ignore_ascii_case(key)
                                || hk.trim().replace('-', "_").eq_ignore_ascii_case(key)
                            {
                                let val = hv.trim().to_string();
                                if !ex.name.is_empty() {
                                    ctx.vars.insert(ex.name.clone(), val.clone());
                                }
                                if !ex.internal {
                                    extracted.push(format!("{key}={val}"));
                                }
                            }
                        }
                    }
                }
            }
            "dsl" => {
                for expr in &ex.dsl {
                    let val = eval_dsl_value(expr, ctx).as_string();
                    if !val.is_empty() {
                        if !ex.name.is_empty() {
                            ctx.vars.insert(ex.name.clone(), val.clone());
                        }
                        if !ex.internal {
                            extracted.push(val);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    extracted
}

fn build_finding_from_template(
    tmpl: &NucleiTemplate,
    matched_url: &str,
    evidence: &str,
    extracted: &[String],
) -> Finding {
    let title = if !tmpl.info.name.is_empty() {
        if tmpl.id.starts_with("CVE-") && !tmpl.info.name.contains(&tmpl.id) {
            format!("{} ({})", tmpl.info.name, tmpl.id)
        } else {
            tmpl.info.name.clone()
        }
    } else {
        tmpl.id.clone()
    };

    let mut details = Vec::new();
    if !tmpl.info.description.is_empty() {
        details.push(tmpl.info.description.clone());
    }
    if !tmpl.info.classification.cve_id.is_empty() {
        details.push(format!("CVE: {}", tmpl.info.classification.cve_id));
    }
    if !tmpl.info.classification.cwe_id.is_empty() {
        details.push(format!("CWE: {}", tmpl.info.classification.cwe_id));
    }
    if !tmpl.info.classification.cvss_score.is_empty() {
        details.push(format!(
            "CVSS: {} ({})",
            tmpl.info.classification.cvss_score, tmpl.info.classification.cvss_metrics
        ));
    }
    if let Some(first_ref) = tmpl.info.references.first() {
        details.push(format!("Reference: {first_ref}"));
    }

    let full_evidence = if extracted.is_empty() {
        evidence.to_string()
    } else {
        format!("{evidence} | Extracted: {}", extracted.join(", "))
    };
    let explain = if details.is_empty() {
        format!("Matched Nuclei template `{}`.", tmpl.id)
    } else {
        details.join(" — ")
    };

    Finding::new(
        &title,
        tmpl.info.severity,
        matched_url,
         Some(tmpl.id.clone()),
        &full_evidence,
        &explain,
    )
}

/// Evaluates a parsed `NucleiTemplate` passively against an already-fetched `Response`.
pub fn evaluate_template_on_response(
    tmpl: &NucleiTemplate,
    url: &str,
    response: &Response,
) -> Option<Finding> {
    let mut vars = BTreeMap::new();
    vars.insert("randstr".into(), "gulp7f9a2b".into());
    let dummy_ctx = DslContext::default();
    for (k, v) in &tmpl.variables {
        let resolved = if v.starts_with("{{") && v.ends_with("}}") {
            eval_dsl_value(&v[2..v.len() - 2], &dummy_ctx).as_string()
        } else {
            v.clone()
        };
        vars.insert(k.clone(), resolved);
    }

    let mut ctx = DslContext::from_response(url, response, 0, vars);
    ctx.push_step(
        response.status as i64,
        response.body.clone(),
        ctx.header.clone(),
        ctx.content_type.clone(),
    );

    for req_step in &tmpl.http {
        let extracted = run_extractors(&req_step.extractors, &mut ctx);
        let non_internal: Vec<&NucleiMatcher> =
            req_step.matchers.iter().filter(|m| !m.internal).collect();
        if non_internal.is_empty() {
            continue;
        }
        let mut evidences = Vec::new();
        let matched = match req_step.matchers_condition {
            Condition::And => non_internal.iter().all(|m| {
                if let Some(ev) = evaluate_matcher(m, &ctx) {
                    evidences.push(ev);
                    true
                } else {
                    false
                }
            }),
            Condition::Or => non_internal.iter().any(|m| {
                if let Some(ev) = evaluate_matcher(m, &ctx) {
                    evidences.push(ev);
                    true
                } else {
                    false
                }
            }),
        };
        if matched {
            return Some(build_finding_from_template(
                tmpl,
                url,
                &evidences.join(" & "),
                &extracted,
            ));
        }
    }
    None
}

/// Actively executes a `NucleiTemplate` (including multi-step `raw:` and `path:` requests,
/// `flow: http(1) && http(2)`, `variables:`, `extractors:`, and `matchers:`) against `base_url`.
pub async fn execute_template_active(
    tmpl: &NucleiTemplate,
    base_url: &str,
    proxy: &crate::proxy::Proxy,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return findings;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return findings;
    }
    let tls = scheme.eq_ignore_ascii_case("https");
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().unwrap_or(if tls { 443 } else { 80 }),
        ),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };

    let mut vars = BTreeMap::new();
    vars.insert("randstr".into(), "gulp7f9a2b".into());
    let dummy_ctx = DslContext::default();
    for (k, v) in &tmpl.variables {
        let resolved = if v.starts_with("{{") && v.ends_with("}}") {
            eval_dsl_value(&v[2..v.len() - 2], &dummy_ctx).as_string()
        } else {
            v.clone()
        };
        vars.insert(k.clone(), resolved);
    }

    let mut ctx = DslContext {
        host: authority.to_string(),
        matched: base_url.to_string(),
        vars,
        ..Default::default()
    };

    for req_step in &tmpl.http {
        let mut raw_payloads: Vec<(String, String)> = Vec::new();

        for raw_tmpl in &req_step.raw {
            let interpolated = interpolate_template_vars(raw_tmpl, base_url, &ctx.vars);
            let first_line = interpolated.lines().next().unwrap_or("GET / HTTP/1.1");
            let req_path = first_line.split_whitespace().nth(1).unwrap_or("/");
            let full_u = if req_path.starts_with("http://") || req_path.starts_with("https://") {
                req_path.to_string()
            } else {
                format!("{scheme}://{authority}{req_path}")
            };
            raw_payloads.push((full_u, interpolated));
        }

        for path_tmpl in &req_step.paths {
            let full_u = interpolate_template_vars(path_tmpl, base_url, &ctx.vars);
            let req_path = crate::scanner::http::path_of(&full_u);
            let body_interp = interpolate_template_vars(&req_step.body, base_url, &ctx.vars);
            let mut raw = format!(
                "{} {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
                req_step.method, req_path
            );
            for (hk, hv) in &req_step.headers {
                let hv_i = interpolate_template_vars(hv, base_url, &ctx.vars);
                raw.push_str(&format!("{hk}: {hv_i}\r\n"));
            }
            if !body_interp.is_empty() {
                raw.push_str(&format!("Content-Length: {}\r\n", body_interp.len()));
            }
            raw.push_str("Connection: close\r\n\r\n");
            raw.push_str(&body_interp);
            raw_payloads.push((full_u, raw));
        }

        for (req_url, raw_wire) in raw_payloads {
            let started = std::time::Instant::now();
            let Ok((_, resp_text)) = proxy
                .one_shot_secure(&host, port, &raw_wire, tls, 6_000)
                .await
            else {
                continue;
            };
            let elapsed_ms = started.elapsed().as_millis();
            let parsed = parse_response(&resp_text);
            let mut hdr_str = format!("HTTP/1.1 {}\r\n", parsed.status);
            for (k, v) in &parsed.headers {
                hdr_str.push_str(&format!("{k}: {v}\r\n"));
            }
            let ct = parsed.header("content-type").unwrap_or("").to_string();
            ctx.duration = (elapsed_ms as f64) / 1000.0;
            ctx.matched = req_url.clone();
            ctx.push_step(parsed.status as i64, parsed.body.clone(), hdr_str, ct);

            let extracted = run_extractors(&req_step.extractors, &mut ctx);

            // Check internal matchers (used in `flow: http(1) && http(2)` preconditions)
            let internal_failed = req_step
                .matchers
                .iter()
                .filter(|m| m.internal)
                .any(|m| evaluate_matcher(m, &ctx).is_none());
            if internal_failed {
                return findings;
            }

            let non_internal: Vec<&NucleiMatcher> =
                req_step.matchers.iter().filter(|m| !m.internal).collect();
            if non_internal.is_empty() {
                continue;
            }

            let mut evidences = Vec::new();
            let matched = match req_step.matchers_condition {
                Condition::And => non_internal.iter().all(|m| {
                    if let Some(ev) = evaluate_matcher(m, &ctx) {
                        evidences.push(ev);
                        true
                    } else {
                        false
                    }
                }),
                Condition::Or => non_internal.iter().any(|m| {
                    if let Some(ev) = evaluate_matcher(m, &ctx) {
                        evidences.push(ev);
                        true
                    } else {
                        false
                    }
                }),
            };

            if matched {
                findings.push(build_finding_from_template(
                    tmpl,
                    &req_url,
                    &evidences.join(" & "),
                    &extracted,
                ));
                if req_step.stop_at_first_match {
                    break;
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuclei_dsl_evaluates_functions_comparisons_and_boolean_logic() {
        let resp = parse_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx/1.18.0\r\n\r\n{\"job_id\":\"123\",\"job_name\":\"run_task\",\"version\":\"1.4.2\"}",
        );
        let mut vars = BTreeMap::new();
        vars.insert("randstr".into(), "abc123".into());
        let ctx = DslContext::from_response("https://example.test/api", &resp, 45, vars);

        assert!(evaluate_dsl(
            "contains_all(body, \"\\\"job_id\\\":\", \"\\\"job_name\\\":\") && contains(content_type, \"application/json\") && status_code == 200",
            &ctx
        ));
        assert!(evaluate_dsl(
            "contains_any(header, \"apache\", \"nginx\") && content_length > 10",
            &ctx
        ));
        assert!(evaluate_dsl(
            "regex(\"job_id\\\":\\\"[0-9]+\", body) && !contains(body, \"error\")",
            &ctx
        ));
        assert!(evaluate_dsl("len(to_lower(\"ADMIN\")) == 5", &ctx));
        assert!(evaluate_dsl(
            "base64_decode(base64(\"gulpsuite\")) == \"gulpsuite\"",
            &ctx
        ));
        assert!(evaluate_dsl("compare_versions(\"1.4.2\", \"< 1.5.0, >= 1.0.0\")", &ctx));
        assert!(!evaluate_dsl("compare_versions(\"1.4.2\", \">= 2.0.0\")", &ctx));
    }

    #[test]
    fn parses_and_evaluates_real_nuclei_cve_yaml_templates() {
        let yaml = r#"
id: CVE-2026-0545

info:
  name: MLflow Job API - Authentication Bypass
  author: DhiyaneshDk
  severity: critical
  description: |
    MLflow contains an authentication bypass under /ajax-api/3.0/jobs/*.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-0545
  classification:
    cvss-score: 9.1
    cve-id: CVE-2026-0545
    cwe-id: CWE-306
  tags: cve,cve2026,mlflow,auth-bypass

http:
  - raw:
      - |
        POST /ajax-api/3.0/jobs/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"job_name":"run_task","params":{"command":"id"}}

    matchers:
      - type: dsl
        dsl:
          - 'contains_all(body, "\"job_id\":", "\"job_name\":")'
          - 'contains(content_type, "application/json")'
          - 'status_code == 200'
        condition: and
"#;
        let tmpl = parse_nuclei_template(yaml).expect("parse nuclei template");
        assert_eq!(tmpl.id, "CVE-2026-0545");
        assert_eq!(tmpl.info.severity, Severity::High);
        assert_eq!(tmpl.info.classification.cve_id, "CVE-2026-0545");
        assert_eq!(tmpl.info.classification.cwe_id, "CWE-306");
        assert_eq!(tmpl.http.len(), 1);
        assert_eq!(tmpl.http[0].raw.len(), 1);
        assert_eq!(tmpl.http[0].matchers.len(), 1);

        let vuln_resp = parse_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"job_id\":\"42\",\"job_name\":\"run_task\"}",
        );
        let finding = evaluate_template_on_response(
            &tmpl,
            "https://target.test/ajax-api/3.0/jobs/",
            &vuln_resp,
        )
        .expect("should match vulnerable response");
        assert!(finding.name.contains("CVE-2026-0545"));
        assert!(finding.confidence.contains("CWE-306"));

        let safe_resp = parse_response(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized",
        );
        assert!(
            evaluate_template_on_response(&tmpl, "https://target.test/ajax-api/3.0/jobs/", &safe_resp)
                .is_none()
        );
    }
}
