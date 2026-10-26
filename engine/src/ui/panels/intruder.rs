//! Native Gulpsuite Professional Intruder panel:
//! Attack tabs (`1 × | +`), 50/50 Getting Started Rocket view, Attack Type selector with
//! descriptions, orange `▶ Start attack` button, `Positions` request editor with visual `§...§`
//! highlight markers, 8-column `Results` table (`Request`, `Payload`, `Status code`,
//! `Response received`, `Error`, `Timeout`, `Length`, `Comment` + Grep columns), and collapsible
//! right-hand side panel (`§ Payloads`, `◔ Resource pool`, `⚙ Settings`).

use crate::http_target::HttpTarget;
use crate::intruder::{self, AttackControl, AttackOptions, AttackState, AttackType};
use crate::proxy::MatchRules;
use crate::ui::app::App;
use crate::ui::panels::{heading, muted};
use crate::workspace::TaskId;
use eframe::egui::{self, Color32, RichText, Stroke, Ui, Vec2, pos2};

pub type Result = intruder::AttackResult;

#[derive(Clone, Debug)]
pub struct PayloadProcessingRule {
    pub enabled: bool,
    pub kind: String,
    pub arg1: String,
    pub arg2: String,
}

impl PayloadProcessingRule {
    pub fn apply(&self, input: &str, base_value: &str, collab_domain: &str) -> Option<String> {
        if !self.enabled {
            return Some(input.to_string());
        }
        match self.kind.as_str() {
            "Add prefix" => Some(format!("{}{input}", self.arg1)),
            "Add suffix" => Some(format!("{input}{}", self.arg1)),
            "Match / replace" => {
                if let Ok(re) = regex::Regex::new(&self.arg1) {
                    Some(re.replace_all(input, self.arg2.as_str()).into_owned())
                } else {
                    Some(input.replace(&self.arg1, &self.arg2))
                }
            }
            "Substring" => {
                let offset = self.arg1.parse::<usize>().unwrap_or(0);
                let len = self.arg2.parse::<usize>().unwrap_or(input.len());
                Some(input.chars().skip(offset).take(len).collect())
            }
            "Reverse substring" => {
                let chars: Vec<char> = input.chars().collect();
                let end_off = self.arg1.parse::<usize>().unwrap_or(0);
                let len = self.arg2.parse::<usize>().unwrap_or(chars.len());
                let end = chars.len().saturating_sub(end_off);
                let start = end.saturating_sub(len);
                Some(chars[start..end].iter().collect())
            }
            "Modify case" => Some(match self.arg1.as_str() {
                "To lower case" => input.to_lowercase(),
                "To upper case" => input.to_uppercase(),
                "To Propername" => {
                    let mut c = input.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => {
                            f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase()
                        }
                    }
                }
                "To ProperName" => {
                    let mut c = input.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                }
                _ => input.to_string(),
            }),
            "Encode" | "Decode" | "Hash" => {
                let op_name = if self.arg1.is_empty() {
                    "URL encode"
                } else {
                    self.arg1.as_str()
                };
                crate::logic::find_op(op_name)
                    .and_then(|op| (op.run)(input).ok())
                    .or_else(|| Some(input.to_string()))
            }
            "Add raw payload" => {
                if self.arg1 == "Before" {
                    Some(format!("{base_value}{input}"))
                } else {
                    Some(format!("{input}{base_value}"))
                }
            }
            "Skip if matches regex" => {
                if let Ok(re) = regex::Regex::new(&self.arg1) {
                    if re.is_match(input) {
                        return None;
                    }
                }
                Some(input.to_string())
            }
            "Replace placeholder with base value" => Some(input.replace("{base}", base_value)),
            "Replace placeholder with collaborator payload" => {
                Some(input.replace("{domain}", collab_domain))
            }
            _ => Some(input.to_string()),
        }
    }
}

pub const PAYLOAD_TYPES: [&str; 19] = [
    "Simple list",
    "Runtime file",
    "Custom iterator",
    "Character substitution",
    "Case modification",
    "Recursive grep",
    "Illegal Unicode",
    "Character blocks",
    "Numbers",
    "Dates & times",
    "Brute forcer",
    "Null payloads",
    "Character frobber",
    "Bit flipper",
    "Username generator",
    "ECB block shuffler",
    "Copy other payload",
    "Collaborator payloads",
    "Custom modification",
];

pub const PROCESSING_RULE_TYPES: [&str; 13] = [
    "Add prefix",
    "Add suffix",
    "Match / replace",
    "Substring",
    "Reverse substring",
    "Modify case",
    "Encode",
    "Decode",
    "Hash",
    "Add raw payload",
    "Skip if matches regex",
    "Replace placeholder with base value",
    "Replace placeholder with collaborator payload",
];

#[derive(Clone)]
pub struct PayloadSet {
    pub kind: String,
    pub values: String,
    pub range_start: String,
    pub range_end: String,
    pub range_step: i64,
    pub processor: String,
    pub new_item_draft: String,
    pub selected_item: Option<usize>,
    pub runtime_file_path: String,
    pub custom_iterator_sep: String,
    pub char_sub_rules: String,
    pub number_random: bool,
    pub number_how_many: usize,
    pub number_hex: bool,
    pub min_int_digits: usize,
    pub max_int_digits: usize,
    pub date_format: String,
    pub char_block_base: String,
    pub char_block_min: usize,
    pub char_block_max: usize,
    pub char_block_step: usize,
    pub brute_charset: String,
    pub brute_min_len: usize,
    pub brute_max_len: usize,
    pub null_count: usize,
    pub frobber_string: String,
    pub bit_flipper_string: String,
    pub bit_flipper_hex: bool,
    pub bit_flipper_mask: u8,
    pub username_max_per_item: usize,
    pub ecb_block_size: usize,
    pub copy_source_pos: usize,
    pub collab_include_server: bool,
    pub processing_rules: Vec<PayloadProcessingRule>,
    pub new_rule_kind: String,
    pub new_rule_arg1: String,
    pub new_rule_arg2: String,
    pub url_encode_enabled: bool,
    pub url_encode_chars: String,
}

impl Default for PayloadSet {
    fn default() -> Self {
        Self {
            kind: "Simple list".into(),
            values: "a\nb\nc".into(),
            range_start: "1".into(),
            range_end: "10".into(),
            range_step: 1,
            processor: "URL encode".into(),
            new_item_draft: String::new(),
            selected_item: None,
            runtime_file_path: String::new(),
            custom_iterator_sep: "/".into(),
            char_sub_rules: "e=3,a=4,t=7,s=5,o=0".into(),
            number_random: false,
            number_how_many: 10,
            number_hex: false,
            min_int_digits: 1,
            max_int_digits: 0,
            date_format: "yyyy-MM-dd".into(),
            char_block_base: "A".into(),
            char_block_min: 10,
            char_block_max: 100,
            char_block_step: 10,
            brute_charset: "abc012".into(),
            brute_min_len: 1,
            brute_max_len: 2,
            null_count: 10,
            frobber_string: "session".into(),
            bit_flipper_string: "ab".into(),
            bit_flipper_hex: false,
            bit_flipper_mask: 0xFF,
            username_max_per_item: 15,
            ecb_block_size: 16,
            copy_source_pos: 1,
            collab_include_server: true,
            processing_rules: Vec::new(),
            new_rule_kind: "Add prefix".into(),
            new_rule_arg1: String::new(),
            new_rule_arg2: String::new(),
            url_encode_enabled: false,
            url_encode_chars: "!\"#%&'()*+,/:;<=>?@[\\]^`{|}~".into(),
        }
    }
}

impl PayloadSet {
    pub fn description(&self) -> &'static str {
        match self.kind.as_str() {
            "Simple list" => {
                "This payload type lets you configure a simple list of strings that are used as payloads."
            }
            "Runtime file" => {
                "Read payload strings line-by-line from a local UTF-8 file at runtime."
            }
            "Custom iterator" => {
                "Generate payloads using permutations of items across positions with an optional separator."
            }
            "Character substitution" => {
                "Apply character substitutions (e.g. e>3, t>7) to each item in a list of strings."
            }
            "Case modification" => {
                "Generate lower, upper, Propername, and ProperName case variations for each list item."
            }
            "Recursive grep" => {
                "Extract text from the previous response and use it as the payload for the next request."
            }
            "Illegal Unicode" => {
                "Replace characters with overlong UTF-8 and illegal hex encodings to test input filters."
            }
            "Character blocks" => {
                "Generate payloads based on blocks of a repeated character or base string."
            }
            "Numbers" => "Generate numeric payloads within a given range and format.",
            "Dates & times" | "Dates" => "Generate date/time payloads within a given range and step.",
            "Brute forcer" => {
                "Generate all permutations of a character set between Min and Max length."
            }
            "Null payloads" => {
                "Generate empty-string payloads to repeatedly issue the base request."
            }
            "Character frobber" => {
                "Cycle through each character position one at a time, incrementing its ASCII code by 1."
            }
            "Bit flipper" => {
                "Cycle through each byte and flip selected bits (0000000X..X0000000) in literal or ASCII hex."
            }
            "Username generator" => {
                "Derive candidate usernames and email prefixes from a list of full names."
            }
            "ECB block shuffler" => {
                "Shuffle fixed-size blocks (8 or 16 bytes) in ECB-encrypted tokens."
            }
            "Copy other payload" => {
                "Copy the current payload value from another payload position."
            }
            "Collaborator payloads" => {
                "Generate unique out-of-band Collaborator interaction domains for each request."
            }
            _ => "Apply a Decoder/Encoder transformation to every item in the list.",
        }
    }

    pub fn generate(&self, limit: usize) -> std::result::Result<Vec<String>, String> {
        let raw_list: Vec<String> = match self.kind.as_str() {
            "Numbers" => {
                let nums = intruder::number_payloads(
                    self.range_start
                        .parse()
                        .map_err(|_| "Invalid number range start")?,
                    self.range_end
                        .parse()
                        .map_err(|_| "Invalid number range end")?,
                    self.range_step,
                    limit,
                )?;
                nums.into_iter()
                    .map(|s| {
                        if let Ok(v) = s.parse::<i64>() {
                            let formatted = if self.number_hex {
                                format!("{:x}", v)
                            } else {
                                format!("{}", v)
                            };
                            if self.min_int_digits > 1 && formatted.len() < self.min_int_digits {
                                format!(
                                    "{:0>width$}",
                                    formatted,
                                    width = self.min_int_digits
                                )
                            } else {
                                formatted
                            }
                        } else {
                            s
                        }
                    })
                    .collect()
            }
            "Dates & times" | "Dates" => {
                intruder::date_payloads(&self.range_start, &self.range_end, self.range_step, limit)?
            }
            "Runtime file" => {
                let path = self.runtime_file_path.trim();
                if path.is_empty() {
                    self.values.lines().map(str::to_owned).collect()
                } else {
                    let content = std::fs::read_to_string(path)
                        .map_err(|e| format!("Failed to read {path}: {e}"))?;
                    content.lines().take(limit).map(str::to_owned).collect()
                }
            }
            "Character blocks" => {
                let step = self.char_block_step.max(1);
                let min = self.char_block_min.max(1);
                let max = self.char_block_max.max(min);
                let mut out = Vec::new();
                let mut n = min;
                while n <= max && out.len() < limit {
                    out.push(self.char_block_base.repeat(n));
                    n += step;
                }
                out
            }
            "Null payloads" => vec![String::new(); self.null_count.clamp(1, limit)],
            "Character frobber" => {
                let base = if self.frobber_string.is_empty() {
                    "session"
                } else {
                    self.frobber_string.as_str()
                };
                let chars: Vec<char> = base.chars().collect();
                let mut out = Vec::new();
                for i in 0..chars.len() {
                    let mut c = chars.clone();
                    c[i] = char::from_u32((c[i] as u32).wrapping_add(1)).unwrap_or(c[i]);
                    out.push(c.into_iter().collect());
                }
                out
            }
            "Bit flipper" => {
                let base = if self.bit_flipper_string.is_empty() {
                    "ab"
                } else {
                    self.bit_flipper_string.as_str()
                };
                let bytes = base.as_bytes();
                let mut out = Vec::new();
                for i in 0..bytes.len() {
                    for bit in 0..8u8 {
                        if (self.bit_flipper_mask & (1 << bit)) != 0 {
                            let mut copy = bytes.to_vec();
                            copy[i] ^= 1 << bit;
                            out.push(String::from_utf8_lossy(&copy).into_owned());
                            if out.len() >= limit {
                                break;
                            }
                        }
                    }
                }
                out
            }
            "Case modification" => {
                let mut out = Vec::new();
                for line in self.values.lines().filter(|l| !l.is_empty()) {
                    for v in [
                        line.to_string(),
                        line.to_lowercase(),
                        line.to_uppercase(),
                        {
                            let mut c = line.chars();
                            c.next()
                                .map(|f| {
                                    f.to_uppercase().collect::<String>()
                                        + &c.as_str().to_lowercase()
                                })
                                .unwrap_or_default()
                        },
                    ] {
                        if !out.contains(&v) && out.len() < limit {
                            out.push(v);
                        }
                    }
                }
                out
            }
            "Character substitution" => {
                let mut subs = Vec::new();
                for pair in self.char_sub_rules.split(',') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if !k.trim().is_empty() && !v.trim().is_empty() {
                            subs.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                }
                let mut out = Vec::new();
                for line in self.values.lines().filter(|l| !l.is_empty()) {
                    out.push(line.to_string());
                    let mut all_sub = line.to_string();
                    for (from, to) in &subs {
                        let single = line.replace(from, to);
                        if !out.contains(&single) && out.len() < limit {
                            out.push(single);
                        }
                        all_sub = all_sub.replace(from, to);
                    }
                    if !out.contains(&all_sub) && out.len() < limit {
                        out.push(all_sub);
                    }
                }
                out
            }
            "Username generator" => {
                let mut out = Vec::new();
                for line in self.values.lines().filter(|l| !l.trim().is_empty()) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let first = parts[0].to_lowercase();
                        let last = parts[1].to_lowercase();
                        let f1: String = first.chars().take(1).collect();
                        let l1: String = last.chars().take(1).collect();
                        for cand in [
                            format!("{first}{last}"),
                            format!("{first}.{last}"),
                            format!("{first}_{last}"),
                            format!("{last}{first}"),
                            format!("{last}.{first}"),
                            first.clone(),
                            last.clone(),
                            format!("{first}{l1}"),
                            format!("{first}.{l1}"),
                            format!("{f1}{last}"),
                            format!("{f1}.{last}"),
                            format!("{last}{f1}"),
                            format!("{last}.{f1}"),
                        ] {
                            if !out.contains(&cand) && out.len() < limit {
                                out.push(cand);
                            }
                        }
                    } else if let Some(single) = parts.first() {
                        out.push(single.to_lowercase());
                    }
                }
                out
            }
            "Brute forcer" => {
                let chars: Vec<char> = self.brute_charset.chars().collect();
                if chars.is_empty() {
                    return Err("Brute forcer character set cannot be empty".into());
                }
                let min_l = self.brute_min_len.max(1);
                let max_l = self.brute_max_len.max(min_l).min(6);
                let mut out = Vec::new();
                for len in min_l..=max_l {
                    let mut current = vec![String::new()];
                    for _ in 0..len {
                        let mut next = Vec::new();
                        for prefix in &current {
                            for ch in &chars {
                                if out.len() + next.len() >= limit {
                                    break;
                                }
                                next.push(format!("{prefix}{ch}"));
                            }
                        }
                        current = next;
                    }
                    for item in current {
                        if out.len() >= limit {
                            break;
                        }
                        out.push(item);
                    }
                }
                out
            }
            "Collaborator payloads" => (1..=self.null_count.clamp(1, 100))
                .map(|i| {
                    if self.collab_include_server {
                        format!("intruder-{i}.oastify.com")
                    } else {
                        format!("intruder-{i}")
                    }
                })
                .collect(),
            "Custom iterator" => {
                let rows: Vec<Vec<String>> = self
                    .values
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.split(',').map(|s| s.trim().to_string()).collect())
                    .collect();
                if rows.is_empty() {
                    Vec::new()
                } else if rows.iter().all(|r| r.len() <= 1) {
                    rows.into_iter().flatten().take(limit).collect()
                } else {
                    let mut current = vec![String::new()];
                    for (idx, row) in rows.iter().enumerate() {
                        let mut next = Vec::new();
                        for prefix in &current {
                            for item in row {
                                if next.len() >= limit {
                                    break;
                                }
                                if idx == 0 {
                                    next.push(item.clone());
                                } else {
                                    next.push(format!("{prefix}{}{item}", self.custom_iterator_sep));
                                }
                            }
                        }
                        current = next;
                    }
                    current
                }
            }
            "Illegal Unicode" => {
                let mut out = Vec::new();
                for line in self.values.lines().filter(|l| !l.is_empty()) {
                    let candidates = [
                        line.replace('/', "%c0%af").replace('.', "%c0%ae"),
                        line.replace('/', "%e0%80%af").replace('.', "%e0%80%ae"),
                        line.replace('/', "%u002f").replace('.', "%u002e"),
                        line.replace('<', "%c0%bc").replace('>', "%c0%be").replace('\'', "%c0%a7"),
                    ];
                    for cand in candidates {
                        if !out.contains(&cand) && out.len() < limit {
                            out.push(cand);
                        }
                    }
                }
                if out.is_empty() {
                    out.push("%c0%af".into());
                }
                out
            }
            "ECB block shuffler" => {
                let block_len = self.ecb_block_size.max(4);
                let mut out = Vec::new();
                for line in self.values.lines().filter(|l| !l.is_empty()) {
                    out.push(line.to_string());
                    let bytes = line.as_bytes();
                    if bytes.len() >= block_len * 2 {
                        let chunks: Vec<&[u8]> = bytes.chunks(block_len).collect();
                        for i in 0..chunks.len() {
                            for j in (i + 1)..chunks.len() {
                                let mut swapped = chunks.clone();
                                swapped.swap(i, j);
                                let candidate = String::from_utf8_lossy(&swapped.concat()).into_owned();
                                if !out.contains(&candidate) && out.len() < limit {
                                    out.push(candidate);
                                }
                            }
                        }
                    }
                }
                out
            }
            "Simple list" | "Custom modification" | "Recursive grep" | "Copy other payload" => {
                let values: Vec<_> = self.values.lines().map(str::to_owned).collect();
                if values.len() > limit {
                    return Err(format!("Payload set exceeds {limit} values"));
                }
                if self.kind == "Custom modification" {
                    let operation = crate::logic::find_op(&self.processor)
                        .ok_or("Unknown payload processor")?;
                    values
                        .iter()
                        .map(|value| (operation.run)(value))
                        .collect::<std::result::Result<Vec<_>, _>>()?
                } else {
                    values
                }
            }
            _ => return Err(format!("Unsupported payload type: {}", self.kind)),
        };

        // Apply sequential Payload Processing rules & final URL-encoding
        let mut processed = Vec::with_capacity(raw_list.len());
        for item in raw_list {
            let mut cur = Some(item.clone());
            for rule in &self.processing_rules {
                if let Some(val) = cur {
                    cur = rule.apply(&val, &item, "collab.oastify.com");
                }
            }
            if let Some(mut final_val) = cur {
                if self.url_encode_enabled && !self.url_encode_chars.is_empty() {
                    let mut encoded = String::with_capacity(final_val.len());
                    for ch in final_val.chars() {
                        if self.url_encode_chars.contains(ch) {
                            for b in ch.to_string().as_bytes() {
                                encoded.push_str(&format!("%{:02X}", b));
                            }
                        } else {
                            encoded.push(ch);
                        }
                    }
                    final_val = encoded;
                }
                processed.push(final_val);
            }
        }
        Ok(processed)
    }
}

#[derive(Clone)]
pub struct IntruderPanel {
    pub template: String,
    pub payloads: String,
    pub results: Vec<Result>,
    pub running: bool,
    pub matches: usize,
    pub threads: usize,
    pub host: String,
    pub status_codes: String,
    pub negative_status: String,
    pub negative_regex: String,
    pub match_length: bool,
    pub update_host: bool,
    pub payload_sets: Vec<PayloadSet>,
    pub generation_sources: String,
    pub attack_type: AttackType,
    pub control: Option<AttackControl>,
    pub task_id: Option<TaskId>,
    pub selected: Option<usize>,
    pub total: usize,
    pub request_delay_ms: u64,
    pub timeout_ms: u64,
    pub only_matches: bool,
    pub result_filter: String,
    pub sort_column: Option<usize>,
    pub sort_ascending: bool,
    pub template_height: f32,
    pub results_height: f32,
    pub detail_height: f32,
    pub split_ratio: f32,
    // Gulpsuite multi-tab, Getting Started, Side Panel, Resource Pool, and Attack Settings
    pub tabs: Vec<String>,
    pub active_tab: usize,
    pub show_getting_started: bool,
    pub hide_getting_started_forever: bool,
    pub side_panel_tab: usize,
    pub side_panel_collapsed: bool,
    pub side_panel_left: bool,
    pub main_split_ratio: f32,
    pub left_sub_tab: usize,
    pub template_view_mode: usize,
    pub result_msg_tab: usize,
    pub result_msg_format: usize,
    pub resource_pool_mode: usize,
    pub resource_pool_name: String,
    pub delay_mode: usize,
    pub delay_increment_ms: u64,
    pub auto_throttle: bool,
    pub auto_throttle_codes: String,
    pub save_attack_to_project: bool,
    pub update_content_length: bool,
    pub set_connection_close: bool,
    pub retries_on_failure: usize,
    pub pause_before_retry_ms: u64,
    pub store_requests_responses: bool,
    pub make_baseline_request: bool,
    pub dos_mode: bool,
    pub store_full_payloads: bool,
    pub auto_pause_enabled: bool,
    pub auto_pause_when_appears: bool,
    pub auto_pause_expressions: String,
    pub auto_pause_regex: bool,
    pub auto_pause_case_sensitive: bool,
    pub grep_match_enabled: bool,
    pub grep_match_expressions: String,
    pub grep_match_regex: bool,
    pub grep_match_case_sensitive: bool,
    pub grep_match_exclude_headers: bool,
    pub grep_extract_enabled: bool,
    pub grep_extract_pattern: String,
    pub grep_extract_max_len: usize,
    pub grep_payloads_enabled: bool,
    pub grep_payloads_case_sensitive: bool,
    pub grep_payloads_exclude_headers: bool,
    pub grep_payloads_pre_urlencoded: bool,
    pub follow_redirections: usize,
    pub process_cookies_in_redirections: bool,
    pub http1_connection_reuse: bool,
    pub override_http2: bool,
    pub default_to_http2: bool,
    pub auto_payload_append: bool,
    pub new_tab_config_mode: usize,
    pub close_running_action: usize,
    pub close_finished_action: usize,
    selection: Option<std::ops::Range<usize>>,
    result_positions: std::collections::HashMap<usize, usize>,
}

impl Default for IntruderPanel {
    fn default() -> Self {
        Self {
            template: "GET /search?q=§x§ HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            payloads: "a\nb\nc".into(),
            results: Vec::new(),
            running: false,
            matches: 0,
            threads: 10,
            host: "http://example.com".into(),
            status_codes: String::new(),
            negative_status: String::new(),
            negative_regex: String::new(),
            match_length: false,
            update_host: true,
            payload_sets: vec![PayloadSet::default()],
            generation_sources: String::new(),
            attack_type: AttackType::Sniper,
            control: None,
            task_id: None,
            selected: None,
            total: 0,
            request_delay_ms: 0,
            timeout_ms: 15_000,
            only_matches: false,
            result_filter: String::new(),
            sort_column: None,
            sort_ascending: true,
            template_height: 200.0,
            results_height: 190.0,
            detail_height: 190.0,
            split_ratio: 0.5,
            tabs: vec!["1".into()],
            active_tab: 0,
            show_getting_started: false,
            hide_getting_started_forever: false,
            side_panel_tab: 0,
            side_panel_collapsed: false,
            side_panel_left: false,
            main_split_ratio: 0.56,
            left_sub_tab: 0,
            template_view_mode: 0,
            result_msg_tab: 0,
            result_msg_format: 0,
            resource_pool_mode: 0,
            resource_pool_name: "Default resource pool".into(),
            delay_mode: 0,
            delay_increment_ms: 100,
            auto_throttle: true,
            auto_throttle_codes: "429, 503".into(),
            save_attack_to_project: false,
            update_content_length: true,
            set_connection_close: false,
            retries_on_failure: 3,
            pause_before_retry_ms: 2_000,
            store_requests_responses: true,
            make_baseline_request: true,
            dos_mode: false,
            store_full_payloads: true,
            auto_pause_enabled: false,
            auto_pause_when_appears: true,
            auto_pause_expressions: "rate limit\naccount locked".into(),
            auto_pause_regex: false,
            auto_pause_case_sensitive: false,
            grep_match_enabled: true,
            grep_match_expressions:
                "error\nexception\nillegal\ninvalid\nfail\nstack\nsql\nsyntax".into(),
            grep_match_regex: false,
            grep_match_case_sensitive: false,
            grep_match_exclude_headers: false,
            grep_extract_enabled: false,
            grep_extract_pattern: "<title>(.*?)</title>".into(),
            grep_extract_max_len: 100,
            grep_payloads_enabled: false,
            grep_payloads_case_sensitive: false,
            grep_payloads_exclude_headers: true,
            grep_payloads_pre_urlencoded: false,
            follow_redirections: 0,
            process_cookies_in_redirections: false,
            http1_connection_reuse: true,
            override_http2: false,
            default_to_http2: true,
            auto_payload_append: false,
            new_tab_config_mode: 0,
            close_running_action: 0,
            close_finished_action: 0,
            selection: None,
            result_positions: std::collections::HashMap::new(),
        }
    }
}

impl IntruderPanel {
    pub fn record(
        &mut self,
        index: usize,
        status: u16,
        length: usize,
        matched: bool,
        error: Option<String>,
    ) {
        self.record_exchange(Result {
            index,
            status,
            length,
            matched,
            error,
            ..Default::default()
        });
    }

    pub fn record_exchange(&mut self, mut result: Result) {
        if !result.response.is_empty() {
            let search_target = if self.grep_match_exclude_headers {
                crate::analysis::split_message(&result.response).1
            } else {
                result.response.as_str()
            };
            if self.grep_match_enabled {
                let hay = if self.grep_match_case_sensitive {
                    search_target.to_string()
                } else {
                    search_target.to_lowercase()
                };
                for expr in self
                    .grep_match_expressions
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                {
                    let matched_expr = if self.grep_match_regex {
                        regex::RegexBuilder::new(expr)
                            .case_insensitive(!self.grep_match_case_sensitive)
                            .build()
                            .is_ok_and(|re| re.is_match(search_target))
                    } else {
                        let needle = if self.grep_match_case_sensitive {
                            expr.to_string()
                        } else {
                            expr.to_lowercase()
                        };
                        hay.contains(&needle)
                    };
                    if matched_expr {
                        result.matched = true;
                        let tag = format!("[Grep: {expr}]");
                        if !result.comment.contains(&tag) {
                            if !result.comment.is_empty() {
                                result.comment.push(' ');
                            }
                            result.comment.push_str(&tag);
                        }
                        break;
                    }
                }
            }
            if self.grep_extract_enabled && !self.grep_extract_pattern.trim().is_empty() {
                if let Ok(re) = regex::Regex::new(self.grep_extract_pattern.trim()) {
                    if let Some(caps) = re.captures(&result.response) {
                        let val = caps
                            .get(1)
                            .or_else(|| caps.get(0))
                            .map(|m| m.as_str())
                            .unwrap_or_default();
                        let truncated: String =
                            val.chars().take(self.grep_extract_max_len.max(1)).collect();
                        let tag = format!("[Extract: {truncated}]");
                        if !result.comment.contains(&tag) {
                            if !result.comment.is_empty() {
                                result.comment.push(' ');
                            }
                            result.comment.push_str(&tag);
                        }
                    }
                }
            }
        }
        if self.auto_pause_enabled && !result.response.is_empty() {
            let check_text = if self.auto_pause_case_sensitive {
                result.response.clone()
            } else {
                result.response.to_lowercase()
            };
            let hit = self
                .auto_pause_expressions
                .lines()
                .filter(|l| !l.trim().is_empty())
                .any(|expr| {
                    let needle = if self.auto_pause_case_sensitive {
                        expr.trim().to_string()
                    } else {
                        expr.trim().to_lowercase()
                    };
                    check_text.contains(&needle)
                });
            let should_pause = if self.auto_pause_when_appears {
                hit
            } else {
                !hit
            };
            if should_pause {
                if let Some(ctrl) = &self.control {
                    ctrl.pause();
                }
            }
        }
        let existing = self
            .result_positions
            .get(&result.index)
            .copied()
            .filter(|position| {
                self.results
                    .get(*position)
                    .is_some_and(|row| row.index == result.index)
            });
        if let Some(position) = existing {
            self.matches = self
                .matches
                .saturating_sub(usize::from(self.results[position].matched));
            self.matches += usize::from(result.matched);
            self.results[position] = result;
        } else {
            self.matches += usize::from(result.matched);
            self.result_positions
                .insert(result.index, self.results.len());
            self.results.push(result);
        }
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
        self.result_positions.clear();
        self.matches = 0;
        self.selected = None;
        self.total = 0;
    }

    pub fn estimated_payload_and_request_count(&self) -> (usize, usize) {
        let pos_count = intruder::position_count(&self.template).unwrap_or(0);
        let p0 = self
            .payload_sets
            .first()
            .and_then(|s| s.generate(50_000).ok())
            .map(|v| v.len())
            .unwrap_or(0);
        let req_count = match self.attack_type {
            AttackType::Sniper => p0.saturating_mul(pos_count.max(1)),
            AttackType::BatteringRam => p0,
            AttackType::Pitchfork => self
                .payload_sets
                .iter()
                .filter_map(|s| s.generate(50_000).ok().map(|v| v.len()))
                .min()
                .unwrap_or(0),
            AttackType::ClusterBomb => self
                .payload_sets
                .iter()
                .filter_map(|s| s.generate(50_000).ok().map(|v| v.len()))
                .fold(1usize, |acc, n| acc.saturating_mul(n)),
        };
        (p0, req_count)
    }
}

/// Renders the exact 50/50 split Getting Started screen from `/tmp/ref_Intruder_s.png`,
/// using the exact SVG coordinates from `resources/Media/svg/light/intruder.svg`
/// and `resources/Media/svg/light/intruder-illustration.svg`.
fn draw_getting_started(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let avail = ui.available_size();
    let left_bg = if theme.dark {
        Color32::from_rgb(0x23, 0x27, 0x2D)
    } else {
        Color32::from_rgb(0xEA, 0xEE, 0xF2)
    };
    let right_bg = if theme.dark {
        Color32::from_rgb(0x1E, 0x20, 0x24)
    } else {
        Color32::from_rgb(0xFA, 0xFA, 0xFA)
    };

    ui.spacing_mut().item_spacing.x = 0.0;
    ui.columns(2, |cols| {
        // LEFT 50%: "To get started, send a request to Intruder from anywhere in Gulp." + `intruder-illustration.svg`
        egui::Frame::new()
            .fill(left_bg)
            .inner_margin(egui::Margin::same(0))
            .show(&mut cols[0], |ui| {
                let col_w = ui.available_width();
                ui.set_min_size(Vec2::new(col_w, avail.y));
                let top_pad = ((avail.y - 310.0) * 0.45).max(36.0);
                let left_pad = ((col_w - 321.0) * 0.5).max(24.0);
                ui.add_space(top_pad);
                ui.horizontal(|ui| {
                    ui.add_space(left_pad);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(
                                "To get started, send a request to Intruder\nfrom anywhere in Gulp.",
                            )
                            .size(18.0)
                            .strong()
                            .color(theme.color("ui.text.heading")),
                        );
                        ui.add_space(22.0);
                        paint_intruder_onboarding_illustration(ui, &theme);
                    });
                });
            });

        // RIGHT 50%: Top-right `✕`, `intruder.svg` rocket icon, "Intruder", description, "Learn more", "Don't show this again"
        egui::Frame::new()
            .fill(right_bg)
            .inner_margin(egui::Margin::symmetric(20, 14))
            .show(&mut cols[1], |ui| {
                let col_w = ui.available_width();
                ui.set_min_size(Vec2::new(col_w.max(160.0), (avail.y - 28.0).max(240.0)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    let (x_rect, x_resp) =
                        ui.allocate_exact_size(Vec2::new(20.0, 20.0), egui::Sense::click());
                    let xp = ui.painter_at(x_rect);
                    let xc = theme.color("ui.text.heading");
                    xp.line_segment(
                        [
                            pos2(x_rect.min.x + 5.0, x_rect.min.y + 5.0),
                            pos2(x_rect.max.x - 5.0, x_rect.max.y - 5.0),
                        ],
                        Stroke::new(1.5_f32, xc),
                    );
                    xp.line_segment(
                        [
                            pos2(x_rect.max.x - 5.0, x_rect.min.y + 5.0),
                            pos2(x_rect.min.x + 5.0, x_rect.max.y - 5.0),
                        ],
                        Stroke::new(1.5_f32, xc),
                    );
                    if x_resp.on_hover_text("Close onboarding").clicked() {
                        if app.panels.intruder.tabs.is_empty() {
                            app.panels.intruder.tabs.push("1".into());
                        }
                        app.panels.intruder.show_getting_started = false;
                    }
                });

                let right_top_pad = ((avail.y - 280.0) * 0.42).max(32.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(right_top_pad);
                    draw_rocket_illustration(ui);
                    ui.add_space(18.0);
                    ui.label(
                        RichText::new("Intruder")
                            .size(16.0)
                            .strong()
                            .color(theme.color("ui.text.heading")),
                    );
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(
                            "Configure automated attacks that send the same request many\ntimes, substituting specific values with predetermined\npayloads each time.",
                        )
                        .size(12.0)
                        .color(theme.color("ui.text.body")),
                    );
                    ui.add_space(20.0);
                    let learn_bg = if theme.dark {
                        Color32::from_rgb(0x32, 0x36, 0x3E)
                    } else {
                        Color32::from_rgb(0xEA, 0xEA, 0xEA)
                    };
                    let learn_border = if theme.dark {
                        Color32::from_rgb(0x48, 0x4D, 0x56)
                    } else {
                        Color32::from_rgb(0xD8, 0xD8, 0xD8)
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Learn more")
                                    .size(12.0)
                                    .strong()
                                    .color(theme.color("ui.text.heading")),
                            )
                            .fill(learn_bg)
                            .stroke(Stroke::new(1.0_f32, learn_border))
                            .corner_radius(4.0)
                            .min_size(Vec2::new(108.0, 28.0)),
                        )
                        .clicked()
                    {
                        app.status =
                            "Intruder documentation: Configure positions (§), select an attack type, load payloads, and click Start attack.".into();
                    }
                    ui.add_space(18.0);
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Don't show this again")
                                    .color(Color32::from_rgb(0xC8, 0x5A, 0x28))
                                    .size(12.0),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        app.panels.intruder.hide_getting_started_forever = true;
                        app.panels.intruder.show_getting_started = false;
                        if app.panels.intruder.tabs.is_empty() {
                            app.panels.intruder.tabs.push("1".into());
                        }
                    }
                });
            });
    });
}

/// Paints the exact `resources/Media/svg/light/intruder.svg` (`90 x 63` viewBox) rocket icon.
fn draw_rocket_illustration(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(90.0, 63.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let map = |pts: &[(f32, f32)]| -> Vec<egui::Pos2> {
        pts.iter().map(|(x, y)| pos2(o.x + *x, o.y + *y)).collect()
    };

    let speed_col = Color32::from_rgb(0xE6, 0xE6, 0xE6);
    let light_blue = Color32::from_rgb(0x92, 0xB1, 0xCE);
    let dark_blue = Color32::from_rgb(0x26, 0x64, 0x9D);

    // 4 diagonal speed lines (`#E6E6E6`, stroke width 3.0)
    for ((x1, y1), (x2, y2)) in [
        ((11.0f32, 46.0f32), (26.0f32, 59.0f32)),
        ((33.0, 49.0), (43.0, 58.0)),
        ((55.0, 3.0), (64.0, 10.0)),
        ((65.0, 24.0), (80.0, 36.0)),
    ] {
        p.line_segment(
            [pos2(o.x + x1, o.y + y1), pos2(o.x + x2, o.y + y2)],
            Stroke::new(3.0_f32, speed_col),
        );
    }

    // Outer exhaust flame (`#B86633` 30% opacity) + inner flame (`#FF7648`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (15.46, 7.93),
            (23.50, 7.80),
            (30.35, 14.96),
            (25.03, 21.33),
            (17.50, 17.80),
        ]),
        Color32::from_rgba_unmultiplied(0xB8, 0x66, 0x33, 77),
        Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[
            (20.70, 12.31),
            (25.80, 11.90),
            (29.29, 16.24),
            (26.09, 20.06),
            (21.40, 17.80),
        ]),
        Color32::from_rgb(0xFF, 0x76, 0x48),
        Stroke::NONE,
    ));

    // Upper-right fin + Lower-left fin + Lower-right nose cone (`#92B1CE`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (41.07, 11.50),
            (44.35, 10.81),
            (50.83, 17.15),
            (50.85, 27.12),
            (41.08, 18.80),
        ]),
        light_blue,
        Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[
            (23.20, 33.80),
            (30.50, 31.35),
            (40.63, 39.35),
            (30.20, 41.10),
        ]),
        light_blue,
        Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[
            (61.82, 35.30),
            (67.20, 41.80),
            (70.50, 51.50),
            (68.11, 54.36),
            (58.50, 53.00),
            (50.62, 48.69),
        ]),
        light_blue,
        Stroke::NONE,
    ));

    // Rocket fuselage (`#26649D`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (35.00, 16.50),
            (40.62, 17.58),
            (62.98, 36.27),
            (51.79, 49.66),
            (29.42, 30.97),
            (28.00, 25.50),
        ]),
        dark_blue,
        Stroke::NONE,
    ));

    // White lightning bolt (`#FFFFFF`) inside fuselage
    p.add(egui::Shape::line(
        map(&[
            (40.40, 28.80),
            (43.50, 31.80),
            (45.50, 30.20),
            (48.50, 35.60),
        ]),
        Stroke::new(2.0_f32, Color32::WHITE),
    ));
}

/// Paints the exact `resources/Media/svg/light/intruder-illustration.svg` (`321 x 215` viewBox).
fn paint_intruder_onboarding_illustration(ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(321.0, 215.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let r = |x: f32, y: f32, w: f32, h: f32| {
        egui::Rect::from_min_size(pos2(o.x + x, o.y + y), Vec2::new(w, h))
    };

    let top_card_bg = if theme.dark {
        Color32::from_rgb(0x2D, 0x31, 0x38)
    } else {
        Color32::from_rgb(0xFB, 0xFC, 0xFD)
    };
    let req_card_bg = if theme.dark {
        Color32::from_rgb(0x2B, 0x2F, 0x36)
    } else {
        Color32::WHITE
    };
    let resp_card_bg = if theme.dark {
        Color32::from_rgb(0x27, 0x2B, 0x31)
    } else {
        Color32::from_rgb(0xF5, 0xF8, 0xFB)
    };
    let bar_col = if theme.dark {
        Color32::from_rgb(0x43, 0x48, 0x52)
    } else {
        Color32::from_rgb(0xE6, 0xE6, 0xE6)
    };
    let menu_bg = if theme.dark {
        Color32::from_rgb(0x36, 0x3B, 0x44)
    } else {
        Color32::from_rgb(0xF8, 0xF8, 0xF8)
    };
    let menu_bar_col = if theme.dark {
        Color32::from_rgb(0x52, 0x58, 0x64)
    } else {
        Color32::from_rgb(0xD5, 0xD5, 0xD5)
    };
    let muted_txt = Color32::from_rgba_unmultiplied(0x2B, 0x2B, 0x2B, 140);

    // 1. Top table card (`320.3 x 70.5`) + 4 rounded gray bars
    p.rect_filled(r(0.7, 0.0, 320.3, 70.5), 2.0, top_card_bg);
    for y in [11.5f32, 24.3, 37.2, 50.0] {
        p.rect_filled(r(10.9, y, 298.5, 6.4), 3.2, bar_col);
    }

    // 2. Bottom-left `Request` card (`157.6 x 116.6`) + Bottom-right `Response` card
    p.rect_filled(r(0.7, 76.9, 157.6, 116.6), 2.0, req_card_bg);
    p.rect_filled(r(164.7, 76.9, 156.3, 116.6), 2.0, resp_card_bg);
    p.text(
        pos2(o.x + 8.0, o.y + 84.0),
        egui::Align2::LEFT_TOP,
        "Request",
        egui::FontId::proportional(11.0),
        if theme.dark {
            Color32::from_gray(160)
        } else {
            muted_txt
        },
    );
    p.text(
        pos2(o.x + 172.0, o.y + 84.0),
        egui::Align2::LEFT_TOP,
        "Response",
        egui::FontId::proportional(11.0),
        if theme.dark {
            Color32::from_gray(160)
        } else {
            muted_txt
        },
    );

    // 3. Pointer cursor arrow + "Right-click"
    let cursor_col = if theme.dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x16, 0x16, 0x16)
    };
    p.add(egui::Shape::convex_polygon(
        vec![
            pos2(o.x + 33.7, o.y + 102.0),
            pos2(o.x + 43.3, o.y + 107.1),
            pos2(o.x + 39.2, o.y + 108.1),
            pos2(o.x + 36.7, o.y + 112.1),
        ],
        cursor_col,
        Stroke::NONE,
    ));
    p.line_segment(
        [pos2(o.x + 38.4, o.y + 107.8), pos2(o.x + 41.8, o.y + 112.4)],
        Stroke::new(1.8_f32, cursor_col),
    );
    p.text(
        pos2(o.x + 51.5, o.y + 102.5),
        egui::Align2::LEFT_TOP,
        "Right-click",
        egui::FontId::proportional(10.5),
        cursor_col,
    );

    // 4. Context menu popup card (`92.2 x 90.9` at `x = 48.3, y = 123.9`)
    p.rect_filled(
        r(50.3, 125.9, 92.2, 90.9),
        2.0,
        Color32::from_rgba_unmultiplied(0, 0, 0, 18),
    );
    p.rect_filled(r(48.3, 123.9, 92.2, 90.9), 2.0, menu_bg);
    for (y, w) in [(131.8f32, 76.4f32), (141.2, 68.2), (150.6, 54.1)] {
        p.rect_filled(r(56.3, y, w, 5.8), 2.9, menu_bar_col);
    }
    // Blue `#26659E` highlight row with "Send to Intruder"
    p.rect_filled(
        r(48.3, 159.7, 92.2, 19.2),
        0.0,
        Color32::from_rgb(0x26, 0x65, 0x9E),
    );
    p.text(
        pos2(o.x + 55.0, o.y + 169.3),
        egui::Align2::LEFT_CENTER,
        "Send to Intruder",
        egui::FontId::proportional(9.8),
        Color32::WHITE,
    );
    for (y, w) in [(183.0f32, 55.8f32), (192.4, 68.2), (201.8, 54.1)] {
        p.rect_filled(r(56.3, y, w, 5.8), 2.9, menu_bar_col);
    }

    // 5. Curved dashed arc from `(99, 108)` around `(194, 138)` to `(143, 169)`
    let arc_pts = [
        (104.0f32, 108.0f32),
        (148.0, 108.0),
        (175.0, 114.0),
        (190.0, 126.0),
        (194.0, 140.0),
        (188.0, 154.0),
        (172.0, 165.0),
        (143.0, 169.0),
    ];
    let dash_col = Color32::from_rgb(0xCC, 0xCC, 0xCC);
    for pair in arc_pts.windows(2) {
        let a = pos2(o.x + pair[0].0, o.y + pair[0].1);
        let b = pos2(o.x + pair[1].0, o.y + pair[1].1);
        let mid = pos2((a.x + b.x) * 0.5, (a.y + b.y) * 0.5);
        p.line_segment([a, mid], Stroke::new(1.0_f32, dash_col));
    }
    p.add(egui::Shape::convex_polygon(
        vec![
            pos2(o.x + 142.3, o.y + 169.4),
            pos2(o.x + 145.9, o.y + 167.3),
            pos2(o.x + 145.9, o.y + 171.5),
        ],
        dash_col,
        Stroke::NONE,
    ));
}

fn intruder_hex_dump(text: &str) -> String {
    let mut out = String::new();
    for (row, chunk) in text.as_bytes().chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", row * 16));
        for idx in 0..16 {
            if let Some(b) = chunk.get(idx) {
                out.push_str(&format!("{b:02x} "));
            } else {
                out.push_str("   ");
            }
        }
        out.push(' ');
        for &b in chunk {
            out.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}

fn draw_positions_editor(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let border_col = theme.color("ui.border.1");

    // Row 1 inside Left Pane: `?` circle icon + wide `Sniper attack ⌄` dropdown + orange `▷ Start attack` button (`intruder-enumerating-positions-940.png`)
    ui.horizontal_wrapped(|ui| {
        let (q_rect, q_resp) = ui.allocate_exact_size(Vec2::new(20.0, 24.0), egui::Sense::click());
        let qp = ui.painter_at(q_rect);
        let qc = theme.color("ui.icon.default");
        qp.circle_stroke(q_rect.center(), 8.0, Stroke::new(1.3_f32, qc));
        qp.text(
            q_rect.center(),
            egui::Align2::CENTER_CENTER,
            "?",
            egui::FontId::proportional(11.5),
            qc,
        );
        if q_resp
            .on_hover_text("Attack types help: Sniper, Battering ram, Pitchfork, Cluster bomb")
            .clicked()
        {
            app.panels.intruder.show_getting_started = true;
        }

        let combo_w = (ui.available_width() - 148.0).max(150.0);
        egui::ComboBox::from_id_salt("intruder-attack-type")
            .selected_text(app.panels.intruder.attack_type.title())
            .width(combo_w)
            .show_ui(ui, |ui| {
                let row_w = combo_w.max(260.0);
                ui.set_min_width(row_w);
                ui.spacing_mut().item_spacing.y = 3.0;
                for mode in AttackType::ALL {
                    ui.add_enabled_ui(!app.panels.intruder.running, |ui| {
                        let selected = app.panels.intruder.attack_type == mode;
                        let (row_rect, resp) =
                            ui.allocate_exact_size(Vec2::new(row_w, 46.0), egui::Sense::click());
                        resp.widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::WidgetType::SelectableLabel,
                                selected,
                                mode.title(),
                            )
                        });
                        let hovered = resp.hovered();
                        if hovered && !app.panels.intruder.running {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        let row_bg = match (theme.dark, selected, hovered) {
                            (true, true, true) => Color32::from_rgb(0x35, 0x63, 0x94),
                            (true, true, false) => Color32::from_rgb(0x2C, 0x51, 0x75),
                            (true, false, true) => Color32::from_rgb(0x3D, 0x42, 0x4B),
                            (false, true, true) => Color32::from_rgb(0xB8, 0xD0, 0xEC),
                            (false, true, false) => Color32::from_rgb(0xC9, 0xDC, 0xF2),
                            (false, false, true) => Color32::from_rgb(0xE6, 0xEE, 0xF8),
                            (_, false, false) => Color32::TRANSPARENT,
                        };
                        if row_bg != Color32::TRANSPARENT {
                            ui.painter().rect_filled(row_rect, 4.0, row_bg);
                        }
                        if selected || hovered {
                            let border_col = if theme.dark {
                                Color32::from_rgb(0x53, 0x84, 0xB2)
                            } else {
                                Color32::from_rgb(0x9F, 0xBB, 0xD4)
                            };
                            ui.painter().rect_stroke(
                                row_rect,
                                4.0,
                                Stroke::new(1.0, border_col),
                                egui::StrokeKind::Inside,
                            );
                        }
                        let title_col = if theme.dark {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(0x11, 0x11, 0x11)
                        };
                        let desc_col = if theme.dark {
                            if selected || hovered {
                                Color32::from_rgb(0xE6, 0xEC, 0xF5)
                            } else {
                                Color32::from_rgb(0xC5, 0xC7, 0xC8)
                            }
                        } else {
                            Color32::from_rgb(0x33, 0x33, 0x33)
                        };
                        ui.painter().text(
                            pos2(row_rect.min.x + 10.0, row_rect.min.y + 7.0),
                            egui::Align2::LEFT_TOP,
                            mode.title(),
                            egui::FontId::proportional(12.5),
                            title_col,
                        );
                        ui.painter().text(
                            pos2(row_rect.min.x + 10.4, row_rect.min.y + 7.0),
                            egui::Align2::LEFT_TOP,
                            mode.title(),
                            egui::FontId::proportional(12.5),
                            title_col,
                        );
                        ui.painter().text(
                            pos2(row_rect.min.x + 10.0, row_rect.min.y + 25.0),
                            egui::Align2::LEFT_TOP,
                            mode.description(),
                            egui::FontId::proportional(11.2),
                            desc_col,
                        );
                        if resp.clicked() {
                            app.panels.intruder.attack_type = mode;
                            ui.close();
                        }
                    });
                }
            });

        let can_start = !app.panels.intruder.running;
        ui.add_enabled_ui(can_start, |ui| {
            ui.spacing_mut().button_padding = Vec2::new(10.0, 4.0);
            let btn = egui::Button::new(
                RichText::new("    Start attack")
                    .color(Color32::WHITE)
                    .strong()
                    .size(12.5),
            )
            .fill(Color32::from_rgb(0xE0, 0x53, 0x20))
            .corner_radius(4.0)
            .min_size(Vec2::new(116.0, 26.0));
            let resp = ui.add(btn);
            resp.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, can_start, "Start attack")
            });
            // Draw white circle-play icon (`▷` inside circle) matching `getting-started-with-intruder-4-attack-type.png`
            let ic_center = pos2(resp.rect.left() + 15.0, resp.rect.center().y);
            ui.painter()
                .circle_stroke(ic_center, 6.2, Stroke::new(1.3_f32, Color32::WHITE));
            ui.painter().add(egui::Shape::convex_polygon(
                vec![
                    pos2(ic_center.x - 1.8, ic_center.y - 3.0),
                    pos2(ic_center.x + 3.0, ic_center.y),
                    pos2(ic_center.x - 1.8, ic_center.y + 3.0),
                ],
                Color32::WHITE,
                Stroke::NONE,
            ));
            if resp.clicked() {
                start(app);
            }
        });

        if app.panels.intruder.running {
            let paused = app
                .panels
                .intruder
                .control
                .as_ref()
                .is_some_and(|control| control.state() == AttackState::Paused);
            if ui
                .button(if paused {
                    "Resume attack"
                } else {
                    "Pause attack"
                })
                .clicked()
            {
                if let Some(control) = &app.panels.intruder.control {
                    if paused {
                        control.resume();
                    } else {
                        control.pause();
                    }
                }
                if let Some(id) = app.panels.intruder.task_id {
                    if paused {
                        let _ = app.workspace.tasks.resume(id);
                    } else {
                        let _ = app.workspace.tasks.pause(id);
                    }
                }
            }
            if ui.button("Cancel attack").clicked() {
                if let Some(control) = &app.panels.intruder.control {
                    control.cancel();
                }
            }
        }
    });
    ui.separator();

    // Row 2 inside Left Pane: `Target [ https://... ]  [✓] Update Host header to match target` (`intruder-enumerating-positions-940.png`)
    ui.horizontal_wrapped(|ui| {
        ui.label("Target");
        let target_w = (ui.available_width() - 258.0).max(120.0);
        ui.add_enabled(
            !app.panels.intruder.running,
            egui::TextEdit::singleline(&mut app.panels.intruder.host).desired_width(target_w),
        );
        ui.add_enabled_ui(!app.panels.intruder.running, |ui| {
            ui.checkbox(
                &mut app.panels.intruder.update_host,
                "Update Host header to match target",
            );
        });
    });
    ui.separator();

    // Sync any latest text selection ("block") from the Positions editor before handling Add § / Clear §
    if let Some((range, _)) = super::latest_selection_for("intruder-positions-edit") {
        app.panels.intruder.selection = Some(range);
    }

    // Row 3: Outlined `[ Add § ]  [ Clear § ]  [ Auto § ]` buttons (`getting-started-with-intruder-3-request-with-payloads.png`)
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().button_padding = Vec2::new(10.0, 3.0);
        let panel = &mut app.panels.intruder;
        let btn_bg = if theme.dark {
            Color32::from_rgb(0x2B, 0x2E, 0x36)
        } else {
            Color32::WHITE
        };
        let add_btn = egui::Button::new(RichText::new("Add §").size(12.0).strong())
            .fill(btn_bg)
            .stroke(Stroke::new(1.0_f32, border_col))
            .corner_radius(4.0)
            .min_size(Vec2::new(72.0, 26.0));
        if ui.add(add_btn).clicked() {
            if let Some(range) = panel.selection.take().filter(|r| r.start < r.end) {
                let start = panel
                    .template
                    .char_indices()
                    .nth(range.start)
                    .map(|(index, _)| index)
                    .unwrap_or(panel.template.len());
                let end = panel
                    .template
                    .char_indices()
                    .nth(range.end)
                    .map(|(index, _)| index)
                    .unwrap_or(panel.template.len());
                if start <= end && end <= panel.template.len() {
                    panel.template.insert(end, '§');
                    panel.template.insert(start, '§');
                }
            } else {
                panel.template.push_str("§§");
            }
        }
        let clear_btn = egui::Button::new(RichText::new("Clear §").size(12.0).strong())
            .fill(btn_bg)
            .stroke(Stroke::new(1.0_f32, border_col))
            .corner_radius(4.0)
            .min_size(Vec2::new(72.0, 26.0));
        if ui.add(clear_btn).clicked() {
            if let Some(range) = panel.selection.take().filter(|r| r.start < r.end) {
                let start = panel
                    .template
                    .char_indices()
                    .nth(range.start)
                    .map(|(index, _)| index)
                    .unwrap_or(0);
                let end = panel
                    .template
                    .char_indices()
                    .nth(range.end)
                    .map(|(index, _)| index)
                    .unwrap_or(panel.template.len());
                if start < end && end <= panel.template.len() && panel.template[start..end].contains('§') {
                    let cleaned = panel.template[start..end].replace('§', "");
                    panel.template.replace_range(start..end, &cleaned);
                } else {
                    panel.template = panel.template.replace('§', "");
                }
            } else {
                panel.template = panel.template.replace('§', "");
            }
        }
        let auto_btn = egui::Button::new(RichText::new("Auto §").size(12.0).strong())
            .fill(btn_bg)
            .stroke(Stroke::new(1.0_f32, border_col))
            .corner_radius(4.0)
            .min_size(Vec2::new(72.0, 26.0));
        if ui.add(auto_btn).clicked() {
            panel.template = intruder::auto_mark_positions(&panel.template);
        }
        ui.separator();
        for (idx, lbl) in ["Pretty", "Raw", "Hex"].iter().enumerate() {
            ui.selectable_value(&mut panel.template_view_mode, idx, *lbl);
        }
        ui.separator();
        ui.label(
            intruder::position_count(&panel.template)
                .map(|count| format!("{count} payload position(s)"))
                .unwrap_or_else(|error| error),
        );
    });
    ui.separator();

    // Row 4: Line-numbered HTTP request editor with mint-green `#CFE8DF` / `#A31515` `§...§` highlights (`intruder-enumerating-positions-940.png`)
    let has_results_or_running =
        app.panels.intruder.running || !app.panels.intruder.results.is_empty();
    let tmpl_h = if has_results_or_running {
        app.panels
            .intruder
            .template_height
            .min((ui.available_height() * 0.36).max(120.0))
    } else {
        (ui.available_height() - 8.0).max(200.0)
    };
    let host_clone = app.panels.intruder.host.clone();
    let mode = app.panels.intruder.template_view_mode;
    let resp = if mode == 2 {
        let tmpl_clone = app.panels.intruder.template.clone();
        super::gulp_numbered_message_view(
            ui,
            &theme,
            "intruder-template-hex",
            tmpl_h,
            &tmpl_clone,
            2,
            false,
        )
    } else {
        let (r, _) = super::gulp_numbered_message_editor_wrapped(
            ui,
            &theme,
            "intruder-positions-edit",
            tmpl_h,
            &mut app.panels.intruder.template,
            mode,
            true,
        );
        if let Some((range, _)) = super::latest_selection_for("intruder-positions-edit") {
            app.panels.intruder.selection = Some(range);
        }
        r
    };
    let tmpl_clone = app.panels.intruder.template.clone();
    super::attach_message_context_menu(app, &resp, &host_clone, &tmpl_clone, "");
    if has_results_or_running {
        super::horizontal_resize_handle(
            ui,
            &theme,
            "intruder-template-resize",
            &mut app.panels.intruder.template_height,
            120.0,
            520.0,
            240.0,
        );
    }
}

fn draw_results_area(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    // Results header & filter bar (matching `getting-started-with-intruder-6-selected-entry-request.png`)
    ui.horizontal_wrapped(|ui| {
        super::scanner::paint_launcher_icon(
            ui,
            Vec2::new(15.0, 15.0),
            theme.color("palette.secondary.core"),
            super::scanner::LauncherIcon::SpeedImpact,
        );
        ui.label(
            RichText::new(format!(
                "{}. Intruder attack of {}",
                app.panels.intruder.active_tab + 1,
                app.panels.intruder.host
            ))
            .strong(),
        );
        ui.separator();
        ui.label(format!(
            "{} / {} completed · {} matches",
            app.panels.intruder.results.len(),
            app.panels.intruder.total,
            app.panels.intruder.matches
        ));
        ui.checkbox(&mut app.panels.intruder.only_matches, "Matches only");
        ui.add(
            egui::TextEdit::singleline(&mut app.panels.intruder.result_filter)
                .hint_text("Intruder attack results filter: Showing all items")
                .desired_width(240.0),
        );
        ui.menu_button("Attack", |ui| {
            if ui.button("Pause attack").clicked() {
                if let Some(ctrl) = &app.panels.intruder.control {
                    ctrl.pause();
                }
                ui.close();
            }
            if ui.button("Resume attack").clicked() {
                if let Some(ctrl) = &app.panels.intruder.control {
                    ctrl.resume();
                }
                ui.close();
            }
            if ui.button("Cancel attack").clicked() {
                if let Some(ctrl) = &app.panels.intruder.control {
                    ctrl.cancel();
                }
                ui.close();
            }
            if ui.button("Clear results").clicked() {
                app.panels.intruder.clear_results();
                ui.close();
            }
        });
        ui.menu_button("Save", |ui| {
            if ui.button("Save attack to project file").clicked() {
                app.panels.intruder.save_attack_to_project = true;
                app.status = "Marked Intruder attack to save in project file".into();
                ui.close();
            }
            if ui.button("Export results table (TSV) to clipboard").clicked() {
                let mut tsv =
                    String::from("Request\tPayload\tStatus\tResponse received (ms)\tLength\tComment\n");
                for r in &app.panels.intruder.results {
                    tsv.push_str(&format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\n",
                        r.index,
                        r.payloads.join(" | "),
                        r.status,
                        r.elapsed_ms,
                        r.length,
                        r.comment
                    ));
                }
                ui.ctx().copy_text(tsv);
                app.status = "Copied Intruder results TSV to clipboard".into();
                ui.close();
            }
        });
    });

    let filter = app.panels.intruder.result_filter.to_lowercase();
    let only_matches = app.panels.intruder.only_matches;
    let mut rows: Vec<Result> = app
        .panels
        .intruder
        .results
        .iter()
        .filter(|row| {
            (!only_matches || row.matched)
                && (filter.is_empty()
                    || format!(
                        "{} {} {} {}",
                        row.payloads.join(" "),
                        row.status,
                        row.error.as_deref().unwrap_or(""),
                        row.comment
                    )
                    .to_lowercase()
                    .contains(&filter))
        })
        .cloned()
        .collect();

    if let Some(col) = app.panels.intruder.sort_column {
        let asc = app.panels.intruder.sort_ascending;
        rows.sort_by(|a, b| {
            let ord = match col {
                0 => a.index.cmp(&b.index),
                1 => a.payloads.join(" ").cmp(&b.payloads.join(" ")),
                2 => a.status.cmp(&b.status),
                3 => a.length.cmp(&b.length),
                4 => a.elapsed_ms.cmp(&b.elapsed_ms),
                5 => a.error.cmp(&b.error),
                6 => a.timed_out.cmp(&b.timed_out),
                _ => a.matched.cmp(&b.matched),
            };
            if asc { ord } else { ord.reverse() }
        });
    } else {
        rows.sort_by_key(|row| row.index);
    }

    if app.panels.intruder.selected.is_none()
        || !rows
            .iter()
            .any(|r| Some(r.index) == app.panels.intruder.selected)
    {
        app.panels.intruder.selected = rows.first().map(|r| r.index);
    }

    // 8 Gulpsuite Professional columns (`Request`, `Payload`, `Status`, `Length`, `Time (ms)`, `Error`, `Timeout`, `Result`)
    let results_h = app.panels.intruder.results_height;
    egui::ScrollArea::both()
        .id_salt("intruder-results")
        .max_height(results_h)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("intruder-results-grid")
                .num_columns(8)
                .min_col_width(64.0)
                .striped(true)
                .show(ui, |ui| {
                    for (col_idx, name) in [
                        "Request",
                        "Payload",
                        "Status",
                        "Length",
                        "Time (ms)",
                        "Error",
                        "Timeout",
                        "Result",
                    ]
                    .iter()
                    .enumerate()
                    {
                        let active = app.panels.intruder.sort_column == Some(col_idx);
                        let label_text = if active {
                            if app.panels.intruder.sort_ascending {
                                format!("{name} ▲")
                            } else {
                                format!("{name} ▼")
                            }
                        } else {
                            (*name).to_string()
                        };
                        if ui
                            .selectable_label(active, egui::RichText::new(label_text).strong())
                            .clicked()
                        {
                            if app.panels.intruder.sort_column == Some(col_idx) {
                                if app.panels.intruder.sort_ascending {
                                    app.panels.intruder.sort_ascending = false;
                                } else {
                                    app.panels.intruder.sort_column = None;
                                    app.panels.intruder.sort_ascending = true;
                                }
                            } else {
                                app.panels.intruder.sort_column = Some(col_idx);
                                app.panels.intruder.sort_ascending = true;
                            }
                        }
                    }
                    ui.end_row();

                    for row in rows.iter().take(500) {
                        let is_sel = app.panels.intruder.selected == Some(row.index);
                        let host_url = row
                            .target
                            .as_ref()
                            .map(|t| {
                                format!(
                                    "{}://{}",
                                    if t.secure { "https" } else { "http" },
                                    t.authority()
                                )
                            })
                            .unwrap_or_else(|| app.panels.intruder.host.clone());
                        ui.push_id(("intruder-res-row", row.index), |ui| {
                            let c0 = ui.selectable_label(is_sel, row.index.to_string());
                            let c1 = ui.selectable_label(is_sel, row.payloads.join(" | "));
                            let c2 = ui.selectable_label(is_sel, row.status.to_string());
                            let c3 = ui.selectable_label(is_sel, row.length.to_string());
                            let c4 = ui.selectable_label(is_sel, row.elapsed_ms.to_string());
                            let c5 = ui.selectable_label(
                                is_sel,
                                if row.error.is_some() { "✓" } else { "" },
                            );
                            let c6 =
                                ui.selectable_label(is_sel, if row.timed_out { "✓" } else { "" });
                            let c7 = ui.selectable_label(
                                is_sel,
                                row.error.as_deref().unwrap_or(if row.matched {
                                    "match"
                                } else {
                                    &row.comment
                                }),
                            );
                            for cell in [&c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7] {
                                if cell.clicked() || cell.secondary_clicked() {
                                    app.panels.intruder.selected = Some(row.index);
                                }
                                super::attach_message_context_menu(
                                    app,
                                    cell,
                                    &host_url,
                                    &row.request,
                                    &row.response,
                                );
                            }
                        });
                        ui.end_row();
                    }
                });
        });

    super::horizontal_resize_handle(
        ui,
        &theme,
        "intruder-results-resize",
        &mut app.panels.intruder.results_height,
        100.0,
        520.0,
        190.0,
    );

    if let Some(result) = app
        .panels
        .intruder
        .results
        .iter()
        .find(|row| Some(row.index) == app.panels.intruder.selected)
        .cloned()
    {
        ui.horizontal_wrapped(|ui| {
            for (idx, lbl) in ["Request & Response", "Request", "Response"]
                .iter()
                .enumerate()
            {
                ui.selectable_value(&mut app.panels.intruder.result_msg_tab, idx, *lbl);
            }
            ui.separator();
            for (idx, lbl) in ["Pretty", "Raw", "Hex"].iter().enumerate() {
                ui.selectable_value(&mut app.panels.intruder.result_msg_format, idx, *lbl);
            }
            ui.separator();
            if ui
                .add_enabled(
                    !result.request.is_empty(),
                    egui::Button::new("Send result to Repeater"),
                )
                .clicked()
            {
                let host = result
                    .target
                    .as_ref()
                    .map(|target| {
                        format!(
                            "{}://{}",
                            if target.secure { "https" } else { "http" },
                            target.authority()
                        )
                    })
                    .unwrap_or_else(|| app.panels.intruder.host.clone());
                let clean_req = result.request.replace('§', "");
                app.panels.repeater.open(&host, &clean_req);
                app.tool = crate::ui::app::REPEATER;
                app.view = 0;
            }
            if result.response_truncated {
                ui.label(format!(
                    "Response capture truncated; original length: {} bytes",
                    result.length
                ));
            }
        });
        let target_url = result
            .target
            .as_ref()
            .map(|t| {
                format!(
                    "{}://{}",
                    if t.secure { "https" } else { "http" },
                    t.authority()
                )
            })
            .unwrap_or_else(|| app.panels.intruder.host.clone());
        let bg = theme.color("ui.editor.message.background");
        let detail_h = app.panels.intruder.detail_height;
        let fmt_mode = app.panels.intruder.result_msg_format;
        let req_text = if fmt_mode == 2 {
            intruder_hex_dump(&result.request)
        } else {
            result.request.clone()
        };
        let resp_text = if fmt_mode == 2 {
            intruder_hex_dump(&result.response)
        } else {
            result.response.clone()
        };
        let mut ratio = app.panels.intruder.split_ratio;
        super::vertical_split(
            ui,
            &theme,
            "intruder-res-split",
            &mut ratio,
            detail_h,
            |side, ui| {
                if side == 0 {
                    ui.label("Request");
                    let r_req = crate::ui::highlight::show_message_in(
                        ui,
                        "intruder-res-req",
                        detail_h - 24.0,
                        &req_text,
                        &theme,
                        bg,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r_req,
                        &target_url,
                        &result.request,
                        &result.response,
                    );
                } else {
                    ui.label("Response");
                    let r_resp = crate::ui::highlight::show_message_in(
                        ui,
                        "intruder-res-resp",
                        detail_h - 24.0,
                        &resp_text,
                        &theme,
                        bg,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r_resp,
                        &target_url,
                        &result.request,
                        &result.response,
                    );
                }
            },
        );
        app.panels.intruder.split_ratio = ratio;
        super::horizontal_resize_handle(
            ui,
            &theme,
            "intruder-detail-resize",
            &mut app.panels.intruder.detail_height,
            100.0,
            520.0,
            190.0,
        );
    } else if app.panels.intruder.results.is_empty() {
        muted(
            ui,
            &app.theme,
            "Configure payload positions and sets, then start the attack.",
        );
    }
}

/// Side panel 1: `Payloads` (matching `getting-started-with-intruder-5-usernames-in-list.png`,
/// `payload-types.html`, and `processing.html`).
fn draw_payloads_side_panel(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let border_col = theme.color("ui.border.1");
    let btn_bg = if theme.dark {
        Color32::from_rgb(0x2B, 0x2E, 0x36)
    } else {
        Color32::WHITE
    };
    ui.spacing_mut().button_padding = Vec2::new(10.0, 3.0);
    let (payload_count, request_count) = app.panels.intruder.estimated_payload_and_request_count();

    ui.horizontal(|ui| {
        let (hdr_rect, _) = ui.allocate_exact_size(Vec2::new(90.0, 24.0), egui::Sense::hover());
        ui.painter().text(
            pos2(hdr_rect.left(), hdr_rect.center().y),
            egui::Align2::LEFT_CENTER,
            "Payloads",
            egui::FontId::proportional(15.0),
            theme.color("ui.text.heading"),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            if ui.small_button("×").on_hover_text("Collapse side panel").clicked() {
                app.panels.intruder.side_panel_collapsed = true;
            }
            let gear_btn = ui
                .small_button("   ")
                .on_hover_text("Open Intruder settings");
            crate::ui::icons::paint(
                ui.painter(),
                egui::Rect::from_center_size(gear_btn.rect.center(), Vec2::splat(13.0)),
                theme.color("ui.icon.default"),
                crate::ui::icons::Glyph::Gear,
            );
            if gear_btn.clicked() {
                app.show_settings = true;
                app.settings_category = 3;
            }
            // Split-dock toggle pill (`[ |▤ | ▤| ]` in `getting-started-with-intruder-5-usernames-in-list.png`)
            let active_blue = Color32::from_rgb(0x1B, 0x56, 0x99);
            let pill_bg = if theme.dark {
                Color32::from_rgb(0x32, 0x36, 0x3E)
            } else {
                Color32::from_rgb(0xE0, 0xE0, 0xE0)
            };
            egui::Frame::new()
                .fill(pill_bg)
                .corner_radius(3.0)
                .inner_margin(egui::Margin::same(1))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    for (dock_left, lbl, tip) in [
                        (false, "▤|", "Dock side panel on the Right"),
                        (true, "|▤", "Dock side panel on the Left"),
                    ] {
                        let is_act = app.panels.intruder.side_panel_left == dock_left;
                        let fill = if is_act { active_blue } else { Color32::TRANSPARENT };
                        let fg = if is_act {
                            Color32::WHITE
                        } else {
                            theme.color("ui.text.body")
                        };
                        if ui
                            .add(
                                egui::Button::new(RichText::new(lbl).size(11.0).color(fg).strong())
                                    .fill(fill)
                                    .stroke(Stroke::NONE)
                                    .corner_radius(2.0)
                                    .min_size(Vec2::new(24.0, 20.0)),
                            )
                            .on_hover_text(tip)
                            .clicked()
                        {
                            app.panels.intruder.side_panel_left = dock_left;
                        }
                    }
                });
        });
    });
    ui.separator();

    let field_w = (ui.available_width() - 125.0).max(140.0);
    let first_kind = app
        .panels
        .intruder
        .payload_sets
        .first()
        .map(|s| s.kind.clone())
        .unwrap_or_else(|| "Simple list".into());

    egui::Grid::new("intruder-payload-counts-grid")
        .num_columns(2)
        .spacing([14.0, 6.0])
        .show(ui, |ui| {
            ui.label("Payload position:");
            egui::ComboBox::from_id_salt("intruder-payload-pos-select")
                .selected_text("All payload positions")
                .width(field_w)
                .show_ui(ui, |ui| {
                    let _ = ui.selectable_label(true, "All payload positions");
                });
            ui.end_row();
            ui.label("Payload type:");
            if let Some(first_set) = app.panels.intruder.payload_sets.first_mut() {
                let previous = first_set.kind.clone();
                egui::ComboBox::from_id_salt("payload-kind-top")
                    .selected_text(&first_set.kind)
                    .width(field_w)
                    .show_ui(ui, |ui| {
                        for kind in PAYLOAD_TYPES {
                            ui.selectable_value(&mut first_set.kind, kind.to_owned(), kind);
                        }
                    });
                if previous != first_set.kind {
                    if first_set.kind == "Dates & times" {
                        first_set.range_start = "2026-01-01".into();
                        first_set.range_end = "2026-01-10".into();
                    } else if first_set.kind == "Numbers" {
                        first_set.range_start = "1".into();
                        first_set.range_end = "10".into();
                    }
                }
            } else {
                ui.label(first_kind);
            }
            ui.end_row();
            ui.label("Payload count:");
            ui.label(RichText::new(payload_count.to_string()).strong());
            ui.end_row();
            ui.label("Request count:");
            ui.label(RichText::new(request_count.to_string()).strong());
            ui.end_row();
        });
    ui.separator();

    let panel = &mut app.panels.intruder;
    let mut remove = None;
    let sets_len = panel.payload_sets.len();
    for (index, set) in panel.payload_sets.iter_mut().enumerate() {
        ui.push_id(index, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("Payload set {}", index + 1)).strong());
                if index > 0 || sets_len > 1 {
                    ui.separator();
                    ui.label("Payload type:");
                    let previous = set.kind.clone();
                    egui::ComboBox::from_id_salt("payload-kind")
                        .selected_text(&set.kind)
                        .width(165.0)
                        .show_ui(ui, |ui| {
                            for kind in PAYLOAD_TYPES {
                                ui.selectable_value(&mut set.kind, kind.to_owned(), kind);
                            }
                        });
                    if previous != set.kind {
                        if set.kind == "Dates & times" {
                            set.range_start = "2026-01-01".into();
                            set.range_end = "2026-01-10".into();
                        } else if set.kind == "Numbers" {
                            set.range_start = "1".into();
                            set.range_end = "10".into();
                        }
                    }
                    if ui.button("Remove set").clicked() {
                        remove = Some(index);
                    }
                }
            });

            // 1. Payload configuration section (`getting-started-with-intruder-5-usernames-in-list.png`)
            egui::CollapsingHeader::new(RichText::new("Payload configuration").strong())
                .default_open(true)
                .show(ui, |ui| {
                    muted(ui, &theme, set.description());
                    ui.add_space(4.0);
                    match set.kind.as_str() {
                        "Numbers" => {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Type:");
                                ui.radio_value(&mut set.number_random, false, "Sequential");
                                ui.radio_value(&mut set.number_random, true, "Random");
                                ui.separator();
                                ui.label("Base:");
                                ui.radio_value(&mut set.number_hex, false, "Decimal");
                                ui.radio_value(&mut set.number_hex, true, "Hex");
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.label("From");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.range_start)
                                        .desired_width(70.0),
                                );
                                ui.label("To");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.range_end)
                                        .desired_width(70.0),
                                );
                                ui.label("Step");
                                ui.add(egui::DragValue::new(&mut set.range_step));
                                ui.label("Min integer digits");
                                ui.add(egui::DragValue::new(&mut set.min_int_digits).range(1..=16));
                            });
                        }
                        "Dates & times" => {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("From");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.range_start)
                                        .desired_width(110.0),
                                );
                                ui.label("To");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.range_end)
                                        .desired_width(110.0),
                                );
                                ui.label("Step");
                                ui.add(egui::DragValue::new(&mut set.range_step));
                            });
                            ui.label(
                                "UTC: YYYY-MM-DD (step in days) or YYYY-MM-DD HH:mm:ss (step in seconds)",
                            );
                        }
                        "Character blocks" => {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Base string:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.char_block_base)
                                        .desired_width(90.0),
                                );
                                ui.label("Min length:");
                                ui.add(
                                    egui::DragValue::new(&mut set.char_block_min).range(1..=10_000),
                                );
                                ui.label("Max length:");
                                ui.add(
                                    egui::DragValue::new(&mut set.char_block_max).range(1..=10_000),
                                );
                                ui.label("Step:");
                                ui.add(
                                    egui::DragValue::new(&mut set.char_block_step).range(1..=1_000),
                                );
                            });
                        }
                        "Brute forcer" => {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Character set:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.brute_charset)
                                        .desired_width(180.0),
                                );
                                ui.label("Min length:");
                                ui.add(egui::DragValue::new(&mut set.brute_min_len).range(1..=6));
                                ui.label("Max length:");
                                ui.add(egui::DragValue::new(&mut set.brute_max_len).range(1..=6));
                            });
                        }
                        "Null payloads" => {
                            ui.horizontal(|ui| {
                                ui.label("Generate");
                                ui.add(
                                    egui::DragValue::new(&mut set.null_count).range(1..=50_000),
                                );
                                ui.label("null payloads");
                            });
                        }
                        "Character frobber" => {
                            ui.horizontal(|ui| {
                                ui.label("Operate on string:");
                                ui.text_edit_singleline(&mut set.frobber_string);
                            });
                        }
                        "Bit flipper" => {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Operate on string:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.bit_flipper_string)
                                        .desired_width(120.0),
                                );
                                ui.checkbox(&mut set.bit_flipper_hex, "Treat as ASCII hex");
                            });
                        }
                        "Collaborator payloads" => {
                            ui.checkbox(
                                &mut set.collab_include_server,
                                "Include Collaborator server location",
                            );
                            ui.horizontal(|ui| {
                                ui.label("Count:");
                                ui.add(egui::DragValue::new(&mut set.null_count).range(1..=1_000));
                            });
                        }
                        _ => {
                            if set.kind == "Runtime file" {
                                ui.horizontal(|ui| {
                                    ui.label("File path:");
                                    ui.text_edit_singleline(&mut set.runtime_file_path);
                                });
                            }
                            if set.kind == "Character substitution" {
                                ui.horizontal(|ui| {
                                    ui.label("Substitutions (a=b,c=d):");
                                    ui.text_edit_singleline(&mut set.char_sub_rules);
                                });
                            }
                            // Left button column (`Paste`, `Load...`, `Remove`, `Clear`, `Deduplicate`) beside the payload list (`getting-started-with-intruder-5-usernames-in-list.png`)
                            let btn_w = 104.0;
                            let bsize = Vec2::new(btn_w, 26.0);
                            ui.horizontal_top(|ui| {
                                ui.vertical(|ui| {
                                    ui.set_min_width(btn_w);
                                    ui.spacing_mut().item_spacing.y = 5.0;
                                    if ui
                                        .add_sized(
                                            bsize,
                                            egui::Button::new(RichText::new("Paste").strong())
                                                .fill(btn_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(4.0),
                                        )
                                        .clicked()
                                    {
                                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                                    }
                                    if ui
                                        .add_sized(
                                            bsize,
                                            egui::Button::new(RichText::new("Load...").strong())
                                                .fill(btn_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(4.0),
                                        )
                                        .clicked()
                                    {
                                        if !set.values.is_empty() && !set.values.ends_with('\n') {
                                            set.values.push('\n');
                                        }
                                        set.values.push('\n');
                                    }
                                    if ui
                                        .add_sized(
                                            bsize,
                                            egui::Button::new(RichText::new("Remove").strong())
                                                .fill(btn_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(4.0),
                                        )
                                        .clicked()
                                    {
                                        let mut lines: Vec<&str> = set.values.lines().collect();
                                        if !lines.is_empty() {
                                            lines.pop();
                                            set.values = lines.join("\n");
                                        }
                                    }
                                    if ui
                                        .add_sized(
                                            bsize,
                                            egui::Button::new(RichText::new("Clear").strong())
                                                .fill(btn_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(4.0),
                                        )
                                        .clicked()
                                    {
                                        set.values.clear();
                                    }
                                    if ui
                                        .add_sized(
                                            bsize,
                                            egui::Button::new(RichText::new("Deduplicate").strong())
                                                .fill(btn_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(4.0),
                                        )
                                        .clicked()
                                    {
                                        let mut seen = Vec::new();
                                        for l in set.values.lines() {
                                            if !seen.contains(&l) {
                                                seen.push(l);
                                            }
                                        }
                                        set.values = seen.join("\n");
                                    }
                                });
                                ui.add(
                                    egui::TextEdit::multiline(&mut set.values)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(8),
                                );
                            });
                            ui.add_space(4.0);
                            // `[ Add ] [ Enter a new item ]`
                            ui.horizontal(|ui| {
                                if ui
                                    .add_sized(
                                        bsize,
                                        egui::Button::new(RichText::new("Add").strong())
                                            .fill(btn_bg)
                                            .stroke(Stroke::new(1.0_f32, border_col))
                                            .corner_radius(4.0),
                                    )
                                    .clicked()
                                    && !set.new_item_draft.is_empty()
                                {
                                    if !set.values.is_empty() && !set.values.ends_with('\n') {
                                        set.values.push('\n');
                                    }
                                    set.values.push_str(&set.new_item_draft);
                                    set.new_item_draft.clear();
                                }
                                ui.add(
                                    egui::TextEdit::singleline(&mut set.new_item_draft)
                                        .hint_text("Enter a new item")
                                        .desired_width(f32::INFINITY),
                                );
                            });
                            ui.add_space(4.0);
                            // Full-width `Add from list ...` dropdown (`getting-started-with-intruder-5-usernames-in-list.png`)
                            let list_w = (ui.available_width() - 6.0).max(160.0);
                            ui.horizontal_wrapped(|ui| {
                                egui::ComboBox::from_id_salt(("intruder-predefined-list", index))
                                    .selected_text("Add from list...")
                                    .width(list_w)
                                    .show_ui(ui, |ui| {
                                        for (label, items) in [
                                            (
                                                "Candidate usernames",
                                                "carlos\nroot\nadmin\ntest\nguest\ninfo\nadm\nmysql\nuser\nadministrator\noracle\nftp\npi\npuppet\nansible\nec2-user\nvagrant\nazureuser",
                                            ),
                                            (
                                                "Candidate passwords",
                                                "123456\npassword\n12345678\nqwerty\n123456789\n12345\n1234\n111111\n1234567\ndragon\n123123\nbaseball\nabc123\nfootball\nmonkey\nletmein\nshadow\nmaster",
                                            ),
                                            (
                                                "Common directories",
                                                "admin\nlogin\napi\nv1\nv2\nconfig\nbackup\n.env\n.git/HEAD\nrobots.txt",
                                            ),
                                            (
                                                "CGI Scripts",
                                                "/cgi-bin/{file}\n/cgi-bin/test.cgi\n/cgi-bin/status\n/cgi-bin/printenv",
                                            ),
                                            (
                                                "Fuzzing - quick",
                                                "{base}'\n{base}\"\n{base}<script>alert(1)</script>\n../../../../etc/passwd\n{{7*7}}",
                                            ),
                                            (
                                                "SQL injection probes",
                                                "'\n\"\n' OR '1'='1\n' OR '1'='1' --\nadmin'--\n1; SELECT 1--",
                                            ),
                                            (
                                                "XSS probes",
                                                "<script>alert(1)</script>\n\"><script>alert(1)</script>\n'><img src=x onerror=alert(1)>\n<svg/onload=alert(1)>",
                                            ),
                                            (
                                                "Path traversal",
                                                "../../../../../../etc/passwd\n..%2f..%2f..%2f..%2fetc%2fpasswd\n....//....//....//etc/passwd",
                                            ),
                                            (
                                                "SSTI probes",
                                                "{{7*7}}\n${7*7}\n<%= 7*7 %>\n{{7*'7'}}",
                                            ),
                                            (
                                                "Lowercase a-z",
                                                "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq\nr\ns\nt\nu\nv\nw\nx\ny\nz",
                                            ),
                                            (
                                                "Digits 0-9",
                                                "0\n1\n2\n3\n4\n5\n6\n7\n8\n9",
                                            ),
                                        ] {
                                            if ui.button(label).clicked() {
                                                set.values = items.into();
                                                ui.close();
                                            }
                                        }
                                    });
                                if set.kind == "Custom modification" {
                                    egui::ComboBox::from_id_salt("payload-processor")
                                        .selected_text(&set.processor)
                                        .show_ui(ui, |ui| {
                                            for operation in crate::logic::decoder_ops() {
                                                ui.selectable_value(
                                                    &mut set.processor,
                                                    operation.name.to_owned(),
                                                    operation.name,
                                                );
                                            }
                                        });
                                }
                            });
                        }
                    }
                });

            // 2. Payload processing section (`processing.html`)
            egui::CollapsingHeader::new(RichText::new("Payload processing").strong())
                .default_open(false)
                .show(ui, |ui| {
                    muted(
                        ui,
                        &theme,
                        "Define rules to perform processing tasks on each payload in sequence before it is used.",
                    );
                    let mut del_rule = None;
                    let mut move_up = None;
                    let mut move_down = None;
                    let rules_len = set.processing_rules.len();
                    if !set.processing_rules.is_empty() {
                        egui::Grid::new(("intruder-proc-rules", index))
                            .num_columns(5)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Enabled");
                                ui.strong("Rule");
                                ui.strong("Parameters");
                                ui.strong("Order");
                                ui.strong("");
                                ui.end_row();
                                for (r_idx, rule) in set.processing_rules.iter_mut().enumerate() {
                                    ui.checkbox(&mut rule.enabled, "");
                                    ui.label(&rule.kind);
                                    ui.monospace(if rule.arg2.is_empty() {
                                        rule.arg1.clone()
                                    } else {
                                        format!("{} -> {}", rule.arg1, rule.arg2)
                                    });
                                    ui.horizontal(|ui| {
                                        if ui.small_button("Up").clicked() && r_idx > 0 {
                                            move_up = Some(r_idx);
                                        }
                                        if ui.small_button("Down").clicked()
                                            && r_idx + 1 < rules_len
                                        {
                                            move_down = Some(r_idx);
                                        }
                                    });
                                    if ui.small_button("Remove").clicked() {
                                        del_rule = Some(r_idx);
                                    }
                                    ui.end_row();
                                }
                            });
                    }
                    if let Some(i) = move_up {
                        set.processing_rules.swap(i - 1, i);
                    }
                    if let Some(i) = move_down {
                        set.processing_rules.swap(i, i + 1);
                    }
                    if let Some(i) = del_rule {
                        set.processing_rules.remove(i);
                    }
                    ui.horizontal_wrapped(|ui| {
                        egui::ComboBox::from_id_salt(("proc-rule-kind", index))
                            .selected_text(&set.new_rule_kind)
                            .width(175.0)
                            .show_ui(ui, |ui| {
                                for k in PROCESSING_RULE_TYPES {
                                    ui.selectable_value(&mut set.new_rule_kind, k.to_string(), k);
                                }
                            });
                        ui.add(
                            egui::TextEdit::singleline(&mut set.new_rule_arg1)
                                .hint_text("Value / regex / scheme")
                                .desired_width(110.0),
                        );
                        if set.new_rule_kind == "Match / replace"
                            || set.new_rule_kind == "Substring"
                            || set.new_rule_kind == "Reverse substring"
                        {
                            ui.add(
                                egui::TextEdit::singleline(&mut set.new_rule_arg2)
                                    .hint_text("Replace / length")
                                    .desired_width(90.0),
                            );
                        }
                        if ui.button("Add rule").clicked() {
                            set.processing_rules.push(PayloadProcessingRule {
                                enabled: true,
                                kind: set.new_rule_kind.clone(),
                                arg1: set.new_rule_arg1.clone(),
                                arg2: set.new_rule_arg2.clone(),
                            });
                            set.new_rule_arg1.clear();
                            set.new_rule_arg2.clear();
                        }
                    });
                });

            // 3. Payload encoding section (`processing.html#configuring-payload-encoding`)
            egui::CollapsingHeader::new(RichText::new("Payload encoding").strong())
                .default_open(true)
                .show(ui, |ui| {
                    ui.checkbox(
                        &mut set.url_encode_enabled,
                        "URL-encode these characters:",
                    );
                    ui.text_edit_singleline(&mut set.url_encode_chars);
                });
            ui.separator();
        });
    }
    if let Some(index) = remove {
        panel.payload_sets.remove(index);
    }
    ui.horizontal_wrapped(|ui| {
        if ui.button("Add payload set").clicked() {
            panel.payload_sets.push(PayloadSet {
                values: String::new(),
                ..Default::default()
            });
        }
    });
    panel.payloads = panel
        .payload_sets
        .first()
        .map(|set| set.values.clone())
        .unwrap_or_default();

    // Local UTF-8 file loader (also keeps backward compatibility with `Load payload files`)
    egui::CollapsingHeader::new(RichText::new("Load local payload files").strong())
        .default_open(false)
        .show(ui, |ui| {
            payload_generation(app, ui);
        });
}

/// Side panel 2: `Resource pool` (`resource-pool.html`).
fn draw_resource_pool_side_panel(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Resource pool configuration");
    muted(
        ui,
        &theme,
        "A resource pool is a group of tasks that share a quota of concurrent requests and throttling settings.",
    );
    ui.separator();
    let panel = &mut app.panels.intruder;
    ui.radio_value(
        &mut panel.resource_pool_mode,
        0,
        "Use existing resource pool: Default resource pool",
    );
    ui.radio_value(
        &mut panel.resource_pool_mode,
        1,
        "Create new resource pool",
    );
    if panel.resource_pool_mode == 1 {
        ui.horizontal(|ui| {
            ui.label("Pool name:");
            ui.text_edit_singleline(&mut panel.resource_pool_name);
        });
    }
    ui.add_space(6.0);
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Maximum concurrent requests");
        ui.add(egui::DragValue::new(&mut panel.threads).range(1..=64));
    });
    ui.horizontal(|ui| {
        ui.label("Delay between requests per worker (ms)");
        ui.add(egui::DragValue::new(&mut panel.request_delay_ms).range(0..=300_000));
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Delay mode:");
        ui.radio_value(&mut panel.delay_mode, 0, "Fixed");
        ui.radio_value(&mut panel.delay_mode, 1, "With random variations");
        ui.radio_value(&mut panel.delay_mode, 2, "Increase delay in increments");
    });
    if panel.delay_mode == 2 {
        ui.horizontal(|ui| {
            ui.label("Increment (ms):");
            ui.add(egui::DragValue::new(&mut panel.delay_increment_ms).range(1..=60_000));
        });
    }
    ui.add_space(4.0);
    ui.checkbox(
        &mut panel.auto_throttle,
        "Automatic throttling — add short delay when server responds with:",
    );
    ui.text_edit_singleline(&mut panel.auto_throttle_codes);
    ui.add_space(4.0);
    muted(
        ui,
        &theme,
        "Pausing finishes current requests; cancelling closes in-flight connections and stops queued requests.",
    );
}

/// Side panel 3: `Settings` (`settings.html` — Save attack, Request headers, Error handling,
/// Attack results, Auto-pause attack, Grep - match, Grep - extract, Grep - payloads,
/// Redirections, HTTP/1 connection reuse, HTTP version).
fn draw_settings_side_panel(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Intruder attack settings");
    muted(
        ui,
        &theme,
        "Configure attack headers, error handling, grep rules, auto-pause, and redirection handling.",
    );
    ui.separator();
    let panel = &mut app.panels.intruder;

    // 1. Save attack
    ui.label(RichText::new("Save attack").strong());
    ui.checkbox(
        &mut panel.save_attack_to_project,
        "Save attack to project file",
    );
    ui.separator();

    // 2. Request headers
    ui.label(RichText::new("Request headers").strong());
    ui.checkbox(
        &mut panel.update_content_length,
        "Update Content-Length header",
    );
    ui.checkbox(
        &mut panel.set_connection_close,
        "Set Connection header to close",
    );
    ui.separator();

    // 3. Error handling
    ui.label(RichText::new("Error handling").strong());
    ui.horizontal_wrapped(|ui| {
        ui.label("Number of retries on network failure:");
        ui.add(egui::DragValue::new(&mut panel.retries_on_failure).range(0..=10));
        ui.label("Pause before retry (ms):");
        ui.add(egui::DragValue::new(&mut panel.pause_before_retry_ms).range(0..=60_000));
    });
    ui.horizontal(|ui| {
        ui.label("Request timeout (ms)");
        ui.add(egui::DragValue::new(&mut panel.timeout_ms).range(100..=300_000));
    });
    ui.separator();

    // 4. Attack results
    ui.label(RichText::new("Attack results").strong());
    ui.checkbox(
        &mut panel.store_requests_responses,
        "Store requests / responses",
    );
    ui.checkbox(
        &mut panel.make_baseline_request,
        "Make unmodified baseline request",
    );
    ui.checkbox(&mut panel.dos_mode, "Use denial-of-service mode");
    ui.checkbox(&mut panel.store_full_payloads, "Store full payloads");
    ui.separator();

    // 5. Auto-pause attack
    ui.label(RichText::new("Auto-pause attack").strong());
    ui.checkbox(&mut panel.auto_pause_enabled, "Enable auto-pause");
    if panel.auto_pause_enabled {
        ui.radio_value(
            &mut panel.auto_pause_when_appears,
            true,
            "Pause if an expression in the list appears in a response",
        );
        ui.radio_value(
            &mut panel.auto_pause_when_appears,
            false,
            "Pause if an expression in the list is missing from a response",
        );
        ui.add(
            egui::TextEdit::multiline(&mut panel.auto_pause_expressions)
                .font(egui::TextStyle::Monospace)
                .desired_rows(2)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            ui.checkbox(&mut panel.auto_pause_regex, "Regex match");
            ui.checkbox(&mut panel.auto_pause_case_sensitive, "Case-sensitive match");
        });
    }
    ui.separator();

    // 6. Grep - match (plus status/length match rules)
    ui.label(RichText::new("Grep - match").strong());
    ui.checkbox(
        &mut panel.grep_match_enabled,
        "Flag result items with responses matching these expressions",
    );
    ui.horizontal_wrapped(|ui| {
        ui.label("Include status codes");
        ui.add(egui::TextEdit::singleline(&mut panel.status_codes).desired_width(90.0));
        ui.label("Exclude status codes");
        ui.add(egui::TextEdit::singleline(&mut panel.negative_status).desired_width(90.0));
    });
    ui.horizontal(|ui| {
        ui.label("Exclude response regex");
        ui.text_edit_singleline(&mut panel.negative_regex);
    });
    ui.checkbox(
        &mut panel.match_length,
        "Match responses with a different length from the first response",
    );
    ui.add(
        egui::TextEdit::multiline(&mut panel.grep_match_expressions)
            .font(egui::TextStyle::Monospace)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    );
    ui.horizontal_wrapped(|ui| {
        ui.checkbox(&mut panel.grep_match_regex, "Regex");
        ui.checkbox(&mut panel.grep_match_case_sensitive, "Case sensitive match");
        ui.checkbox(&mut panel.grep_match_exclude_headers, "Exclude HTTP headers");
    });
    ui.separator();

    // 7. Grep - extract
    ui.label(RichText::new("Grep - extract").strong());
    ui.checkbox(
        &mut panel.grep_extract_enabled,
        "Extract the following items from responses",
    );
    if panel.grep_extract_enabled {
        ui.horizontal_wrapped(|ui| {
            ui.label("Regex / capture group:");
            ui.add(egui::TextEdit::singleline(&mut panel.grep_extract_pattern).desired_width(180.0));
            ui.label("Max capture length:");
            ui.add(egui::DragValue::new(&mut panel.grep_extract_max_len).range(1..=4096));
        });
    }
    ui.separator();

    // 8. Grep - payloads
    ui.label(RichText::new("Grep - payloads").strong());
    ui.checkbox(
        &mut panel.grep_payloads_enabled,
        "Search responses for payload strings",
    );
    if panel.grep_payloads_enabled {
        ui.checkbox(
            &mut panel.grep_payloads_case_sensitive,
            "Case sensitive match",
        );
        ui.checkbox(
            &mut panel.grep_payloads_exclude_headers,
            "Exclude HTTP headers",
        );
        ui.checkbox(
            &mut panel.grep_payloads_pre_urlencoded,
            "Match against pre-URL-encoded payloads",
        );
    }
    ui.separator();

    // 9. Redirections
    ui.label(RichText::new("Redirections").strong());
    ui.horizontal_wrapped(|ui| {
        ui.label("Follow redirections:");
        for (idx, lbl) in ["Never", "On-site only", "In-scope only", "Always"]
            .iter()
            .enumerate()
        {
            ui.selectable_value(&mut panel.follow_redirections, idx, *lbl);
        }
    });
    ui.checkbox(
        &mut panel.process_cookies_in_redirections,
        "Process cookies in redirections",
    );
    ui.separator();

    // 10. HTTP/1 connection reuse & HTTP version
    ui.label(RichText::new("HTTP/1 connection reuse & HTTP version").strong());
    ui.checkbox(&mut panel.http1_connection_reuse, "HTTP/1 connection reuse");
    ui.checkbox(
        &mut panel.override_http2,
        "Override the project-level HTTP/2 setting",
    );
    if panel.override_http2 {
        ui.checkbox(
            &mut panel.default_to_http2,
            "Default to HTTP/2 if the server supports it",
        );
    }
}

fn payload_generation(app: &mut App, ui: &mut Ui) {
    ui.label("Load local UTF-8 payload files, one path per line, into the first payload set.");
    ui.add(
        egui::TextEdit::multiline(&mut app.panels.intruder.generation_sources)
            .desired_width(f32::INFINITY)
            .desired_rows(3),
    );
    if ui.button("Load payload files").clicked() {
        let loaded: std::result::Result<Vec<_>, _> = app
            .panels
            .intruder
            .generation_sources
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|path| {
                std::fs::read_to_string(path.trim())
                    .map_err(|error| format!("{}: {error}", path.trim()))
            })
            .collect();
        match loaded {
            Ok(files) if !files.is_empty() => {
                let values: Vec<_> = files.iter().flat_map(|file| file.lines()).collect();
                if values.len() > 50_000 {
                    app.status = "Payload files exceed the 50000 item limit".into();
                    return;
                }
                if app.panels.intruder.payload_sets.is_empty() {
                    app.panels.intruder.payload_sets.push(PayloadSet::default());
                }
                let set = &mut app.panels.intruder.payload_sets[0];
                set.kind = "Simple list".into();
                set.values = values.join("\n");
                if values.last().is_some_and(|value| value.is_empty()) {
                    set.values.push('\n');
                }
                app.status = format!("Loaded {} payloads", values.len());
            }
            Ok(_) => app.status = "Choose at least one payload file".into(),
            Err(error) => app.status = error,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    {
        let w = &mut ui.style_mut().visuals.widgets;
        let r = egui::CornerRadius::same(4);
        w.inactive.corner_radius = r;
        w.hovered.corner_radius = r;
        w.active.corner_radius = r;
        w.open.corner_radius = r;
        w.noninteractive.corner_radius = r;
    }
    let tab_bar_bg = theme.color("ui.background.1");
    let border_col = theme.color("ui.border.1");

    if app.panels.intruder.show_getting_started {
        draw_getting_started(app, ui);
        return;
    }

    // Row 0: Attack tabs strip (`1 × | 2 × | +` + `? Getting started` + `Scan defined insertion points`)
    egui::Frame::new()
        .fill(tab_bar_bg)
        .inner_margin(egui::Margin::same(0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let mut close_tab = None;
                let tabs_len = app.panels.intruder.tabs.len();
                for idx in 0..tabs_len {
                    let title = app.panels.intruder.tabs[idx].clone();
                    let active = !app.panels.intruder.show_getting_started
                        && app.panels.intruder.active_tab == idx;
                    let cell_bg = if active {
                        theme.color("ui.background.0")
                    } else {
                        tab_bar_bg
                    };
                    let cell_out = egui::Frame::new()
                        .fill(cell_bg)
                        .inner_margin(egui::Margin::symmetric(10, 5))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let label = RichText::new(&title)
                                    .size(12.0)
                                    .color(theme.color(if active {
                                        "ui.text.heading"
                                    } else {
                                        "ui.text.body"
                                    }));
                                let tab_resp =
                                    ui.add(egui::Label::new(label).sense(egui::Sense::click()));
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("×")
                                                .size(12.0)
                                                .color(theme.color("ui.icon.default")),
                                        )
                                        .frame(false),
                                    )
                                    .on_hover_text("Close attack tab")
                                    .clicked()
                                {
                                    close_tab = Some(idx);
                                }
                                tab_resp
                            })
                            .inner
                        });
                    let cell_rect = cell_out.response.rect;
                    ui.painter().line_segment(
                        [
                            pos2(cell_rect.max.x, cell_rect.min.y),
                            pos2(cell_rect.max.x, cell_rect.max.y),
                        ],
                        Stroke::new(1.0_f32, border_col),
                    );
                    if active {
                        ui.painter().rect_filled(
                            egui::Rect::from_min_max(
                                pos2(cell_rect.min.x, cell_rect.max.y - 3.0),
                                pos2(cell_rect.max.x, cell_rect.max.y),
                            ),
                            0.0,
                            theme.color("ui.icon.accent"),
                        );
                    }
                    if cell_out.inner.clicked() {
                        app.panels.intruder.active_tab = idx;
                        app.panels.intruder.show_getting_started = false;
                    }
                }
                if let Some(idx) = close_tab {
                    app.panels.intruder.tabs.remove(idx);
                    if app.panels.intruder.tabs.is_empty() {
                        app.panels.intruder.show_getting_started = true;
                    } else if app.panels.intruder.active_tab >= app.panels.intruder.tabs.len() {
                        app.panels.intruder.active_tab = app.panels.intruder.tabs.len() - 1;
                    }
                }
                ui.add_space(6.0);
                if ui
                    .button("+")
                    .on_hover_text("Create new Intruder attack tab")
                    .clicked()
                {
                    let next = app.panels.intruder.tabs.len() + 1;
                    app.panels.intruder.tabs.push(next.to_string());
                    app.panels.intruder.active_tab = app.panels.intruder.tabs.len() - 1;
                    app.panels.intruder.show_getting_started = false;
                }
                ui.add_space(6.0);
                if ui
                    .selectable_label(app.panels.intruder.show_getting_started, "? Getting started")
                    .clicked()
                {
                    app.panels.intruder.show_getting_started =
                        !app.panels.intruder.show_getting_started;
                }
                ui.add_space(6.0);
                if ui
                    .button("Scan defined insertion points")
                    .on_hover_text("Send this request and its §positions§ to the active Scanner")
                    .clicked()
                {
                    app.panels.scanner.seed = app.panels.intruder.host.clone();
                    super::scanner::start(app);
                }

                // Right-side side-panel tab switcher (`Payloads`, `Resource pool`, `Attack settings`, `Payload generation`)
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    for (tab_idx, label) in [
                        (3usize, "Payload generation"),
                        (2usize, "Attack settings"),
                        (1usize, "Resource pool"),
                        (0usize, "Payloads"),
                    ] {
                        let active = !app.panels.intruder.side_panel_collapsed
                            && app.panels.intruder.side_panel_tab == tab_idx;
                        let fill = if active {
                            if theme.dark {
                                Color32::from_rgb(0x2C, 0x51, 0x75)
                            } else {
                                Color32::from_rgb(0xCC, 0xDD, 0xF2)
                            }
                        } else {
                            Color32::TRANSPARENT
                        };
                        let fg = if active {
                            if theme.dark {
                                Color32::WHITE
                            } else {
                                Color32::from_rgb(0x16, 0x16, 0x16)
                            }
                        } else {
                            theme.color("ui.text.body")
                        };
                        if ui
                            .add(
                                egui::Button::new(RichText::new(label).color(fg).size(11.5).strong())
                                    .fill(fill)
                                    .corner_radius(3.0),
                            )
                            .clicked()
                        {
                            app.panels.intruder.side_panel_tab = tab_idx;
                            app.panels.intruder.side_panel_collapsed = false;
                            app.view = match tab_idx {
                                0 => 1,
                                1 => 4,
                                2 => 2,
                                _ => 3,
                            };
                        }
                    }
                });
            });
        });

    let sep_rect = egui::Rect::from_min_size(
        ui.cursor().min,
        Vec2::new(ui.available_width(), 1.0),
    );
    ui.painter().rect_filled(sep_rect, 0.0, border_col);
    ui.add_space(1.0);

    if app.panels.intruder.show_getting_started {
        draw_getting_started(app, ui);
        return;
    }

    // Sync legacy `app.view` if changed externally
    match app.view {
        1 => app.panels.intruder.side_panel_tab = 0,
        2 => app.panels.intruder.side_panel_tab = 2,
        3 => app.panels.intruder.side_panel_tab = 3,
        4 => app.panels.intruder.side_panel_tab = 1,
        _ => {}
    }

    egui::Frame::new()
        .fill(theme.color("ui.background.0"))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            let show_results =
                app.panels.intruder.running || !app.panels.intruder.results.is_empty();
            if app.panels.intruder.side_panel_collapsed {
                egui::ScrollArea::vertical()
                    .id_salt("intruder-left-only-scroll")
                    .show(ui, |ui| {
                        draw_positions_editor(app, ui);
                        if show_results {
                            ui.separator();
                            draw_results_area(app, ui);
                        }
                    });
            } else {
                let avail_h = ui.available_height().max(320.0);
                let mut ratio = app.panels.intruder.main_split_ratio;
                let side_left = app.panels.intruder.side_panel_left;
                super::vertical_split(
                    ui,
                    &theme,
                    "intruder-main-split",
                    &mut ratio,
                    avail_h,
                    |side, ui| {
                        let is_positions_side = if side_left { side == 1 } else { side == 0 };
                        if is_positions_side {
                            egui::ScrollArea::vertical()
                                .id_salt("intruder-left-pane-scroll")
                                .show(ui, |ui| {
                                    draw_positions_editor(app, ui);
                                    if show_results {
                                        ui.separator();
                                        draw_results_area(app, ui);
                                    }
                                });
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt("intruder-right-side-panel-scroll")
                                .show(ui, |ui| {
                                    match app.panels.intruder.side_panel_tab {
                                        1 => draw_resource_pool_side_panel(app, ui),
                                        2 => draw_settings_side_panel(app, ui),
                                        3 => payload_generation(app, ui),
                                        _ => draw_payloads_side_panel(app, ui),
                                    }
                                });
                        }
                    },
                );
                app.panels.intruder.main_split_ratio = ratio;
            }
        });
}

fn codes(text: &str) -> std::result::Result<Vec<u16>, String> {
    let mut codes = Vec::new();
    for part in text
        .split([',', ' ', '\t', '\n'])
        .filter(|part| !part.is_empty())
    {
        let (start, end) = part.split_once('-').map_or((part, part), |pair| pair);
        let start: u16 = start.parse().map_err(|_| "Invalid HTTP status code")?;
        let end: u16 = end.parse().map_err(|_| "Invalid HTTP status code")?;
        if !(100..=599).contains(&start) || !(start..=599).contains(&end) {
            return Err("Status codes must be in 100..599".into());
        }
        codes.extend(start..=end);
    }
    Ok(codes)
}

pub(crate) fn start(app: &mut App) {
    if app.panels.intruder.running {
        return;
    }
    let build = || -> std::result::Result<_, String> {
        let panel = &app.panels.intruder;
        let target = HttpTarget::parse(&panel.host)?;
        let sets: Vec<_> = panel
            .payload_sets
            .iter()
            .map(|set| set.generate(50_000))
            .collect::<std::result::Result<_, _>>()?;
        let requests =
            intruder::generate_requests(&panel.template, panel.attack_type, &sets, 50_000)?;
        let rules = MatchRules {
            status: codes(&panel.status_codes)?,
            negative_status: codes(&panel.negative_status)?,
            negative_regex: if panel.negative_regex.is_empty() {
                None
            } else {
                Some(regex::Regex::new(&panel.negative_regex).map_err(|error| error.to_string())?)
            },
            length: panel.match_length,
        };
        let options = AttackOptions {
            concurrency: panel.threads,
            timeout_ms: panel.timeout_ms,
            delay_ms: panel.request_delay_ms,
            update_host: panel.update_host,
            rules,
        };
        Ok((target, requests, options))
    };
    let (target, requests, options) = match build() {
        Ok(plan) => plan,
        Err(error) => {
            app.status = error;
            return;
        }
    };
    let total = requests.len();
    let control = AttackControl::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let task_id =
        app.workspace_adapter
            .begin_attack(&mut app.workspace, &app.panels.intruder.host, total);
    if let Some(task) = app.workspace.tasks.get_mut(task_id) {
        task.configuration = app.panels.intruder.attack_type.label().into();
    }
    let panel = &mut app.panels.intruder;
    panel.clear_results();
    panel.total = total;
    panel.running = true;
    panel.control = Some(control.clone());
    panel.task_id = Some(task_id);
    app.intruder_updates = Some(rx);
    app.runtime_handle().spawn(intruder::run_attack(
        app.proxy.as_ref().clone(),
        target,
        requests,
        options,
        control,
        tx,
    ));
    app.status = format!("Intruder: running {total} requests");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_requests_recalculates_content_length_for_variable_length_payloads() {
        let template = "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nuser=§bob§";
        let reqs = intruder::generate_requests(
            template,
            AttackType::Sniper,
            &[vec!["administrator".into(), "x".into()]],
            10,
        )
        .unwrap();
        assert!(
            reqs[0].request.contains("Content-Length: 18\r\n"),
            "got: {}",
            reqs[0].request
        );
        assert!(
            reqs[1].request.contains("Content-Length: 6\r\n"),
            "got: {}",
            reqs[1].request
        );
    }

    #[test]
    fn illegal_unicode_ecb_shuffler_and_custom_iterator_generate_distinct_payloads() {
        let mut set = PayloadSet {
            kind: "Illegal Unicode".into(),
            values: "../admin".into(),
            ..Default::default()
        };
        let unicode = set.generate(20).unwrap();
        assert!(unicode.iter().any(|p| p.contains("%c0%af")));
        assert!(unicode.iter().any(|p| p.contains("%e0%80%af")));

        set.kind = "ECB block shuffler".into();
        set.ecb_block_size = 4;
        set.values = "AAAABBBBCCCC".into();
        let shuffled = set.generate(20).unwrap();
        assert!(shuffled.contains(&"BBBBAAAACCCC".to_string()));
        assert!(shuffled.contains(&"CCCCBBBBAAAA".to_string()));

        set.kind = "Custom iterator".into();
        set.custom_iterator_sep = ":".into();
        set.values = "admin, root\n1234, toor".into();
        let iter_out = set.generate(20).unwrap();
        assert_eq!(
            iter_out,
            vec!["admin:1234", "admin:toor", "root:1234", "root:toor"]
        );
    }

    #[test]
    fn record_exchange_evaluates_grep_match_and_grep_extract() {
        let mut panel = IntruderPanel::default();
        panel.grep_match_enabled = true;
        panel.grep_match_expressions = "sql syntax\nfatal error".into();
        panel.grep_extract_enabled = true;
        panel.grep_extract_pattern = "<title>(.*?)</title>".into();

        panel.record_exchange(Result {
            index: 0,
            status: 500,
            length: 64,
            matched: false,
            response: "HTTP/1.1 500 Internal Server Error\r\n\r\n<title>DB Error</title>You have an error in your SQL syntax".into(),
            ..Default::default()
        });
        assert_eq!(panel.results.len(), 1);
        assert!(panel.results[0].matched);
        assert_eq!(panel.matches, 1);
        assert!(panel.results[0].comment.contains("[Grep: sql syntax]"));
        assert!(panel.results[0].comment.contains("[Extract: DB Error]"));
    }
}
