//! Local Intruder request generation and attack execution.

use crate::http_target::HttpTarget;
use crate::proxy::{MatchRules, Proxy};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttackType {
    #[default]
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl AttackType {
    pub const ALL: [Self; 4] = [
        Self::Sniper,
        Self::BatteringRam,
        Self::Pitchfork,
        Self::ClusterBomb,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Sniper => "Sniper",
            Self::BatteringRam => "Battering ram",
            Self::Pitchfork => "Pitchfork",
            Self::ClusterBomb => "Cluster bomb",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Sniper => "Sniper attack",
            Self::BatteringRam => "Battering ram attack",
            Self::Pitchfork => "Pitchfork attack",
            Self::ClusterBomb => "Cluster bomb attack",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Sniper => {
                "Inserts each payload into each position one at a time, using a single payload set."
            }
            Self::BatteringRam => {
                "Simultaneously places the same payload into all positions, using a single payload set."
            }
            Self::Pitchfork => {
                "Allocate a payload set to each position. Intruder iterates through each set in parallel."
            }
            Self::ClusterBomb => {
                "Allocate a payload set to each position. Intruder iterates through all possible combinations of each set."
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttackRequest {
    pub request: String,
    pub payloads: Vec<String>,
}

fn position_ranges(template: &str) -> Result<Vec<std::ops::Range<usize>>, String> {
    let markers: Vec<_> = template
        .match_indices('§')
        .map(|(offset, _)| offset)
        .collect();
    if markers.is_empty() {
        return Err("Add at least one §payload position§".into());
    }
    if markers.len() % 2 != 0 {
        return Err("Every payload position needs an opening and closing § marker".into());
    }
    Ok(markers
        .chunks_exact(2)
        .map(|pair| pair[0]..pair[1] + '§'.len_utf8())
        .collect())
}

pub fn position_count(template: &str) -> Result<usize, String> {
    position_ranges(template).map(|ranges| ranges.len())
}

pub fn auto_mark_positions(raw: &str) -> String {
    let mut raw = raw.replace('§', "");
    let (head, body) = crate::analysis::split_message(&raw);
    let mut ranges = Vec::new();
    let mut pairs = |text: &str, separator: char, offset: usize, trim: bool| {
        let mut cursor = 0;
        for pair in text.split(separator) {
            if let Some(equal) = pair.find('=') {
                let value = &pair[equal + 1..];
                let leading = if trim {
                    value.len() - value.trim_start().len()
                } else {
                    0
                };
                let length = if trim {
                    value.trim().len()
                } else {
                    value.len()
                };
                let start = offset + cursor + equal + 1 + leading;
                ranges.push(start..start + length);
            }
            cursor += pair.len() + separator.len_utf8();
        }
    };
    if let Some(line) = head.lines().next() {
        if let Some(target) = line.split_whitespace().nth(1) {
            if let Some(query) = target.find('?') {
                let text = target[query + 1..].split('#').next().unwrap_or("");
                pairs(text, '&', line.find(target).unwrap_or(0) + query + 1, false);
            }
        }
    }
    let mut offset = 0;
    let mut content_type = String::new();
    for line in head.split_inclusive('\n') {
        if let Some((name, value)) = line.trim_end_matches(['\r', '\n']).split_once(':') {
            if name.eq_ignore_ascii_case("cookie") {
                pairs(value, ';', offset + name.len() + 1, true);
            }
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_ascii_lowercase();
            }
        }
        offset += line.len();
    }
    let body_offset = raw.len() - body.len();
    if content_type.starts_with("application/x-www-form-urlencoded") {
        pairs(body, '&', body_offset, false);
    }
    if content_type.starts_with("application/json") {
        let pattern = regex::Regex::new(
            r#":\s*("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)"#,
        )
        .expect("static JSON value expression");
        for capture in pattern.captures_iter(body) {
            if let Some(value) = capture.get(1) {
                let quoted = value.as_str().starts_with('"');
                ranges.push(
                    body_offset + value.start() + usize::from(quoted)
                        ..body_offset + value.end() - usize::from(quoted),
                );
            }
        }
    }
    ranges.sort_by_key(|range| range.start);
    ranges.dedup();
    for range in ranges.into_iter().rev() {
        raw.insert(range.end, '§');
        raw.insert(range.start, '§');
    }
    raw
}

pub fn generate_requests(
    template: &str,
    mode: AttackType,
    sets: &[Vec<String>],
    limit: usize,
) -> Result<Vec<AttackRequest>, String> {
    let ranges = position_ranges(template)?;
    let set_count = if matches!(mode, AttackType::Sniper | AttackType::BatteringRam) {
        1
    } else {
        ranges.len()
    };
    if sets.len() < set_count || sets[..set_count].iter().any(Vec::is_empty) {
        return Err(format!(
            "{} needs {set_count} non-empty payload set(s)",
            mode.label()
        ));
    }
    let count = match mode {
        AttackType::Sniper => sets[0].len().checked_mul(ranges.len()),
        AttackType::BatteringRam => Some(sets[0].len()),
        AttackType::Pitchfork => sets[..set_count].iter().map(Vec::len).min(),
        AttackType::ClusterBomb => sets[..set_count]
            .iter()
            .try_fold(1usize, |total, set| total.checked_mul(set.len())),
    }
    .filter(|count| *count <= limit)
    .ok_or_else(|| format!("Attack exceeds the configured {limit} request limit"))?;
    let mut generated_bytes = 0usize;
    let mut render = |replacements: &[Option<&str>],
                      payloads: Vec<String>|
     -> Result<AttackRequest, String> {
        let size = template.len() - ranges.iter().map(|range| range.len()).sum::<usize>()
            + ranges
                .iter()
                .enumerate()
                .map(|(index, range)| replacements[index].map_or(range.len() - 4, str::len))
                .sum::<usize>();
        generated_bytes = generated_bytes
            .checked_add(size)
            .filter(|size| *size <= 64 * 1024 * 1024)
            .ok_or("Generated requests exceed the 64 MiB memory limit")?;
        let mut request = String::new();
        let mut start = 0;
        for (index, range) in ranges.iter().enumerate() {
            request.push_str(&template[start..range.start]);
            request
                .push_str(replacements[index].unwrap_or(&template[range.start + 2..range.end - 2]));
            start = range.end;
        }
        request.push_str(&template[start..]);
        let request = sync_content_length(&request);
        Ok(AttackRequest { request, payloads })
    };
    let mut requests = Vec::with_capacity(count);
    match mode {
        AttackType::Sniper => {
            for position in 0..ranges.len() {
                for payload in &sets[0] {
                    let mut replacements = vec![None; ranges.len()];
                    replacements[position] = Some(payload.as_str());
                    requests.push(render(&replacements, vec![payload.clone()])?);
                }
            }
        }
        AttackType::BatteringRam => {
            for payload in &sets[0] {
                requests.push(render(
                    &vec![Some(payload.as_str()); ranges.len()],
                    vec![payload.clone()],
                )?);
            }
        }
        AttackType::Pitchfork | AttackType::ClusterBomb => {
            for ordinal in 0..count {
                let mut cursor = ordinal;
                let mut indices = vec![0; ranges.len()];
                for position in (0..ranges.len()).rev() {
                    indices[position] = if mode == AttackType::Pitchfork {
                        ordinal
                    } else {
                        cursor % sets[position].len()
                    };
                    cursor /= sets[position].len();
                }
                let payloads: Vec<_> = indices
                    .iter()
                    .enumerate()
                    .map(|(position, index)| sets[position][*index].clone())
                    .collect();
                let replacements: Vec<_> = payloads
                    .iter()
                    .map(|payload| Some(payload.as_str()))
                    .collect();
                requests.push(render(&replacements, payloads.clone())?);
            }
        }
    }
    Ok(requests)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackState {
    Running,
    Paused,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct AttackControl {
    state: watch::Sender<AttackState>,
}

impl Default for AttackControl {
    fn default() -> Self {
        Self {
            state: watch::channel(AttackState::Running).0,
        }
    }
}

impl AttackControl {
    pub fn state(&self) -> AttackState {
        *self.state.borrow()
    }
    pub fn pause(&self) {
        self.state.send_if_modified(|state| {
            if *state == AttackState::Running {
                *state = AttackState::Paused;
                true
            } else {
                false
            }
        });
    }
    pub fn resume(&self) {
        self.state.send_if_modified(|state| {
            if *state == AttackState::Paused {
                *state = AttackState::Running;
                true
            } else {
                false
            }
        });
    }
    pub fn cancel(&self) {
        self.state.send_replace(AttackState::Cancelled);
    }
}

#[derive(Clone)]
pub struct AttackOptions {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub delay_ms: u64,
    pub update_host: bool,
    pub rules: MatchRules,
}

impl Default for AttackOptions {
    fn default() -> Self {
        Self {
            concurrency: 4,
            timeout_ms: 15_000,
            delay_ms: 0,
            update_host: true,
            rules: MatchRules::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AttackResult {
    pub index: usize,
    pub payloads: Vec<String>,
    pub request: String,
    pub response: String,
    pub response_truncated: bool,
    pub target: Option<HttpTarget>,
    pub status: u16,
    pub length: usize,
    pub matched: bool,
    pub error: Option<String>,
    pub timed_out: bool,
    pub comment: String,
    pub elapsed_ms: u128,
}

fn range_values(start: i64, end: i64, step: i64, limit: usize) -> Result<Vec<i64>, String> {
    if step == 0 || (start < end && step < 0) || (start > end && step > 0) {
        return Err("Step must be non-zero and move from the start toward the end".into());
    }
    let count = (i128::from(end) - i128::from(start)).abs() / i128::from(step).abs() + 1;
    if count > limit as i128 {
        return Err(format!("Payload range exceeds the {limit} value limit"));
    }
    Ok((0..count)
        .map(|index| (i128::from(start) + index * i128::from(step)) as i64)
        .collect())
}

pub fn number_payloads(
    start: i64,
    end: i64,
    step: i64,
    limit: usize,
) -> Result<Vec<String>, String> {
    range_values(start, end, step, limit)
        .map(|values| values.into_iter().map(|value| value.to_string()).collect())
}

fn date_timestamp(value: &str) -> Result<i64, String> {
    let value = value.trim().replace('T', " ");
    let (date, clock) = value
        .split_once(' ')
        .map_or((value.as_str(), "00:00:00"), |pair| pair);
    let parts: Vec<_> = date.split('-').collect();
    let clock: Vec<_> = clock.split(':').collect();
    if parts.len() != 3 || clock.len() != 3 {
        return Err("Use YYYY-MM-DD or YYYY-MM-DD HH:mm:ss (UTC)".into());
    }
    let invalid = || "Invalid date or time".to_owned();
    let month = time::Month::try_from(parts[1].parse::<u8>().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let date = time::Date::from_calendar_date(
        parts[0].parse().map_err(|_| invalid())?,
        month,
        parts[2].parse().map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let datetime = date
        .with_hms(
            clock[0].parse().map_err(|_| invalid())?,
            clock[1].parse().map_err(|_| invalid())?,
            clock[2].parse().map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
    Ok(datetime.assume_utc().unix_timestamp())
}

pub fn date_payloads(
    start: &str,
    end: &str,
    step: i64,
    limit: usize,
) -> Result<Vec<String>, String> {
    let date_only = !start.trim().contains([' ', 'T']);
    if date_only != !end.trim().contains([' ', 'T']) {
        return Err("Start and end must use the same date/time format".into());
    }
    let step = if date_only {
        step.checked_mul(86400).ok_or("Date step is too large")?
    } else {
        step
    };
    range_values(date_timestamp(start)?, date_timestamp(end)?, step, limit)?
        .into_iter()
        .map(|value| {
            let date = time::OffsetDateTime::from_unix_timestamp(value)
                .map_err(|error| error.to_string())?;
            if date_only {
                Ok(date.date().to_string())
            } else {
                Ok(format!(
                    "{} {:02}:{:02}:{:02}",
                    date.date(),
                    date.hour(),
                    date.minute(),
                    date.second()
                ))
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct AttackSummary {
    pub total: usize,
    pub completed: usize,
    pub matches: usize,
    pub cancelled: bool,
}

#[derive(Clone, Debug)]
pub enum AttackUpdate {
    Result(AttackResult),
    Done(AttackSummary),
}

async fn ready(state: &mut watch::Receiver<AttackState>) -> bool {
    loop {
        let current = *state.borrow_and_update();
        match current {
            AttackState::Running => return true,
            AttackState::Cancelled => return false,
            AttackState::Paused => {
                if state.changed().await.is_err() {
                    return false;
                }
            }
        }
    }
}

async fn cancelled(state: &mut watch::Receiver<AttackState>) {
    loop {
        if *state.borrow_and_update() == AttackState::Cancelled {
            return;
        }
        if state.changed().await.is_err() {
            return;
        }
    }
}

/// Updates any existing `Content-Length` header in `raw` to match the byte length of its body.
pub fn sync_content_length(raw: &str) -> String {
    let sep = if let Some(idx) = raw.find("\r\n\r\n") {
        Some((idx, "\r\n\r\n", "\r\n"))
    } else {
        raw.find("\n\n").map(|idx| (idx, "\n\n", "\n"))
    };
    let Some((sep_idx, sep_str, line_sep)) = sep else {
        return raw.to_string();
    };
    let head = &raw[..sep_idx];
    let body = &raw[sep_idx + sep_str.len()..];
    let has_cl = head.lines().skip(1).any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
    });
    if !has_cl {
        return raw.to_string();
    }
    let mut updated = String::with_capacity(raw.len() + 16);
    for (i, line) in head.lines().enumerate() {
        if i > 0
            && line
                .split_once(':')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        {
            updated.push_str(&format!("Content-Length: {}{line_sep}", body.len()));
        } else {
            updated.push_str(line);
            updated.push_str(line_sep);
        }
    }
    updated.push_str(line_sep);
    updated.push_str(body);
    updated
}

pub fn update_host_header(raw: &str, authority: &str) -> String {
    let raw_synced = sync_content_length(raw);
    let (head, body) = crate::analysis::split_message(&raw_synced);
    let mut updated = String::new();
    let mut found = false;
    for line in head.lines() {
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        {
            if found {
                continue;
            }
            updated.push_str(&format!("Host: {authority}\r\n"));
            found = true;
        } else {
            updated.push_str(line);
            updated.push_str("\r\n");
        }
    }
    if !found {
        updated.push_str(&format!("Host: {authority}\r\n"));
    }
    updated.push_str("\r\n");
    updated.push_str(body);
    updated
}

pub async fn run_attack(
    proxy: Proxy,
    target: HttpTarget,
    requests: Vec<AttackRequest>,
    options: AttackOptions,
    control: AttackControl,
    updates: std::sync::mpsc::Sender<AttackUpdate>,
) {
    let requests = Arc::new(requests);
    let cursor = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let matches = Arc::new(AtomicUsize::new(0));
    let baseline = Arc::new(AtomicUsize::new(usize::MAX));
    let capture_budget = Arc::new(AtomicUsize::new(64 * 1024 * 1024));
    let mut workers = Vec::new();
    for _ in 0..options.concurrency.clamp(1, 64).min(requests.len()) {
        let (requests, cursor, completed, matches, baseline) = (
            requests.clone(),
            cursor.clone(),
            completed.clone(),
            matches.clone(),
            baseline.clone(),
        );
        let capture_budget = capture_budget.clone();
        let (proxy, target, options, updates) = (
            proxy.clone(),
            target.clone(),
            options.clone(),
            updates.clone(),
        );
        let mut state = control.state.subscribe();
        let mut cancellation = control.state.subscribe();
        workers.push(tokio::spawn(async move {
            while ready(&mut state).await {
                let index = cursor.fetch_add(1, Ordering::SeqCst);
                let Some(row) = requests.get(index) else { break; };
                let raw = if options.update_host { update_host_header(&row.request, &target.authority()) } else { row.request.clone() };
                let start = std::time::Instant::now();
                let outcome = tokio::select! {
                    biased;
                    _ = cancelled(&mut cancellation) => break,
                    result = proxy.one_shot_secure(&target.host, target.port, &raw, target.secure, options.timeout_ms) => result,
                };
                let (status, mut response, error) = match outcome {
                    Ok((status, response)) => (status, response, None),
                    Err(error) => (0, String::new(), Some(error)),
                };
                let matched = error.is_none() && crate::proxy::apply_rules(&options.rules, &baseline, status, &response);
                if matched { matches.fetch_add(1, Ordering::SeqCst); }
                completed.fetch_add(1, Ordering::SeqCst);
                let length = response.len();
                let wanted = length.min(crate::proxy::BODY_CAPTURE_LIMIT);
                let budget = capture_budget.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |budget| Some(budget.saturating_sub(wanted))).unwrap_or(0);
                let mut keep = wanted.min(budget);
                while !response.is_char_boundary(keep) { keep -= 1; }
                response.truncate(keep);
                let timed_out = error.as_deref().is_some_and(|e| e.to_lowercase().contains("timed out") || e.to_lowercase().contains("timeout"));
                let result = AttackResult { index, payloads: row.payloads.clone(), request: raw, length, response_truncated: keep < length, target: Some(target.clone()), response, status, matched, error, timed_out, comment: String::new(), elapsed_ms: start.elapsed().as_millis() };
                if updates.send(AttackUpdate::Result(result)).is_err() { break; }
                if options.delay_ms > 0 {
                    tokio::select! {
                        _ = cancelled(&mut cancellation) => break,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(options.delay_ms)) => {}
                    }
                }
            }
        }));
    }
    for worker in workers {
        let _ = worker.await;
    }
    let _ = updates.send(AttackUpdate::Done(AttackSummary {
        total: requests.len(),
        completed: completed.load(Ordering::SeqCst),
        matches: matches.load(Ordering::SeqCst),
        cancelled: control.state() == AttackState::Cancelled,
    }));
}
