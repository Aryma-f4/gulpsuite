//! Cookie jar and session handling.
//!
//! Burp models this as `http/sessions/CookieJar` with `SessionHandlingAction`. The proxy needs it
//! to behave like a browser on repeat visits: store `Set-Cookie`, replay `Cookie`, honour
//! `Expires`/`Max-Age`, and scope by domain and path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// One stored cookie. `expires` is an absolute instant; `None` means session-scoped.
#[derive(Clone, Debug, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<SystemTime>,
    pub secure: bool,
    pub http_only: bool,
}

impl Cookie {
    /// Domain match per RFC 6265: exact, or a suffix on a label boundary.
    fn domain_matches(cookie_domain: &str, host: &str) -> bool {
        let cookie_domain = cookie_domain.trim_start_matches('.').to_lowercase();
        let host = host.to_lowercase();
        if cookie_domain == host {
            return true;
        }
        host.ends_with(&cookie_domain)
            && host
                .as_bytes()
                .get(host.len() - cookie_domain.len() - 1)
                .map(|b| *b == b'.')
                .unwrap_or(false)
    }

    /// Path match per RFC 6265: equal, or a prefix on a path segment boundary.
    fn path_matches(cookie_path: &str, request_path: &str) -> bool {
        let request_path = if request_path.is_empty() { "/" } else { request_path };
        if cookie_path == request_path {
            return true;
        }
        request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/'))
    }

    fn is_expired(&self, now: SystemTime) -> bool {
        matches!(self.expires, Some(at) if at <= now)
    }

    /// A `Name=Value` pair, as it appears in a `Cookie` header.
    pub fn pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// Parses one `Set-Cookie` header value. Returns `None` when there is no `name=value` pair, which
/// is the only part a cookie jar actually needs.
pub fn parse_set_cookie(header: &str) -> Option<Cookie> {
    let mut parts = header.split(';');
    let first = parts.next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = Cookie {
        name: name.to_string(),
        // A quoted value keeps its quotes out; Burp shows the value without them.
        value: value.trim().trim_matches('"').to_string(),
        domain: String::new(),
        path: "/".into(),
        expires: None,
        secure: false,
        http_only: false,
    };
    for attribute in parts {
        let attribute = attribute.trim();
        let (key, val) = match attribute.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim()),
            None => (attribute.to_lowercase(), ""),
        };
        match key.as_str() {
            "domain" => cookie.domain = val.trim_start_matches('.').to_lowercase(),
            "path" => cookie.path = if val.is_empty() { "/".into() } else { val.to_string() },
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "max-age" => {
                if let Ok(seconds) = val.parse::<i64>() {
                    cookie.expires = Some(
                        SystemTime::now()
                            + if seconds >= 0 {
                                Duration::from_secs(seconds as u64)
                            } else {
                                Duration::from_secs(0)
                            },
                    );
                }
            }
            "expires" => cookie.expires = parse_http_date(val),
            _ => {}
        }
    }
    Some(cookie)
}

/// `Set-Cookie2`/`Expires` uses RFC 1123 format: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let cleaned = value.replace(['-', ','], " ");
    let mut tokens: Vec<&str> = cleaned.split_whitespace().collect();
    // `Sun, 06 Nov 1994 ...` starts with a weekday, and the token count alone cannot tell the two
    // forms apart: both "06 Nov 1994 08:49:37 GMT" and "Sun 06 Nov 1994 08:49:37 GMT" are six
    // tokens. The first token decides: a date starts with the day number, a weekday does not parse
    // as one. Getting this wrong left every real Expires header unparsed, so expired cookies were
    // kept for the whole session.
    let starts_with_weekday = tokens
        .first()
        .map(|t| !t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    if starts_with_weekday {
        tokens.remove(0);
    }
    // What is actually required is day, month, year and a time; the weekday and the trailing zone
    // are both optional, so the floor is four tokens rather than six.
    if tokens.len() < 4 {
        return None;
    }
    let day: u64 = tokens[0].parse().ok()?;
    // Month names arrive title-cased ("Nov") while the table is lowercase.
    let month_token = tokens[1].to_ascii_lowercase();
    let month = MONTHS
        .iter()
        .position(|m| month_token.starts_with(m))? as u32
        + 1;
    let year: i64 = tokens[2].parse().ok()?;
    let time: Vec<&str> = tokens[3].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: u64 = time[0].parse().ok()?;
    let minute: u64 = time[1].parse().ok()?;
    let second: u64 = time[2].parse().ok()?;

    // Days from the civil epoch, so the result does not depend on the host time zone.
    let days = days_from_civil(year, month, day);
    let epoch = SystemTime::UNIX_EPOCH;
    epoch
        .checked_add(Duration::from_secs(
            days * 86_400 + hour * 3_600 + minute * 60 + second,
        ))
}

/// Howard Hinnant's civil-date algorithm. Valid for any Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) as u64
}

/// Thread-safe cookie store keyed by host.
#[derive(Default)]
pub struct CookieJar {
    inner: Mutex<HashMap<String, Vec<Cookie>>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a `Set-Cookie` header. The host is used when the cookie names no domain, matching how
    /// a browser treats a host-only cookie.
    pub fn store(&self, host: &str, header: &str) -> Option<Cookie> {
        let mut cookie = parse_set_cookie(header)?;
        if cookie.domain.is_empty() {
            cookie.domain = host.trim_start_matches('.').to_lowercase();
        }
        let mut jar = self.inner.lock().expect("cookie jar is not poisoned");
        let bucket = jar.entry(host.to_lowercase()).or_default();
        bucket.retain(|c| !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path));
        if !cookie.is_expired(SystemTime::now()) {
            bucket.push(cookie.clone());
        }
        Some(cookie)
    }

    /// The cookies that should be sent to `host` for `path` over `secure` transport.
    ///
    /// Every bucket is scanned rather than only the one keyed by `host`: a cookie stored for
    /// `example.test` with `Domain=example.test` must also be sent to `sub.example.test`, so
    /// looking up a single host would silently drop it.
    pub fn for_request(&self, host: &str, path: &str, secure: bool) -> Vec<Cookie> {
        let now = SystemTime::now();
        let jar = self.inner.lock().expect("cookie jar is not poisoned");
        let mut out: Vec<Cookie> = jar
            .values()
            .flatten()
            .filter(|c| {
                !c.is_expired(now)
                    && Cookie::domain_matches(&c.domain, host)
                    && Cookie::path_matches(&c.path, path)
                    && !(c.secure && !secure)
            })
            .cloned()
            .collect();
        // Longer paths first, which is what RFC 6265 asks for.
        out.sort_by(|a, b| b.path.len().cmp(&a.path.len()).then(a.name.cmp(&b.name)));
        out
    }

    /// The `Cookie` header value, or `None` when nothing applies.
    pub fn header(&self, host: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.for_request(host, path, secure);
        if cookies.is_empty() {
            return None;
        }
        Some(
            cookies
                .iter()
                .map(Cookie::pair)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Drops expired cookies. Called opportunistically so a long session does not accumulate them.
    pub fn evict_expired(&self) -> usize {
        let now = SystemTime::now();
        let mut jar = self.inner.lock().expect("cookie jar is not poisoned");
        let mut removed = 0;
        jar.retain(|_, bucket| {
            let before = bucket.len();
            bucket.retain(|c| !c.is_expired(now));
            removed += before - bucket.len();
            !bucket.is_empty()
        });
        removed
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("cookie jar is not poisoned")
            .values()
            .map(Vec::len)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.lock().expect("cookie jar is not poisoned").clear();
    }

    /// Every stored cookie, for display.
    pub fn all(&self) -> Vec<Cookie> {
        self.inner
            .lock()
            .expect("cookie jar is not poisoned")
            .values()
            .flatten()
            .cloned()
            .collect()
    }
}

/// Every `Set-Cookie` header value in a raw HTTP response, in order.
pub fn parse_set_cookie_headers(response: &str) -> Vec<String> {
    response
        .split("\r\n")
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("set-cookie")
                .then(|| value.trim().to_string())
        })
        .collect()
}

/// Inserts or replaces a header line in a raw request, keeping the head/body separator.
pub fn set_header(head: &str, name: &str, value: &str) -> String {
    let (head_part, body) = match head.find("\r\n\r\n") {
        Some(at) => (&head[..at], &head[at..]),
        None => (head, ""),
    };
    let prefix = format!("{}:", name.to_lowercase());
    let replacement = format!("{name}: {value}");
    // Owned strings: a Vec<&str> would borrow temporaries built inside the loop.
    let mut kept: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in head_part.split("\r\n") {
        if line.to_lowercase().starts_with(&prefix) {
            if !replaced {
                kept.push(replacement.clone());
                replaced = true;
            }
            continue;
        }
        kept.push(line.to_string());
    }
    if !replaced {
        kept.push(replacement);
    }
    format!("{}\r\n{}", kept.join("\r\n"), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jar_with(set_cookie: &str, host: &str) -> CookieJar {
        let jar = CookieJar::new();
        jar.store(host, set_cookie);
        jar
    }

    #[test]
    fn a_basic_cookie_round_trips() {
        let jar = jar_with("session=abc123; Path=/", "example.test");
        assert_eq!(jar.header("example.test", "/", false).as_deref(), Some("session=abc123"));
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn a_second_set_cookie_replaces_the_first() {
        let jar = CookieJar::new();
        jar.store("example.test", "session=one; Path=/");
        jar.store("example.test", "session=two; Path=/");
        assert_eq!(jar.header("example.test", "/", false).as_deref(), Some("session=two"));
        assert_eq!(jar.len(), 1, "the old value must be replaced, not kept alongside");
    }

    #[test]
    fn cookies_are_scoped_to_their_domain_and_subdomains() {
        let jar = jar_with("a=1; Domain=example.test", "example.test");
        assert!(jar.header("example.test", "/", false).is_some());
        assert!(jar.header("sub.example.test", "/", false).is_some(), "subdomain must match");
        assert!(jar.header("notexample.test", "/", false).is_none(), "suffix must respect the label");
        assert!(jar.header("evil.test", "/", false).is_none());
    }

    #[test]
    fn cookies_are_scoped_to_their_path() {
        let jar = jar_with("a=1; Path=/admin", "example.test");
        assert!(jar.header("example.test", "/admin", false).is_some());
        assert!(jar.header("example.test", "/admin/x", false).is_some());
        assert!(jar.header("example.test", "/", false).is_none());
        // "/admin" must not match "/administrator": that is not a segment boundary.
        assert!(jar.header("example.test", "/administrator", false).is_none());
    }

    #[test]
    fn a_secure_cookie_is_not_sent_over_plain_http() {
        let jar = jar_with("a=1; Secure", "example.test");
        // The jar has no transport knowledge, so this checks the filter is present and driven by
        // the caller's notion of scheme; https hosts here are matched loosely.
        assert!(jar.header("example.test", "/", true).is_some(), "Secure is sent over https");
        assert!(
            jar.header("example.test", "/", false).is_none(),
            "a Secure cookie must not go out over plain http"
        );
    }

    #[test]
    fn attributes_are_parsed() {
        let cookie = parse_set_cookie(
            "id=7; Domain=.shop.test; Path=/cart; Secure; HttpOnly; SameSite=Lax",
        )
        .expect("parses");
        assert_eq!(cookie.name, "id");
        assert_eq!(cookie.value, "7");
        assert_eq!(cookie.domain, "shop.test");
        assert_eq!(cookie.path, "/cart");
        assert!(cookie.secure);
        assert!(cookie.http_only);
    }

    #[test]
    fn quoted_values_lose_their_quotes() {
        let cookie = parse_set_cookie("t=\"hello world\"").expect("parses");
        assert_eq!(cookie.value, "hello world");
    }

    #[test]
    fn garbage_is_rejected_rather_than_stored() {
        assert!(parse_set_cookie("").is_none());
        assert!(parse_set_cookie("novalue").is_none());
        assert!(parse_set_cookie("=novalue").is_none());
    }

    #[test]
    fn max_age_zero_expires_immediately() {
        let jar = jar_with("a=1; Max-Age=0", "example.test");
        assert!(jar.is_empty(), "Max-Age=0 must not be stored");
        assert!(jar.header("example.test", "/", false).is_none());
    }

    #[test]
    fn expires_dates_are_understood() {
        // 1994 is in the past, so this cookie must not survive.
        let jar = jar_with("a=1; Expires=Sun, 06 Nov 1994 08:49:37 GMT", "example.test");
        assert!(jar.is_empty(), "a past Expires must not be stored");

        let far = parse_set_cookie("a=1; Expires=Sun, 06 Nov 2094 08:49:37 GMT").expect("parses");
        assert!(far.expires.is_some());
        assert!(!far.is_expired(SystemTime::now()));
    }

    #[test]
    fn the_civil_date_helper_matches_known_days() {
        // 1970-01-01 is day 0.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn set_cookie_headers_are_extracted_from_a_response() {
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nContent-Type: text/plain\r\nSet-Cookie: b=2\r\n\r\nbody";
        assert_eq!(parse_set_cookie_headers(response), vec!["a=1; Path=/", "b=2"]);
        assert!(parse_set_cookie_headers("HTTP/1.1 200 OK\r\n\r\n").is_empty());
    }

    #[test]
    fn set_header_inserts_and_replaces() {
        let head = "GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: x\r\n\r\nbody";
        let with = set_header(head, "User-Agent", "gulpsuite");
        assert!(with.contains("User-Agent: gulpsuite"));
        assert!(!with.contains("User-Agent: x"), "the old value must be gone");
        assert_eq!(with.matches("User-Agent").count(), 1);
        assert!(with.ends_with("\r\n\r\nbody"), "the body must survive");

        let added = set_header(head, "Cookie", "a=1");
        assert!(added.contains("Cookie: a=1"));
        assert!(added.ends_with("\r\n\r\nbody"));
    }

    #[test]
    fn expiry_is_evicted_from_the_jar() {
        let jar = CookieJar::new();
        jar.store("example.test", "gone=1; Max-Age=0");
        jar.store("example.test", "kept=1");
        assert_eq!(jar.evict_expired(), 0);
        assert_eq!(jar.len(), 1);
    }
}
