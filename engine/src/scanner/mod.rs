//! The vulnerability scanner: crawl a target, analyse what comes back, and inject test payloads.
//!
//! Three stages, each usable on its own:
//!   * [`crawler`] walks links and forms from a seed URL within a scope.
//!   * [`passive`] inspects a response that was fetched anyway and reports what it can prove.
//!   * [`active`] sends test payloads into parameters and forms and infers from the difference.
//!
//! Every check reports [`Finding`]s with the evidence that triggered them, because a scanner that
//! cannot show its working is a scanner nobody trusts.

pub mod active;
pub mod crawler;
pub mod http;
pub mod passive;
pub mod retirejs_data;

use std::collections::BTreeMap;

/// How confident we are and how bad it is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// One confirmed issue.
#[derive(Clone, Debug)]
pub struct Finding {
    pub name: String,
    pub severity: Severity,
    /// Where it was found.
    pub url: String,
    /// Which parameter, if any.
    pub parameter: Option<String>,
    /// The literal evidence: a header, a marker echoed back, a file path.
    pub evidence: String,
    /// How the check decided, in words a human can check.
    pub confidence: String,
}

impl Finding {
    pub fn new(
        name: &str,
        severity: Severity,
        url: &str,
        parameter: Option<String>,
        evidence: &str,
        confidence: &str,
    ) -> Self {
        Finding {
            name: name.to_string(),
            severity,
            url: url.to_string(),
            parameter,
            evidence: evidence.to_string(),
            confidence: confidence.to_string(),
        }
    }
}

/// What a crawl or scan has reached so far.
#[derive(Default, Clone)]
pub struct Coverage {
    /// URL -> status code, in discovery order.
    pub pages: Vec<(String, u16)>,
    pub requests_made: usize,
    pub findings: Vec<Finding>,
}

impl Coverage {
    pub fn hosts(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for (url, _) in &self.pages {
            let host = split(url).map(|(h, _)| h).unwrap_or_default();
            *out.entry(host).or_default() += 1;
        }
        out
    }

    pub fn by_severity(&self) -> [(Severity, usize); 4] {
        let mut counts = [(Severity::High, 0), (Severity::Medium, 0), (Severity::Low, 0), (Severity::Info, 0)];
        for finding in &self.findings {
            let slot = counts.iter_mut().find(|(s, _)| *s == finding.severity);
            if let Some(slot) = slot {
                slot.1 += 1;
            }
        }
        counts
    }
}

/// Splits a scope field on commas, whitespace, or newlines, dropping empties.
fn split_entries(text: &str) -> Vec<&str> {
    text.split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// True when `host` is `pattern`, treating a leading `.` as "this host or any subdomain of it".
fn host_matches(host: &str, pattern: &str) -> bool {
    match pattern.strip_prefix('.') {
        Some(base) => host == base || host.ends_with(pattern),
        None => host == pattern,
    }
}

/// Which hosts a scan is allowed to touch.
#[derive(Clone, Debug)]
pub struct Scope {
    /// Hosts (or host prefixes) that are in scope. Empty means "whatever we crawl".
    pub hosts: Vec<String>,
    pub include_subdomains: bool,
    pub max_depth: usize,
    pub max_pages: usize,
    /// Paths that must match, e.g. `/api/`. Empty means every path.
    pub path_prefixes: Vec<String>,
    /// Hosts explicitly out of scope. Checked after the include list, so it always wins.
    pub excluded_hosts: Vec<String>,
    /// Paths explicitly out of scope, e.g. `/logout`. Wins over `path_prefixes`.
    pub excluded_path_prefixes: Vec<String>,
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            hosts: Vec::new(),
            include_subdomains: true,
            max_depth: 3,
            max_pages: 200,
            path_prefixes: Vec::new(),
            excluded_hosts: Vec::new(),
            excluded_path_prefixes: Vec::new(),
        }
    }
}

impl Scope {
    pub fn for_host(host: &str) -> Self {
        Scope {
            hosts: vec![host.to_ascii_lowercase()],
            ..Default::default()
        }
    }

    /// True when the URL is inside the scope. `depth` is checked by the caller against `max_depth`.
    pub fn allows(&self, url: &str) -> bool {
        let Some((host, path)) = split(url) else {
            return false;
        };
        let host = host.to_ascii_lowercase();

        let host_ok = if self.hosts.is_empty() {
            true
        } else if self.include_subdomains {
            self.hosts
                .iter()
                .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        } else {
            self.hosts.iter().any(|allowed| host == *allowed)
        };
        if !host_ok {
            return false;
        }
        // Exclusions are checked before the path includes, so an exclude always beats an include.
        if self.excluded_hosts.iter().any(|denied| host_matches(&host, denied)) {
            return false;
        }
        if self.excluded_path_prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            return false;
        }
        if self.path_prefixes.is_empty() {
            return true;
        }
        self.path_prefixes.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Builds a scope from the Target panel's two free-text fields.
    ///
    /// Entries are separated by commas, whitespace, or newlines. A leading `-.` in the include
    /// list turns off subdomain matching, and a `*` host means "anything not excluded".
    pub fn from_spec(include: &str, exclude: &str, max_depth: usize, max_pages: usize) -> Self {
        let mut scope = Scope { max_depth, max_pages, ..Default::default() };
        for entry in split_entries(include) {
            match entry.strip_prefix("-.host:") {
                Some(rest) => {
                    scope.include_subdomains = false;
                    scope.hosts.push(rest.to_ascii_lowercase());
                }
                None => match entry.strip_prefix("/path:") {
                    Some(rest) => scope.path_prefixes.push(rest.to_ascii_lowercase()),
                    None => scope.hosts.push(entry.to_ascii_lowercase()),
                },
            }
        }
        for entry in split_entries(exclude) {
            match entry.strip_prefix("/path:") {
                Some(rest) => scope.excluded_path_prefixes.push(rest.to_ascii_lowercase()),
                None => scope.excluded_hosts.push(entry.to_ascii_lowercase()),
            }
        }
        if scope.hosts.iter().any(|h| h == "*") {
            scope.hosts.clear();
        }
        scope
    }
}

/// Splits an absolute URL into host and path, ignoring anything malformed.
pub fn split(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let path = rest[authority.len()..].split(['?', '#']).next().unwrap_or("/");
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    Some((host.to_string(), if path.is_empty() { "/".into() } else { path.to_string() }))
}

/// The host and port a request should be dialled on.
pub fn endpoint(url: &str) -> Option<(String, u16, bool)> {
    let tls = url.starts_with("https://");
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), if tls { 443 } else { 80 }),
        },
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    Some((host, port, tls))
}

#[cfg(test)]
#[cfg(test)]
mod scope_tests {
    use super::Scope;

    #[test]
    fn an_include_field_limits_hosts() {
        let scope = Scope::from_spec("example.test", "", 2, 20);
        assert!(scope.allows("http://example.test/a"));
        assert!(scope.allows("http://sub.example.test/a"), "subdomains are included by default");
        assert!(!scope.allows("http://other.test/a"));
    }

    #[test]
    fn a_leading_dash_dot_host_turns_off_subdomains() {
        let scope = Scope::from_spec("-.host:example.test", "", 2, 20);
        assert!(scope.allows("http://example.test/a"));
        assert!(!scope.allows("http://sub.example.test/a"));
    }

    #[test]
    fn an_exclude_field_beats_an_include() {
        let scope = Scope::from_spec("example.test", "admin.example.test", 2, 20);
        assert!(scope.allows("http://example.test/a"));
        assert!(!scope.allows("http://admin.example.test/a"));
    }

    #[test]
    fn path_prefixes_narrow_the_scope() {
        let scope = Scope::from_spec("example.test /path:/api/", "", 2, 20);
        assert!(scope.allows("http://example.test/api/v1"));
        assert!(!scope.allows("http://example.test/secret"));
    }

    #[test]
    fn a_path_exclusion_beats_a_path_include() {
        let scope = Scope::from_spec("example.test /path:/api/", "/path:/api/logout", 2, 20);
        assert!(scope.allows("http://example.test/api/v1"));
        assert!(!scope.allows("http://example.test/api/logout"));
    }

    #[test]
    fn a_star_means_anything_not_excluded() {
        let scope = Scope::from_spec("*", "blocked.test", 2, 20);
        assert!(scope.allows("http://anything.test/a"));
        assert!(!scope.allows("http://blocked.test/a"));
    }

    #[test]
    fn separators_of_any_kind_are_accepted() {
        let scope = Scope::from_spec("a.test, b.test\nc.test\td.test", "", 2, 20);
        for host in ["a.test", "b.test", "c.test", "d.test"] {
            assert!(scope.allows(&format!("http://{host}/x")), "{host} should be in scope");
        }
        assert_eq!(scope.hosts.len(), 4);
    }

    #[test]
    fn an_empty_include_keeps_the_default_behaviour() {
        let scope = Scope::from_spec("", "", 2, 20);
        assert!(scope.hosts.is_empty());
        assert!(scope.allows("http://anything.test/a"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_defaults_to_everything_up_to_the_page_cap() {
        let scope = Scope::default();
        assert!(scope.allows("http://anything.test/x"));
        assert!(scope.allows("https://other.test/"));
    }

    #[test]
    fn scope_respects_host_list() {
        let scope = Scope::for_host("example.com");
        assert!(scope.allows("http://example.com/a"));
        assert!(scope.allows("http://api.example.com/a"), "subdomains included by default");
        assert!(!scope.allows("http://evil.test/a"));
        assert!(!scope.allows("http://notexample.com/a"), "suffix must be a real subdomain");
    }

    #[test]
    fn scope_can_exclude_subdomains() {
        let scope = Scope {
            hosts: vec!["example.com".into()],
            include_subdomains: false,
            ..Default::default()
        };
        assert!(scope.allows("http://example.com/"));
        assert!(!scope.allows("http://api.example.com/"));
    }

    #[test]
    fn scope_can_restrict_paths() {
        let scope = Scope {
            hosts: vec!["example.com".into()],
            path_prefixes: vec!["/api/".into()],
            ..Default::default()
        };
        assert!(scope.allows("http://example.com/api/v1/users"));
        assert!(!scope.allows("http://example.com/admin"));
    }

    #[test]
    fn malformed_urls_are_out_of_scope() {
        let scope = Scope::default();
        assert!(!scope.allows("not-a-url"));
        assert!(!scope.allows("ftp://example.com/x"));
        assert!(!scope.allows("http:///path"));
    }

    #[test]
    fn endpoint_infers_scheme_default_ports() {
        assert_eq!(endpoint("http://a.test/x"), Some(("a.test".into(), 80, false)));
        assert_eq!(endpoint("https://a.test/x"), Some(("a.test".into(), 443, true)));
        assert_eq!(endpoint("http://a.test:8080/x"), Some(("a.test".into(), 8080, false)));
        assert_eq!(endpoint("garbage"), None);
    }

    #[test]
    fn split_returns_host_and_path() {
        let (host, path) = split("https://a.test:8443/x/y?z=1").unwrap();
        assert_eq!(host, "a.test");
        assert_eq!(path, "/x/y");
        assert_eq!(split("https://a.test").unwrap().1, "/");
    }

    #[test]
    fn severity_orders_from_info_to_high() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn coverage_groups_by_host_and_severity() {
        let mut coverage = Coverage::default();
        coverage.pages.push(("http://a.test/1".into(), 200));
        coverage.pages.push(("http://a.test/2".into(), 404));
        coverage.pages.push(("http://b.test/".into(), 200));
        coverage.findings.push(Finding::new(
            "x",
            Severity::High,
            "http://a.test/1",
            None,
            "",
            "",
        ));
        assert_eq!(coverage.hosts().len(), 2);
        assert_eq!(coverage.hosts()["a.test"], 2);
        assert_eq!(coverage.by_severity()[0], (Severity::High, 1));
    }
}