//! Content discovery: probe a bounded path list against hosts the proxy has already seen.
//!
//! Burp's Discover crawls a starting URL and reports what answers. This takes the hosts already in
//! the proxy history and requests a small fixed set of paths against each, through the same
//! `one_shot` path the scanner uses, so probes show up in the history like any other traffic.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::proxy::Proxy;

/// Ceiling on the whole run, so a large history cannot turn Discover into a flood.
pub const MAX_PROBES: usize = 200;
/// Per-request timeout.
pub const TIMEOUT_MS: u64 = 8_000;

/// One answered probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub url: String,
    pub status: u16,
    /// Bytes of the response body that were read.
    pub length: usize,
}

/// What a run reports back to the caller as it goes.
#[derive(Clone, Debug)]
pub enum Update {
    Probing { host: String, done: usize, total: usize },
    Found(Finding),
    Done { probes: usize },
}

/// Splits a free-text path list into paths, dropping blanks and duplicates.
pub fn paths_from(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let path = if line.starts_with('/') { line.to_string() } else { format!("/{line}") };
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// Extracts the distinct authorities from proxy history.
///
/// The port is kept: two services on the same machine are two different things to probe, and the
/// proxy records `host` as `host:port` already.
pub fn hosts_from(targets: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for target in targets {
        // Drop the scheme first: splitting the whole value on '/' would leave "http:".
        let rest = target.split_once("://").map(|(_, r)| r).unwrap_or(target.as_str());
        let authority = rest.split('/').next().unwrap_or("");
        // Trim any userinfo, but keep the port.
        let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
        if authority.is_empty() {
            continue;
        }
        if seen.insert(authority.to_string()) {
            out.push(authority.to_string());
        }
    }
    out
}

/// The URLs a run would request, capped at `MAX_PROBES`. Exposed so the count can be shown up front.
pub fn plan(hosts: &[String], paths: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    'outer: for host in hosts {
        for path in paths {
            if out.len() >= MAX_PROBES {
                break 'outer;
            }
            out.push(format!("http://{host}{path}"));
        }
    }
    out
}

/// Probes every planned URL, reporting through `on_update` as it goes.
pub async fn probe(
    proxy: Arc<Proxy>,
    urls: Vec<String>,
    on_update: &(dyn Fn(Update) + Send + Sync),
) {
    let total = urls.len();
    let mut probes = 0usize;
    for (index, url) in urls.into_iter().enumerate() {
        if let Some((host, _path)) = crate::scanner::split(&url) {
            on_update(Update::Probing { host, done: index, total });
        }
        // `endpoint` is the host and port to dial, so a probe hits exactly the path asked for with
        // no injected parameter bolted on.
        let Some((host, port, tls)) = crate::scanner::endpoint(&url) else {
            continue;
        };
        let raw = crate::scanner::http::build_get(&url, &host, port, tls, None);
        let Ok((_, text)) = proxy.one_shot_secure(&host, port, &raw, tls, TIMEOUT_MS).await else {
            continue;
        };
        probes += 1;
        let response = crate::scanner::http::parse_response(&text);
        on_update(Update::Found(Finding {
            url,
            status: response.status,
            length: response.body.len(),
        }));
    }
    on_update(Update::Done { probes });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalised_and_deduplicated() {
        let paths = paths_from("/robots.txt\nadmin\n/robots.txt\n\n  /x  ");
        assert_eq!(paths, vec!["/robots.txt", "/admin", "/x"]);
    }

    #[test]
    fn authorities_keep_their_port_and_are_deduplicated() {
        let targets = vec![
            "http://a.test/x".to_string(),
            "http://a.test/x".to_string(),
            // A different port is a different service, so it is kept as its own entry.
            "a.test:8080".to_string(),
            "https://b.test".to_string(),
            "http://".to_string(),
            "http://user:pw@c.test/x".to_string(),
        ];
        assert_eq!(
            hosts_from(targets.into_iter()),
            vec!["a.test", "a.test:8080", "b.test", "c.test"]
        );
    }

    #[test]
    fn the_plan_crosses_hosts_with_paths() {
        let hosts = vec!["a.test".to_string(), "b.test".to_string()];
        let paths = vec!["/x".to_string(), "/y".to_string()];
        assert_eq!(
            plan(&hosts, &paths),
            vec![
                "http://a.test/x",
                "http://a.test/y",
                "http://b.test/x",
                "http://b.test/y"
            ]
        );
    }

    #[test]
    fn the_plan_is_capped() {
        let hosts: Vec<String> = (0..100).map(|i| format!("h{i}.test")).collect();
        let paths = vec!["/x".to_string(), "/y".to_string(), "/z".to_string()];
        assert_eq!(plan(&hosts, &paths).len(), MAX_PROBES);
    }

    #[test]
    fn an_empty_history_plans_nothing() {
        assert!(plan(&[], &["/x".to_string()]).is_empty());
    }
}
