//! The crawler: walk a target from a seed URL, staying inside scope.
//!
//! Link and form extraction are pure functions over the HTML so they can be tested without a
//! network; the walk itself is async and drives them.

use std::collections::HashSet;

use super::active::InjectionPoint;
use super::http::{parse_response, Response};
use super::{Coverage, Finding, Scope};
use crate::proxy::Proxy;

/// What the crawl reports as it goes.
#[derive(Clone, Debug)]
pub enum Progress {
    Fetching(String),
    Skipped { url: String, reason: &'static str },
    Finished { pages: usize, findings: usize },
}

/// Collapses `.` and `..` segments. Without this a crawl emits `/x/../z` URLs, which no server
/// serves and no scope rule matches.
pub fn normalise_path(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

/// Resolves a possibly-relative reference against the page it was found on.
pub fn resolve(base: &str, reference: &str) -> Option<String> {
    // Fragments are client-side only; following them would re-crawl the same page.
    let reference = reference.trim().split('#').next().unwrap_or("").trim();
    if reference.is_empty() || reference.starts_with('#') {
        return None;
    }
    // Not worth crawling, and often not even fetchable.
    if reference.starts_with("mailto:")
        || reference.starts_with("tel:")
        || reference.starts_with("javascript:")
        || reference.starts_with("data:")
    {
        return None;
    }
    if let Some(rest) = reference.strip_prefix("//") {
        let scheme = if base.starts_with("https://") { "https" } else { "http" };
        return Some(format!("{scheme}://{rest}"));
    }
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Some(reference.to_string());
    }
    let Some((scheme, scheme_host)) = base.split_once("://") else {
        return None;
    };
    let authority = scheme_host.split('/').next().unwrap_or(scheme_host);
    let origin = format!("{scheme}://{authority}");
    if reference.starts_with('/') {
        return Some(format!("{origin}{}", normalise_path(reference)));
    }
    let base_path = super::http::path_of(base);
    let directory = match base_path.rfind('/') {
        Some(index) => &base_path[..=index],
        None => "/",
    };
    Some(format!("{origin}{}", normalise_path(&format!("{directory}{reference}"))))
}

/// Pulls every same-document link out of an HTML body.
pub fn links(body: &str, base: &str) -> Vec<String> {
    let mut found = Vec::new();
    let lower = body.to_ascii_lowercase();
    for attribute in ["href=\"", "href='", "src=\"", "src='"] {
        let mut cursor = 0usize;
        while let Some(start) = lower[cursor..].find(attribute) {
            let from = cursor + start + attribute.len();
            let quote = &attribute[attribute.len() - 1..];
            let Some(end) = body[from..].find(quote) else { break };
            let raw = &body[from..from + end];
            cursor = from + end;
            if let Some(url) = resolve(base, raw) {
                found.push(url);
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Pulls every form and its fields out of an HTML body.
pub fn forms(body: &str, base: &str) -> Vec<Vec<(String, String)>> {
    let mut found = Vec::new();
    let lower = body.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(start) = lower[cursor..].find("<form") {
        let from = cursor + start;
        let Some(end) = lower[from..].find("</form>") else { break };
        let chunk = &body[from..from + end];
        cursor = from + end;

        let mut fields = Vec::new();
        let mut at = 0usize;
        while let Some(input_at) = chunk[at..].find("<input") {
            let start = at + input_at;
            let Some(tag_end) = chunk[start..].find('>') else { break };
            let tag = &chunk[start..start + tag_end];
            at = start + tag_end;

            let name = attribute(tag, "name").unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let kind = attribute(tag, "type").unwrap_or_else(|| "text".to_string());
            // Submit buttons and unchecked boxes never carry an interesting value.
            if ["submit", "button", "image", "reset", "file"].contains(&kind.to_ascii_lowercase().as_str()) {
                continue;
            }
            let value = attribute(tag, "value").unwrap_or_default();
            fields.push((name, value));
        }
        if !fields.is_empty() {
            found.push(fields);
        }
    }
    let _ = base;
    found
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{name}=\"");
    let at = lower.find(&needle)? + needle.len();
    let rest = &tag[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Injection points a page offers: query parameters, form fields, and JSON properties,
/// skipping ignored analytics/session parameters from `AuditDefaults.json`.
pub fn injection_points(url: &str, body: &str) -> Vec<InjectionPoint> {
    let mut points = Vec::new();

    let path = super::http::path_of(url);
    if let Some(query) = path.split_once('?').map(|(_, q)| q) {
        for pair in query.split('&') {
            if let Some((name, _)) = pair.split_once('=') {
                let decoded = decode(name);
                if !decoded.is_empty() && !super::active::is_ignored_insertion_point(&decoded) {
                    points.push(InjectionPoint::query(url, &decoded));
                }
            }
        }
    }

    for fields in forms(body, url) {
        for (index, (name, _)) in fields.iter().enumerate() {
            if super::active::is_ignored_insertion_point(name) {
                continue;
            }
            let mut siblings = fields.clone();
            siblings.remove(index);
            let mut point = InjectionPoint::query(url, name);
            point.method = super::active::InjectionMethod::Form;
            point.siblings = siblings;
            points.push(point);
        }
    }

    if body.trim_start().starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(body)
        {
            for key in map.keys().take(8) {
                if !super::active::is_ignored_insertion_point(key) {
                    points.push(InjectionPoint::json_field(url, key));
                }
            }
        }
    }
    points
}

/// Parses `Allow:` and `Disallow:` paths from `/robots.txt` (`CrawlDefaults.json` `request_robots_txt`).
pub fn parse_robots_txt(body: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        for prefix in ["Disallow:", "Allow:", "disallow:", "allow:"] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let path = rest.trim();
                if path.starts_with('/') && !path.contains('*') {
                    if let Some(u) = resolve(base, path) {
                        if !out.contains(&u) {
                            out.push(u);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Parses `<loc>...</loc>` URLs from `/sitemap.xml` (`CrawlDefaults.json` `request_sitemap`).
pub fn parse_sitemap_xml(body: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<loc>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</loc>") else {
            break;
        };
        let raw = after[..end].trim();
        if let Some(u) = resolve(base, raw) {
            if !out.contains(&u) {
                out.push(u);
            }
        }
        rest = &after[end + 6..];
    }
    out
}

fn decode(value: &str) -> String {
    value.replace("+", " ").replace("%20", " ")
}

/// Walks a target, running passive analysis on everything it fetches.
pub async fn crawl(
    seed: &str,
    scope: &Scope,
    proxy: &Proxy,
    on_progress: &(dyn Fn(Progress) + Send + Sync),
) -> Coverage {
    let mut coverage = Coverage::default();
    if !scope.allows(seed) {
        on_progress(Progress::Skipped {
            url: seed.to_string(),
            reason: "seed is outside the scope",
        });
        return coverage;
    }

    let mut queue: Vec<(String, usize)> = vec![(seed.to_string(), 0)];
    let mut seen: HashSet<String> = HashSet::new();

    while let Some((url, depth)) = queue.pop() {
        if seen.len() >= scope.max_pages {
            break;
        }
        // Compare on the URL without its query so a parameterised page is crawled once.
        let key = super::http::path_of(&url);
        if !seen.insert(key) {
            continue;
        }
        if !scope.allows(&url) {
            on_progress(Progress::Skipped {
                url: url.clone(),
                reason: "outside the scope",
            });
            continue;
        }

        on_progress(Progress::Fetching(url.clone()));
        let Some((host, port, tls, raw)) =
            super::active::InjectionPoint::baseline_request(&url)
        else {
            continue;
        };
        let response_text = match proxy.one_shot_secure(&host, port, &raw, tls, 15_000).await {
            Ok((_, text)) => text,
            Err(_) => continue,
        };
        let response: Response = parse_response(&response_text);
        coverage.requests_made += 1;
        coverage.pages.push((url.clone(), response.status));

        // Passive analysis runs on everything fetched, whatever the depth.
        let findings: Vec<Finding> = super::passive::inspect(&url, &response);
        coverage.findings.extend(findings);

        // Only follow links while there is depth left and capacity to use.
        if depth >= scope.max_depth {
            continue;
        }
        if response.status < 200 || response.status >= 400 {
            continue;
        }
        let content_type = response.header("content-type").unwrap_or("");
        if !content_type.contains("html") && !response.body.contains('<') {
            continue;
        }

        for link in links(&response.body, &url) {
            if !seen.contains(&super::http::path_of(&link)) && scope.allows(&link) {
                queue.push((link, depth + 1));
            }
        }
    }

    on_progress(Progress::Finished {
        pages: coverage.pages.len(),
        findings: coverage.findings.len(),
    });
    coverage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_references_resolve_against_the_page() {
        // The last segment of the base is a file, so "z" is a sibling of it, not a child.
        assert_eq!(resolve("http://a.test/x/y", "z").unwrap(), "http://a.test/x/z");
        assert_eq!(resolve("http://a.test/x/y/", "z").unwrap(), "http://a.test/x/y/z");
        assert_eq!(resolve("http://a.test/x/y", "/z").unwrap(), "http://a.test/z");
        // "../z" climbs out of "/x/", landing at the root.
        assert_eq!(resolve("http://a.test/x/y", "../z").unwrap(), "http://a.test/z");
    }

    #[test]
    fn absolute_and_protocol_relative_references_are_kept() {
        assert_eq!(resolve("http://a.test/", "https://b.test/x").unwrap(), "https://b.test/x");
        assert_eq!(resolve("http://a.test/", "//b.test/x").unwrap(), "http://b.test/x");
        assert_eq!(resolve("https://a.test/", "//b.test/x").unwrap(), "https://b.test/x");
    }

    #[test]
    fn references_we_cannot_crawl_are_skipped() {
        for reference in ["mailto:a@b.test", "tel:+1", "javascript:void(0)", "data:text/html,x", "#top", ""] {
            assert!(resolve("http://a.test/", reference).is_none(), "{reference} should be skipped");
        }
    }

    #[test]
    fn fragments_are_stripped_so_a_page_is_crawled_once() {
        assert_eq!(resolve("http://a.test/x/", "y#frag").unwrap(), "http://a.test/x/y");
        assert_eq!(resolve("http://a.test/x", "/y#a").unwrap(), "http://a.test/y");
    }

    #[test]
    fn dot_segments_are_normalised() {
        assert_eq!(normalise_path("/x/y/../z"), "/x/z");
        assert_eq!(normalise_path("/x/./y"), "/x/y");
        assert_eq!(normalise_path("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalise_path("/"), "/");
        assert_eq!(resolve("http://a.test/x/y", "../z").unwrap(), "http://a.test/z");
        assert_eq!(resolve("http://a.test/x/y", "../../z").unwrap(), "http://a.test/z");
    }

    #[test]
    fn links_are_extracted_deduplicated_and_sorted() {
        let body = r#"
            <a href="/one">1</a>
            <a href='/two'>2</a>
            <img src="https://cdn.test/a.png">
            <script src="/app.js"></script>
            <a href="/one">again</a>
        "#;
        let found = links(body, "http://a.test/");
        assert_eq!(
            found,
            vec![
                "http://a.test/app.js".to_string(),
                "http://a.test/one".to_string(),
                "http://a.test/two".to_string(),
                "https://cdn.test/a.png".to_string(),
            ]
        );
    }

    #[test]
    fn a_page_with_no_links_yields_nothing() {
        assert!(links("<p>nothing here</p>", "http://a.test/").is_empty());
    }

    #[test]
    fn form_fields_are_extracted_and_buttons_skipped() {
        let body = r#"<form action="/login" method="post">
            <input type="hidden" name="csrf" value="tok">
            <input type="text" name="user" value="">
            <input type="password" name="pass">
            <input type="submit" name="go" value="Sign in">
            <input type="checkbox" name="remember">
        </form>"#;
        let found = forms(body, "http://a.test/");
        assert_eq!(found.len(), 1);
        let names: Vec<&str> = found[0].iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["csrf", "user", "pass", "remember"], "submit button should be dropped");
    }

    #[test]
    fn forms_without_fields_are_not_reported() {
        assert!(forms(r#"<form action="/search"></form>"#, "http://a.test/").is_empty());
    }

    #[test]
    fn injection_points_cover_query_parameters() {
        let points = injection_points("http://a.test/s?q=1&page=2", "<p>x</p>");
        let names: Vec<&str> = points.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["q", "page"]);
    }

    #[test]
    fn injection_points_cover_form_fields_as_posts() {
        let body = r#"<form method="post"><input name="user"><input name="pass"></form>"#;
        let points = injection_points("http://a.test/login", body);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].method, super::super::active::InjectionMethod::Form);
        assert_eq!(points[0].name, "user");
        assert_eq!(points[0].siblings, vec![("pass".to_string(), String::new())]);
    }

    #[test]
    fn urlencoded_parameter_names_are_decoded() {
        let points = injection_points("http://a.test/s?first%20name=x", "<p>x</p>");
        assert_eq!(points[0].name, "first name");
    }

    #[test]
    fn attribute_parsing_handles_both_quote_styles() {
        assert_eq!(attribute(r#"<input name="a" value="b">"#, "name").unwrap(), "a");
        assert_eq!(attribute(r#"<input name=a>"#, "name"), None);
    }

    #[tokio::test]
    async fn crawl_refuses_a_seed_outside_scope() {
        let (proxy, _events) = Proxy::new();
        let scope = Scope::for_host("example.com");
        let seen = std::sync::Mutex::new(Vec::new());
        let coverage = crawl("http://other.test/", &scope, &proxy, &|event| {
            if let Progress::Skipped { url, .. } = event {
                seen.lock().unwrap().push(url);
            }
        })
        .await;
        assert!(coverage.pages.is_empty());
        assert!(coverage.findings.is_empty());
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}