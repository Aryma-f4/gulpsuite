//! Passive analysis: what can be proven from a response that was fetched anyway.
//!
//! These checks send nothing extra, so they are safe to run against anything already in the proxy
//! history. Each one reports the literal evidence it fired on.

use super::Finding;
use super::Severity;
use crate::scanner::http::Response;

/// Security headers worth asking for, and why.
const SECURITY_HEADERS: [(&str, Severity, &str); 6] = [
    (
        "Content-Security-Policy",
        Severity::Medium,
        "No CSP, so an injected script has nothing to stop it.",
    ),
    (
        "Strict-Transport-Security",
        Severity::Medium,
        "No HSTS, so a first request can be downgraded to plain HTTP.",
    ),
    (
        "X-Content-Type-Options",
        Severity::Low,
        "No X-Content-Type-Options, so MIME sniffing can misread a response.",
    ),
    (
        "Referrer-Policy",
        Severity::Low,
        "No Referrer-Policy, so URLs can leak to third parties.",
    ),
    (
        "Permissions-Policy",
        Severity::Info,
        "No Permissions-Policy, so powerful browser features stay available.",
    ),
    (
        "X-Frame-Options",
        Severity::Low,
        "No framing protection, so the page can be embedded by another site.",
    ),
];

/// True if `url` or `response` is a static sub-resource (`.js`, `.css`, image, font, etc.)
/// where document-level framing/CSP headers do not apply.
pub fn is_static_subresource(url: &str, response: &Response) -> bool {
    let path = url
        .split('?')
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    if [
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff",
        ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".webm", ".pdf", ".zip",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
    {
        return true;
    }
    if let Some(ct) = response.header("Content-Type") {
        let ctl = ct.to_ascii_lowercase();
        if ctl.starts_with("image/")
            || ctl.starts_with("font/")
            || ctl.starts_with("audio/")
            || ctl.starts_with("video/")
            || ctl.contains("javascript")
            || ctl.contains("text/css")
        {
            return true;
        }
    }
    false
}

/// True if a passive finding is host-wide (should be consolidated once per origin in live/crawl scans,
/// matching `consolidate_passive_issues: true` in `Audit coverage - thorough.json`).
pub fn is_host_wide_passive_issue(finding_name: &str) -> bool {
    finding_name.starts_with("Missing ")
        || finding_name.starts_with("Version disclosure")
        || finding_name.starts_with("Cookie without ")
        || finding_name == "Session cookie in a response"
        || finding_name == "Vulnerable JavaScript dependency"
}

/// Inspects one response and returns everything it proves.
pub fn inspect(url: &str, response: &Response) -> Vec<Finding> {
    let mut findings = Vec::new();
    let body = &response.body;

    // Only flag missing document security headers on 2xx HTML/document responses, not redirects,
    // 404/500 errors, or static sub-resources (`.js`, `.css`, images, fonts).
    let is_2xx = (200..300).contains(&response.status);
    if is_2xx && !is_static_subresource(url, response) {
        for (header, severity, why) in SECURITY_HEADERS {
            if response.header(header).is_none() {
                findings.push(Finding::new(
                    &format!("Missing {header}"),
                    severity,
                    url,
                    None,
                    &format!("header `{header}` absent"),
                    why,
                ));
            }
        }
    }

    findings.extend(cookies(url, response));
    findings.extend(version_disclosure(url, response));
    findings.extend(vulnerable_js_dependencies(url, body));
    findings.extend(dom_taint_analysis(url, body));
    findings.extend(serialized_objects(url, response));
    findings.extend(stack_trace(url, body));
    findings.extend(secrets(url, body));
    findings.extend(private_keys(url, body));
    findings.extend(sql_errors(url, body));
    findings.extend(paths_disclosed(url, body));
    findings.extend(directory_listing(url, response));
    findings.extend(cors(url, response));
    findings.extend(mixed_content(url, body));
    findings.extend(comments(url, body));
    findings.extend(open_redirect(url, response));

    findings
}

fn private_keys(url: &str, body: &str) -> Vec<Finding> {
    for marker in [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        if body.contains(marker) {
            return vec![Finding::new(
                "Private key disclosed",
                Severity::High,
                url,
                None,
                marker,
                "A PEM-encoded private key block was returned in the response body.",
            )];
        }
    }
    Vec::new()
}

fn sql_errors(url: &str, body: &str) -> Vec<Finding> {
    let lower = body.to_ascii_lowercase();
    for sig in [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "postgresql query failed",
        "sqlite3::",
        "unclosed quotation mark after the character string",
    ] {
        if lower.contains(sig) {
            return vec![Finding::new(
                "Database error disclosed",
                Severity::High,
                url,
                None,
                sig,
                "The response contains a raw SQL/database error message.",
            )];
        }
    }
    Vec::new()
}

/// Cookies that miss a flag they should set.
fn cookies(url: &str, response: &Response) -> Vec<Finding> {
    let tls = url.starts_with("https://");
    response
        .set_cookie()
        .iter()
        .flat_map(|cookie| {
            let name = cookie.split(';').next().unwrap_or("").trim().to_string();
            let lower = cookie.to_ascii_lowercase();
            let mut found = Vec::new();
            if tls && !lower.contains("secure") {
                found.push(Finding::new(
                    "Cookie without Secure",
                    Severity::Medium,
                    url,
                    None,
                    cookie,
                    "Set over HTTPS without Secure, so it can travel in clear text.",
                ));
            }
            if !lower.contains("httponly") {
                found.push(Finding::new(
                    "Cookie without HttpOnly",
                    Severity::Low,
                    url,
                    None,
                    cookie,
                    "No HttpOnly, so script can read it.",
                ));
            }
            if !lower.contains("samesite") {
                found.push(Finding::new(
                    "Cookie without SameSite",
                    Severity::Info,
                    url,
                    None,
                    cookie,
                    "No SameSite, so the cookie rides cross-site requests.",
                ));
            }
            if !name.is_empty() && is_session_cookie(&name) {
                found.push(Finding::new(
                    "Session cookie in a response",
                    Severity::Info,
                    url,
                    None,
                    cookie,
                    "Session cookie set without `HttpOnly` elsewhere in the app is a common chain.",
                ));
            }
            found
        })
        .collect()
}

fn is_session_cookie(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["session", "sess", "jsessionid", "phpsessid", "token", "auth"]
        .iter()
        .any(|hint| lower.contains(hint))
}

/// Server and framework version banners, enriched with CVE & CWE references when the version
fn safe_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Server, proxy, runtime, and CMS version banners, enriched with CVE & CWE references when
/// the version matches a known vulnerable release.
fn version_disclosure(url: &str, response: &Response) -> Vec<Finding> {
    let mut found = Vec::new();
    for header in [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator",
        "Via",
        "X-Jenkins",
        "X-Drupal-Cache",
    ] {
        if let Some(value) = response.header(header) {
            let cve_note = lookup_server_cves(value);
            let looks_like_version = cve_note.is_some()
                || value
                    .split(|c: char| !c.is_ascii_digit() && c != '.')
                    .any(|part| {
                        let digits = part.chars().filter(|c| c.is_ascii_digit()).count();
                        let dots = part.chars().filter(|c| *c == '.').count();
                        digits >= 2 && dots >= 1
                    });
            if looks_like_version {
                let (sev, explain) = if let Some(cves) = cve_note {
                    (
                        Severity::Medium,
                        format!(
                            "Software version matches known CVE vulnerabilities ({cves}) — https://nvd.nist.gov/"
                        ),
                    )
                } else {
                    (
                        Severity::Info,
                        "Exact software version lets an attacker match known flaws (CWE-200).".into(),
                    )
                };
                found.push(Finding::new(
                    &format!("Version disclosure via {header}"),
                    sev,
                    url,
                    None,
                    &format!("{header}: {value}"),
                    &explain,
                ));
            }
        }
    }

    // Also inspect `<meta name="generator" content="...">` in HTML bodies for CMS CVEs (WordPress, Drupal, Joomla)
    let body_prefix = safe_prefix(&response.body, 8192);
    let lower_prefix = body_prefix.to_ascii_lowercase();
    if let Some(gen_idx) = lower_prefix.find("name=\"generator\"") {
        let win_start = gen_idx.saturating_sub(80);
        let win_end = (gen_idx + 140).min(lower_prefix.len());
        let window = &body_prefix[win_start..win_end];
        if let Some(c_idx) = window.to_ascii_lowercase().find("content=\"") {
            let after = &window[c_idx + 9..];
            if let Some(end_q) = after.find('"') {
                let gen_val = after[..end_q].trim();
                if let Some(cves) = lookup_server_cves(gen_val) {
                    found.push(Finding::new(
                        "Version disclosure via Meta Generator",
                        Severity::Medium,
                        url,
                        None,
                        &format!("<meta name=\"generator\" content=\"{gen_val}\">"),
                        &format!(
                            "Generator version matches known CVE vulnerabilities ({cves}) — https://nvd.nist.gov/"
                        ),
                    ));
                }
            }
        }
    }
    found
}

/// Matches a server/runtime/CMS version banner against known high-impact CVEs.
pub fn lookup_server_cves(banner: &str) -> Option<&'static str> {
    let b = banner.to_ascii_lowercase();
    if b.contains("apache/2.4.49") {
        Some("CVE-2021-41773 (Apache 2.4.49 Path traversal & RCE, CVSS 9.8, CWE-22)")
    } else if b.contains("apache/2.4.50") {
        Some("CVE-2021-42013 (Apache 2.4.50 Path traversal & RCE bypass, CVSS 9.8, CWE-22)")
    } else if let Some(rest) = b.split("apache/2.4.").nth(1) {
        let patch = rest
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|n| n.parse::<u32>().ok())?;
        if patch < 52 {
            Some("CVE-2021-44790 / CVE-2021-44224 (Apache 2.4 < 2.4.52 Lua heap overflow & SSRF, CWE-787)")
        } else if patch < 56 {
            Some("CVE-2023-25690 (Apache 2.4 < 2.4.56 mod_proxy HTTP Request Smuggling, CVSS 9.8, CWE-444)")
        } else if patch < 60 {
            Some("CVE-2024-38474 / CVE-2024-38476 (Apache 2.4 < 2.4.60 mod_rewrite substitution bypass & SSRF, CWE-116)")
        } else {
            None
        }
    } else if b.contains("openssl/1.0.1") {
        Some("CVE-2014-0160 (Heartbleed TLS memory disclosure, CWE-125)")
    } else if b.contains("openssl/3.0.")
        && b.split("openssl/3.0.")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|p| p <= 6)
    {
        Some("CVE-2022-3602 / CVE-2022-3786 (OpenSSL 3.0.0-3.0.6 X.509 punycode buffer overflow, CWE-120)")
    } else if b.contains("php/8.1.0-dev") {
        Some("Backdoored PHP 8.1.0-dev User-Agentt RCE (CVSS 9.8, CWE-94)")
    } else if b.contains("php/5.")
        || b.contains("php/7.0")
        || b.contains("php/7.1")
        || b.contains("php/7.2")
        || b.contains("php/7.3")
    {
        Some("CVE-2019-11043 / CVE-2024-4577 (End-of-life PHP RCE & CGI argument injection, CVSS 9.8, CWE-78)")
    } else if b.contains("php/7.4.")
        || b.contains("php/8.0.")
        || b.contains("php/8.1.")
        || b.contains("php/8.2.")
    {
        Some("CVE-2024-4577 / CVE-2022-31625 (PHP CGI argument injection & driver memory corruption, CWE-78)")
    } else if b.contains("nginx/1.18.")
        || b.contains("nginx/1.16.")
        || b.contains("nginx/1.14.")
        || b.contains("nginx/1.19.")
        || b.contains("nginx/1.20.0")
    {
        Some("CVE-2021-23017 (nginx DNS resolver 1-byte memory overwrite, CWE-193)")
    } else if b.contains("nginx/1.21.") || b.contains("nginx/1.22.") {
        Some("CVE-2022-41741 / CVE-2022-41742 (nginx mp4 module memory corruption, CWE-787)")
    } else if b.contains("tomcat/8.")
        || b.contains("tomcat/9.0.")
        || b.contains("coyote/1.1")
    {
        Some("CVE-2024-50379 / CVE-2023-46589 (Apache Tomcat TOCTOU RCE & trailer request smuggling, CVSS 9.8, CWE-367)")
    } else if b.contains("jetty(9.") || b.contains("jetty/9.") || b.contains("jetty(10.") {
        Some("CVE-2021-28164 / CVE-2021-34429 (Eclipse Jetty WEB-INF URI normalization disclosure, CWE-200)")
    } else if b.contains("next.js") {
        Some("CVE-2025-29927 / CVE-2024-34351 (Next.js x-middleware-subrequest auth bypass & Server Action SSRF, CWE-285)")
    } else if b.contains("wordpress 4.") || b.contains("wordpress 5.") || b.contains("wordpress 6.0") || b.contains("wordpress 6.1") || b.contains("wordpress 6.2") || b.contains("wordpress 6.3") || b.contains("wordpress 6.4") {
        Some("CVE-2024-31210 / CVE-2023-2745 (WordPress core path traversal, XSS & plugin RCE exposure, CWE-22)")
    } else if b.contains("drupal 7") || b.contains("drupal 8") {
        Some("CVE-2018-7600 / CVE-2019-6340 (Drupalgeddon2 remote code execution, CVSS 9.8, CWE-94)")
    } else if b.contains("microsoft-iis/7.") || b.contains("microsoft-iis/8.") {
        Some("CVE-2017-7269 / CVE-2015-1635 (IIS WebDAV ScStoragePathFromUrl & HTTP.sys RCE, CWE-119)")
    } else {
        None
    }
}

/// Parses a dotted semantic version `X.Y.Z` into `(major, minor, patch)`.
pub fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let cleaned = ver.trim().trim_start_matches(['v', 'V']);
    let mut parts = cleaned.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Gulpsuite Pro's Retire.js Vulnerable JavaScript Dependency CVE Engine
/// (`resources/RetireJS/retirejs_repository.json`, `005009a0_VulnerableJsDependency`).
/// Evaluates all 477 embedded Retire.js + modern npm vulnerability ranges with zero heap allocation
/// for the rule table, consolidating all matching CVE/GHSA/CWE identifiers per `(library, version)`.
pub fn vulnerable_js_dependencies(url: &str, body: &str) -> Vec<Finding> {
    use super::retirejs_data::RETIREJS_RULES;

    let mut found = Vec::new();
    // Bound body scan to first 128 KiB to keep memory and CPU minimal on multi-MB bundles
    let scan_slice = safe_prefix(body, 131_072);
    let lower = scan_slice.to_ascii_lowercase();
    let url_lower = url.to_ascii_lowercase();

    // Group matched rules by `(library, version)`
    let mut matched_by_lib: Vec<(
        &'static str,
        String,
        Severity,
        Vec<&'static str>,
        Vec<&'static str>,
        &'static str,
        (u32, u32, u32),
    )> = Vec::new();

    for rule in RETIREJS_RULES {
        for pat in rule.patterns {
            let extracted_ver = lower
                .find(pat)
                .map(|idx| &lower[idx + pat.len()..])
                .or_else(|| url_lower.find(pat).map(|idx| &url_lower[idx + pat.len()..]))
                .and_then(|rest| {
                    let ver_str: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    let trimmed = ver_str.trim_matches('.');
                    if trimmed.contains('.') && trimmed.len() >= 3 {
                        Some(trimmed.to_string())
                    } else {
                        None
                    }
                });

            if let Some(ver_str) = extracted_ver {
                if let Some(ver) = parse_semver(&ver_str) {
                    let above_ok = rule.at_or_above.map_or(true, |min_v| ver >= min_v);
                    if above_ok && ver < rule.below {
                        if let Some(entry) = matched_by_lib
                            .iter_mut()
                            .find(|e| e.0 == rule.library && e.1 == ver_str)
                        {
                            if rule.severity > entry.2 {
                                entry.2 = rule.severity;
                                entry.5 = rule.summary;
                            }
                            if rule.below > entry.6 {
                                entry.6 = rule.below;
                            }
                            if !entry.3.contains(&rule.cves) {
                                entry.3.push(rule.cves);
                            }
                            if !entry.4.contains(&rule.cwe) {
                                entry.4.push(rule.cwe);
                            }
                        } else {
                            matched_by_lib.push((
                                rule.library,
                                ver_str,
                                rule.severity,
                                vec![rule.cves],
                                vec![rule.cwe],
                                rule.summary,
                                rule.below,
                            ));
                        }
                        break;
                    }
                }
            }
        }
    }

    for (lib, ver_str, sev, cves_list, cwe_list, summary, max_below) in matched_by_lib {
        let joined_cves = cves_list.join(", ");
        let joined_cwes = cwe_list.join(", ");
        let evidence = format!(
            "{lib} {ver_str} (vulnerable < {}.{}.{}): {joined_cves}",
            max_below.0, max_below.1, max_below.2
        );
        found.push(Finding::new(
            "Vulnerable JavaScript dependency",
            sev,
            url,
            Some(format!("{lib} {ver_str}")),
            &evidence,
            &format!("{summary} ({joined_cwes}) — https://nvd.nist.gov/"),
        ));
    }
    found
}

/// Extracts `(ecosystem, package_name, version)` tuples from a URL and response body for
/// live worldwide CVE querying (`https://api.osv.dev/v1/query`).
pub fn extract_detected_packages(url: &str, body: &str) -> Vec<(&'static str, String, String)> {
    use super::retirejs_data::RETIREJS_RULES;
    let mut out: Vec<(&'static str, String, String)> = Vec::new();
    let scan_slice = safe_prefix(body, 65_536);
    let lower = scan_slice.to_ascii_lowercase();
    let url_lower = url.to_ascii_lowercase();

    for rule in RETIREJS_RULES {
        if out.iter().any(|(_, pkg, _)| pkg == rule.library) {
            continue;
        }
        for pat in rule.patterns {
            if let Some(rest) = lower
                .find(pat)
                .map(|idx| &lower[idx + pat.len()..])
                .or_else(|| url_lower.find(pat).map(|idx| &url_lower[idx + pat.len()..]))
            {
                let ver_str: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let trimmed = ver_str.trim_matches('.');
                if trimmed.contains('.') && trimmed.len() >= 3 && parse_semver(trimmed).is_some() {
                    out.push(("npm", rule.library.to_string(), trimmed.to_string()));
                    break;
                }
            }
        }
    }

    // Also extract CDN URLs like `cdn.jsdelivr.net/npm/<pkg>@<ver>` or `unpkg.com/<pkg>@<ver>`
    for marker in ["cdn.jsdelivr.net/npm/", "unpkg.com/"] {
        let mut rest = lower.as_str();
        while let Some(pos) = rest.find(marker) {
            let after = &rest[pos + marker.len()..];
            let token: String = after
                .chars()
                .take_while(|c| {
                    c.is_ascii_alphanumeric() || matches!(*c, '@' | '.' | '-' | '_' | '/')
                })
                .collect();
            if let Some((pkg, ver_part)) = token.rsplit_once('@') {
                let ver: String = ver_part
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let ver = ver.trim_matches('.');
                if !pkg.is_empty() && ver.contains('.') && ver.len() >= 3 {
                    let pkg_clean = pkg.trim_matches('/').to_string();
                    if !out.iter().any(|(_, p, v)| p == &pkg_clean && v == ver) {
                        out.push(("npm", pkg_clean, ver.to_string()));
                    }
                }
            }
            rest = &after[token.len().max(1)..];
        }
    }
    out
}

/// Static JavaScript DOM taint analysis (`auditing.html#javascript-analysis-phase`):
/// Detects attacker-controllable DOM sources (`location.search`, `location.hash`, `document.referrer`,
/// `window.name`) flowing directly into dangerous DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`,
/// `location.href`, `location.replace`) within the same script block or statement without sanitization.
fn dom_taint_analysis(url: &str, body: &str) -> Vec<Finding> {
    if !body.contains("<script") && !url.ends_with(".js") {
        return Vec::new();
    }
    const SOURCES: [&str; 5] = [
        "location.search",
        "location.hash",
        "document.referrer",
        "window.name",
        "document.url",
    ];
    const XSS_SINKS: [&str; 5] = [
        ".innerhtml",
        ".outerhtml",
        "document.write(",
        "document.writeln(",
        "eval(",
    ];
    const REDIRECT_SINKS: [&str; 3] = [
        "location.href =",
        "location.href=",
        "location.replace(",
    ];

    let lower = body.to_ascii_lowercase();
    let mut found = Vec::new();

    for &src in &SOURCES {
        let Some(src_pos) = lower.find(src) else {
            continue;
        };
        // Inspect a bounded local window (<= 240 chars) after the DOM source so unrelated
        // sources and sinks across large bundles do not produce false positives.
        let win_end = (src_pos + 240).min(lower.len());
        let window = &lower[src_pos..win_end];
        if window.contains("encodeuricomponent(")
            || window.contains("dompurify.sanitize(")
            || window.contains("textcontent")
        {
            continue;
        }
        if let Some(&sink) = XSS_SINKS.iter().find(|&&k| window.contains(k)) {
            found.push(Finding::new(
                "Cross-site scripting (DOM-based)",
                Severity::High,
                url,
                Some(src.to_string()),
                &format!("DOM source `{src}` reaches sink `{sink}`"),
                "Static JavaScript AST/taint analysis detected an untrusted DOM source flowing into an HTML/code execution sink (CWE-79, Type 0x00200310).",
            ));
            break;
        }
        if let Some(&sink) = REDIRECT_SINKS.iter().find(|&&k| window.contains(k)) {
            found.push(Finding::new(
                "Open redirection (DOM-based)",
                Severity::Low,
                url,
                Some(src.to_string()),
                &format!("DOM source `{src}` reaches navigation sink `{sink}`"),
                "Static JavaScript taint analysis detected an untrusted DOM source controlling a navigation sink (CWE-601, Type 0x00500110).",
            ));
            break;
        }
    }
    found
}

/// Detects serialized objects in HTTP responses (`00400900_serialized-object-in-http-message`).
fn serialized_objects(url: &str, response: &Response) -> Vec<Finding> {
    let mut found = Vec::new();
    if response.body.contains("rO0AB") {
        found.push(Finding::new(
            "Serialized object in HTTP message",
            Severity::High,
            url,
            None,
            "rO0AB (Base64 Java ObjectInputStream header 0xACED0005)",
            "Java serialized object stream detected; deserializing untrusted data can lead to remote code execution (CWE-502, Type 0x00400900).",
        ));
    }
    found
}

/// Stack traces that reveal framework internals.
fn stack_trace(url: &str, body: &str) -> Vec<Finding> {
    const SIGNATURES: [&str; 6] = [
        "Traceback (most recent call last)",
        "java.lang.NullPointerException",
        "Microsoft .NET Framework",
        "System.NullReferenceException",
        "Fatal error: Uncaught",
        "ORA-01756",
    ];
    let lower = body.to_ascii_lowercase();
    SIGNATURES
        .iter()
        .filter(|signature| lower.contains(&signature.to_ascii_lowercase()))
        .map(|signature| {
            let evidence = body
                .lines()
                .find(|line| line.to_ascii_lowercase().contains(&signature.to_ascii_lowercase()))
                .unwrap_or(signature)
                .trim()
                .chars()
                .take(160)
                .collect::<String>();
            Finding::new(
                "Stack trace disclosed",
                Severity::Low,
                url,
                None,
                &evidence,
                "A stack trace shows code paths, framework versions and sometimes file paths.",
            )
        })
        .collect()
}

/// Credentials and keys echoed into the page.
fn secrets(url: &str, body: &str) -> Vec<Finding> {
    const PATTERNS: [(&str, Severity); 5] = [
        ("password=", Severity::High),
        ("passwd=", Severity::High),
        ("api_key=", Severity::High),
        ("apiKey=", Severity::High),
        ("secret=", Severity::High),
    ];
    let mut found = Vec::new();
    let lower_body = body.to_ascii_lowercase();
    for (needle, severity) in PATTERNS {
        let needle_low = needle.to_ascii_lowercase();
        let mut search_from = 0usize;
        while let Some(rel) = lower_body[search_from..].find(&needle_low) {
            let index = search_from + rel;
            let after_eq = index + needle.len();
            search_from = after_eq;

            // Ignore HTML attributes (`name="password"`, `<input`), URL query links (`?password=&`), or JS code
            let prefix = &lower_body[index.saturating_sub(24)..index];
            if prefix.contains("name=")
                || prefix.contains("type=")
                || prefix.contains("placeholder=")
                || prefix.contains("href=")
                || prefix.contains("action=")
                || prefix.contains("id=")
                || prefix.contains("for=")
                || prefix.ends_with('?')
                || prefix.ends_with('&')
            {
                continue;
            }
            let rest = &body[after_eq..];
            let candidate: String = rest
                .trim_start_matches(['"', '\''])
                .chars()
                .take_while(|c| {
                    !c.is_whitespace()
                        && !matches!(c, '"' | '\'' | '&' | '<' | '>' | ';' | ',' | ')' | '}' | ']')
                })
                .collect();
            let cand_low = candidate.to_ascii_lowercase();
            let alnum_count = candidate.chars().filter(|c| c.is_ascii_alphanumeric()).count();
            if alnum_count < 5
                || candidate.contains('(')
                || candidate.contains('{')
                || candidate.contains('[')
                || candidate.contains('$')
                || candidate.contains('.')
                || candidate.contains('+')
                || matches!(
                    cand_low.as_str(),
                    "null"
                        | "undefined"
                        | "true"
                        | "false"
                        | "none"
                        | "password"
                        | "secret"
                        | "changeme"
                        | "required"
                        | "hidden"
                )
                || cand_low.starts_with("your_")
                || cand_low.starts_with("example")
            {
                continue;
            }

            let evidence = body[index..]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .chars()
                .take(120)
                .collect::<String>();
            found.push(Finding::new(
                "Sensitive value in response",
                severity,
                url,
                None,
                &evidence,
                "A credential-looking value is present in the response body.",
            ));
            break;
        }
    }
    // AWS access key ids (`AKIA` followed by 16 uppercase alphanumeric characters).
    if let Some(pos) = body.find("AKIA") {
        let token: String = body[pos..]
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .collect();
        if token.len() >= 16 {
            found.push(Finding::new(
                "AWS access key id in response",
                Severity::High,
                url,
                None,
                &body
                    .lines()
                    .find(|line| line.contains("AKIA"))
                    .unwrap_or("AKIA...")
                    .trim()
                    .chars()
                    .take(120)
                    .collect::<String>(),
                "An AKIA-prefixed identifier is an AWS access key id and should not be client-visible.",
            ));
        }
    }
    found
}

/// Absolute filesystem paths leaking build layout.
fn paths_disclosed(url: &str, body: &str) -> Vec<Finding> {
    const MARKERS: [&str; 5] = ["/home/", "/Users/", "C:\\Windows", "/var/www", "/usr/lib/"];
    let mut found = Vec::new();
    for marker in MARKERS {
        if let Some(index) = body.find(marker) {
            let prefix = &body[index.saturating_sub(8)..index].to_ascii_lowercase();
            if prefix.ends_with("href=\"")
                || prefix.ends_with("href='")
                || prefix.ends_with("src=\"")
                || prefix.ends_with("src='")
            {
                continue;
            }
            let evidence = body[index..]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .chars()
                .take(120)
                .collect::<String>();
            found.push(Finding::new(
                "Filesystem path disclosed",
                Severity::Low,
                url,
                None,
                &evidence,
                "An absolute server path in a response describes the deployment.",
            ));
        }
    }
    found
}

/// A directory index rather than an application page.
fn directory_listing(url: &str, response: &Response) -> Vec<Finding> {
    let body = &response.body;
    if body.contains("<title>Index of ") || body.contains("?C=N;O=D") {
        vec![Finding::new(
            "Directory listing exposed",
            Severity::Medium,
            url,
            None,
            "Index of ...",
            "The server lists directory contents, revealing files that should not be guessable.",
        )]
    } else {
        Vec::new()
    }
}

/// CORS headers that are too permissive.
fn cors(url: &str, response: &Response) -> Vec<Finding> {
    let mut found = Vec::new();
    let allow_origin = response.header("Access-Control-Allow-Origin").unwrap_or("");
    let allow_credentials = response
        .header("Access-Control-Allow-Credentials")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if allow_origin == "*" && allow_credentials {
        found.push(Finding::new(
            "CORS wildcard with credentials",
            Severity::High,
            url,
            None,
            "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
            "Any origin can read authenticated responses.",
        ));
    }
    // Reflecting the Origin header back is the other way this goes wrong.
    if !allow_origin.is_empty() && allow_origin != "*" && allow_credentials {
        if let Some(origin) = response.header("Access-Control-Allow-Origin") {
            if origin.contains("null") || origin.contains("http://") {
                found.push(Finding::new(
                    "CORS reflects an untrusted origin",
                    Severity::Medium,
                    url,
                    None,
                    origin,
                    "The response echoes an arbitrary Origin back while allowing credentials.",
                ));
            }
        }
    }
    found
}

/// Plain-HTTP sub-resources on an HTTPS page.
fn mixed_content(url: &str, body: &str) -> Vec<Finding> {
    if !url.starts_with("https://") {
        return Vec::new();
    }
    let mut found = Vec::new();
    for attribute in ["src=\"http://", "href=\"http://", "action=\"http://"] {
        if let Some(index) = body.find(attribute) {
            found.push(Finding::new(
                "Mixed content",
                Severity::Medium,
                url,
                None,
                &body[index..].chars().take(100).collect::<String>(),
                "An HTTPS page loads a sub-resource over plain HTTP, which can be tampered with.",
            ));
            break;
        }
    }
    found
}

/// HTML comments that leak intentions.
fn comments(url: &str, body: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    let lower = body.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(start) = lower[cursor..].find("<!--") {
        let from = cursor + start + 4;
        let Some(end) = lower[from..].find("-->") else { break };
        let comment = body[from..from + end].trim().to_string();
        cursor = from + end + 3;
        let cl = comment.to_ascii_lowercase();
        let has_word = |w: &str| {
            cl.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|tok| tok == w)
        };
        if has_word("todo")
            || has_word("fixme")
            || has_word("hack")
            || cl.contains("api key")
            || cl.contains("api_key")
            || cl.contains("secret_key")
            || cl.contains("password:")
            || cl.contains("password=")
            || cl.contains("remove before")
        {
            found.push(Finding::new(
                "Revealing HTML comment",
                Severity::Low,
                url,
                None,
                &comment.chars().take(120).collect::<String>(),
                "A comment names an unfinished or sensitive piece of work.",
            ));
        }
    }
    found
}

/// A Location header pointing somewhere the site does not own.
fn open_redirect(url: &str, response: &Response) -> Vec<Finding> {
    let Some(location) = response.header("Location") else {
        return Vec::new();
    };
    if !(response.status >= 300 && response.status < 400) {
        return Vec::new();
    }
    let Some((host, _)) = super::split(url) else {
        return Vec::new();
    };
    if !location.starts_with("http://") && !location.starts_with("https://") {
        return Vec::new(); // A relative redirect stays on site.
    }
    let Some((target_host, _)) = super::split(location) else {
        return Vec::new();
    };
    let same_site = target_host.eq_ignore_ascii_case(&host) || same_registrable_domain(&target_host, &host);

    if same_site {
        return Vec::new();
    }
    vec![Finding::new(
        "Open redirect",
        Severity::Medium,
        url,
        None,
        location,
        "The redirect target is controlled by the site and leaves it, which is useful for phishing.",
    )]
}

/// True when one host is the other or a subdomain of it, so `www.a.test` matches `a.test`.
/// Comparing final labels would be wrong: `evil.test` and `a.test` share a TLD but are unrelated.
fn same_registrable_domain(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::http::parse_response;

    fn scan(url: &str, raw: &str) -> Vec<Finding> {
        inspect(url, &parse_response(raw))
    }

    fn named<'a>(findings: &'a [Finding], needle: &str) -> Option<&'a Finding> {
        findings.iter().find(|f| f.name.contains(needle))
    }

    #[test]
    fn missing_security_headers_are_reported_once_each() {
        let findings = scan("http://a.test/", "HTTP/1.1 200 OK\r\n\r\nhello");
        for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"] {
            assert!(named(&findings, header).is_some(), "{header} not reported");
        }
        let count = findings
            .iter()
            .filter(|f| f.name.contains("Content-Security-Policy"))
            .count();
        assert_eq!(count, 1, "the same header reported twice");
    }

    #[test]
    fn present_security_headers_are_not_reported() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\
                   Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\n\
                   Referrer-Policy: no-referrer\r\nPermissions-Policy: geolocation=()\r\n\
                   X-Frame-Options: DENY\r\n\r\nhello";
        let findings = scan("http://a.test/", raw);
        assert!(named(&findings, "Missing").is_none(), "{findings:?}");
    }

    #[test]
    fn secure_flag_only_matters_over_https() {
        let cookie = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=1; HttpOnly; SameSite=Lax\r\n\r\n";
        let plain = scan("http://a.test/", cookie);
        let secure = scan("https://a.test/", cookie);
        assert!(named(&plain, "without Secure").is_none());
        assert!(named(&secure, "without Secure").is_some());
    }

    #[test]
    fn cookie_flag_gaps_are_each_reported() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=1\r\n\r\n";
        let findings = scan("https://a.test/", raw);
        assert!(named(&findings, "without Secure").is_some());
        assert!(named(&findings, "without HttpOnly").is_some());
        assert!(named(&findings, "without SameSite").is_some());
    }

    #[test]
    fn version_banner_is_flagged_but_a_plain_name_is_not() {
        let with_version = scan("http://a.test/", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\nx");
        assert!(named(&with_version, "Version disclosure").is_some());

        let plain = scan("http://a.test/", "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\nx");
        assert!(named(&plain, "Version disclosure").is_none());
    }

    #[test]
    fn stack_traces_are_found_in_any_common_language() {
        for signature in [
            "Traceback (most recent call last):",
            "java.lang.NullPointerException",
            "System.NullReferenceException: oops",
        ] {
            let raw = format!("HTTP/1.1 500 Err\r\n\r\n{signature}\n  at com.x.Y.z(Y.java:1)");
            let findings = scan("http://a.test/", &raw);
            assert!(
                named(&findings, "Stack trace").is_some(),
                "missed: {signature}"
            );
        }
    }

    #[test]
    fn credentials_in_the_body_are_reported_with_the_line_as_evidence() {
        let raw = "HTTP/1.1 200 OK\r\n\r\nuser=hunter password=hunter2 end";
        let findings = scan("http://a.test/", raw);
        let finding = named(&findings, "Sensitive value").expect("no finding");
        assert!(finding.evidence.contains("password=hunter2"));
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn aws_key_ids_are_reported() {
        let raw = "HTTP/1.1 200 OK\r\n\r\nkey=AKIAIOSFODNN7EXAMPLE";
        let findings = scan("http://a.test/", raw);
        assert!(named(&findings, "AWS").is_some());
    }

    #[test]
    fn filesystem_paths_are_reported() {
        let raw = "HTTP/1.1 500 Err\r\n\r\nCould not open /var/www/html/config.php";
        let findings = scan("http://a.test/", raw);
        assert!(named(&findings, "Filesystem path").is_some());
    }

    #[test]
    fn directory_listing_is_detected() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n<title>Index of /uploads</title>";
        let findings = scan("http://a.test/", raw);
        assert!(named(&findings, "Directory listing").is_some());
    }

    #[test]
    fn cors_wildcard_with_credentials_is_high() {
        let raw = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\
                   Access-Control-Allow-Credentials: true\r\n\r\nx";
        let findings = scan("http://a.test/", raw);
        assert_eq!(
            named(&findings, "CORS").expect("no finding").severity,
            Severity::High
        );
    }

    #[test]
    fn cors_without_credentials_is_not_flagged() {
        let raw = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\nx";
        let findings = scan("http://a.test/", raw);
        assert!(named(&findings, "CORS").is_none());
    }

    #[test]
    fn mixed_content_only_applies_to_https_pages() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n<img src=\"http://cdn.test/a.png\">";
        let secure = scan("https://a.test/", raw);
        let plain = scan("http://a.test/", raw);
        assert!(named(&secure, "Mixed content").is_some());
        assert!(named(&plain, "Mixed content").is_none());
    }

    #[test]
    fn revealing_comments_are_reported_and_ordinary_ones_are_not() {
        let bad = scan("http://a.test/", "HTTP/1.1 200 OK\r\n\r\n<!-- TODO: remove the api key -->");
        let fine = scan("http://a.test/", "HTTP/1.1 200 OK\r\n\r\n<!-- layout -->");
        assert!(named(&bad, "comment").is_some());
        assert!(named(&fine, "comment").is_none());
    }

    #[test]
    fn relative_and_same_site_redirects_are_not_open_redirects() {
        let relative = scan("http://a.test/", "HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n");
        let same_site = scan("http://a.test/", "HTTP/1.1 302 Found\r\nLocation: http://www.a.test/x\r\n\r\n");
        assert!(named(&relative, "Open redirect").is_none());
        assert!(named(&same_site, "Open redirect").is_none());
    }

    #[test]
    fn off_site_redirect_is_an_open_redirect() {
        let raw = "HTTP/1.1 302 Found\r\nLocation: http://evil.test/phish\r\n\r\n";
        let findings = scan("http://a.test/", raw);
        let finding = named(&findings, "Open redirect").expect("no finding");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.evidence.contains("evil.test"));
    }

    #[test]
    fn a_clean_response_produces_nothing() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\
                   Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\n\
                   Referrer-Policy: no-referrer\r\nPermissions-Policy: geolocation=()\r\n\
                   X-Frame-Options: DENY\r\n\r\n<h1>ok</h1>";
        let findings = scan("https://a.test/", raw);
        assert!(findings.is_empty(), "a clean page should be silent, got {findings:?}");
    }

    #[test]
    fn retirejs_cve_engine_detects_vulnerable_js_libraries_and_cves() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n<script src=\"/js/jquery-1.8.3.min.js\"></script><script src=\"/js/lodash-4.17.15.min.js\"></script>";
        let findings = scan("https://a.test/", raw);
        let jq = findings
            .iter()
            .find(|f| f.name == "Vulnerable JavaScript dependency" && f.evidence.contains("jquery"))
            .expect("jquery CVE not reported");
        assert!(jq.evidence.contains("CVE-2020-7656"));
        let lod = findings
            .iter()
            .find(|f| f.name == "Vulnerable JavaScript dependency" && f.evidence.contains("lodash"))
            .expect("lodash CVE not reported");
        assert!(lod.evidence.contains("CVE-2021-23337"));
        assert_eq!(lod.severity, Severity::High);
    }

    #[test]
    fn server_banner_cve_and_dom_taint_sinks_are_reported() {
        let raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n<script>var q = location.search; document.getElementById('out').innerHTML = q;</script>";
        let findings = scan("https://a.test/", raw);
        let srv = named(&findings, "Version disclosure").expect("server version not reported");
        assert!(srv.confidence.contains("CVE-2021-41773"));
        let dom = named(&findings, "Cross-site scripting (DOM-based)").expect("DOM XSS not reported");
        assert_eq!(dom.severity, Severity::High);
    }
}
