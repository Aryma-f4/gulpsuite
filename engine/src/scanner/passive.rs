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

/// Inspects one response and returns everything it proves.
pub fn inspect(url: &str, response: &Response) -> Vec<Finding> {
    let mut findings = Vec::new();
    let body = &response.body;

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
/// matches a known vulnerable release.
fn version_disclosure(url: &str, response: &Response) -> Vec<Finding> {
    let mut found = Vec::new();
    for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"] {
        if let Some(value) = response.header(header) {
            let looks_like_version = value
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .any(|part| {
                    let digits = part.chars().filter(|c| c.is_ascii_digit()).count();
                    let dots = part.chars().filter(|c| *c == '.').count();
                    digits >= 2 && (dots == 0 || dots >= 1)
                });
            if looks_like_version {
                let cve_note = lookup_server_cves(value);
                let (sev, explain) = if let Some(cves) = cve_note {
                    (
                        Severity::Medium,
                        format!(
                            "Exact software version matches known vulnerabilities ({cves})."
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
    found
}

/// Matches a server/runtime version banner against known high-impact CVEs.
pub fn lookup_server_cves(banner: &str) -> Option<&'static str> {
    let b = banner.to_ascii_lowercase();
    if b.contains("apache/2.4.49") {
        Some("CVE-2021-41773 (Path traversal & RCE, CWE-22)")
    } else if b.contains("apache/2.4.50") {
        Some("CVE-2021-42013 (Path traversal & RCE bypass, CWE-22)")
    } else if b.contains("apache/2.4.")
        && b.split("apache/2.4.")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|patch| patch < 52)
    {
        Some("CVE-2021-44790 / CVE-2021-44224 (Apache 2.4 < 2.4.52)")
    } else if b.contains("openssl/1.0.1") {
        Some("CVE-2014-0160 (Heartbleed TLS memory disclosure, CWE-125)")
    } else if b.contains("php/8.1.0-dev") {
        Some("Backdoored PHP 8.1.0-dev User-Agentt RCE")
    } else if b.contains("php/5.") || b.contains("php/7.0") || b.contains("php/7.1") || b.contains("php/7.2") {
        Some("CVE-2019-11043 (PHP-FPM buffer underflow RCE, CWE-787)")
    } else if b.contains("nginx/1.18.") || b.contains("nginx/1.16.") || b.contains("nginx/1.14.") {
        Some("CVE-2021-23017 (nginx resolver off-by-one heap write, CWE-193)")
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

/// Burp Suite Pro's Retire.js Vulnerable JavaScript Dependency CVE Engine
/// (`resources/RetireJS/retirejs_repository.json`, `005009a0_VulnerableJsDependency`).
/// Extracts `<script src="...">` filenames and inline `/*! Library vX.Y.Z` banners, compares
/// `(major, minor, patch)` against `below` / `atOrAbove` ranges, and reports exact CVE, GHSA, and CWE IDs.
pub fn vulnerable_js_dependencies(url: &str, body: &str) -> Vec<Finding> {
    struct JsVulnRule {
        library: &'static str,
        patterns: &'static [&'static str],
        below: (u32, u32, u32),
        at_or_above: Option<(u32, u32, u32)>,
        severity: Severity,
        cves: &'static str,
        cwe: &'static str,
        summary: &'static str,
    }

    const RULES: &[JsVulnRule] = &[
        JsVulnRule {
            library: "jquery",
            patterns: &["jquery-", "jquery/", "jquery.min.js?v=", "/*! jquery v"],
            below: (1, 9, 0),
            at_or_above: None,
            severity: Severity::Medium,
            cves: "CVE-2020-7656, CVE-2012-6708, CVE-2011-4969 (GHSA-q4m3-2j7h-f7xw)",
            cwe: "CWE-79",
            summary: "Selector interpreted as HTML & load() XSS in jQuery < 1.9.0.",
        },
        JsVulnRule {
            library: "jquery",
            patterns: &["jquery-", "jquery/", "jquery.min.js?v=", "/*! jquery v"],
            below: (3, 5, 0),
            at_or_above: Some((1, 9, 0)),
            severity: Severity::Medium,
            cves: "CVE-2020-11022, CVE-2020-11023, CVE-2019-11358 (GHSA-gxr4-xjj5-5px2)",
            cwe: "CWE-79, CWE-1321",
            summary: "htmlPrefilter XSS & Object.prototype pollution in jQuery < 3.5.0.",
        },
        JsVulnRule {
            library: "lodash",
            patterns: &["lodash-", "lodash/", "lodash.min.js?v=", "lodash v"],
            below: (4, 17, 21),
            at_or_above: None,
            severity: Severity::High,
            cves: "CVE-2021-23337, CVE-2020-8203, CVE-2019-10744 (GHSA-35jh-r3h4-6jhm)",
            cwe: "CWE-78, CWE-1321",
            summary: "Command injection via template() and prototype pollution in lodash < 4.17.21.",
        },
        JsVulnRule {
            library: "bootstrap",
            patterns: &["bootstrap-", "bootstrap/", "/*! bootstrap v"],
            below: (4, 3, 1),
            at_or_above: None,
            severity: Severity::Medium,
            cves: "CVE-2019-8331, CVE-2018-14040, CVE-2018-14042 (GHSA-9v3m-8fp8-mj99)",
            cwe: "CWE-79",
            summary: "XSS in data-template, data-content, and tooltip/popover attributes in Bootstrap < 4.3.1.",
        },
        JsVulnRule {
            library: "angular",
            patterns: &["angular-", "angular/", "angularjs/", "/*! angularjs v"],
            below: (1, 8, 0),
            at_or_above: None,
            severity: Severity::Medium,
            cves: "CVE-2022-25869, CVE-2020-7676 (GHSA-5cp4-xmrw-59wf)",
            cwe: "CWE-79",
            summary: "XSS and sandbox escape in AngularJS < 1.8.0.",
        },
        JsVulnRule {
            library: "moment",
            patterns: &["moment-", "moment/", "moment.min.js?v="],
            below: (2, 29, 4),
            at_or_above: None,
            severity: Severity::High,
            cves: "CVE-2022-31129, CVE-2022-24785 (GHSA-wc69-rhjr-hc9g)",
            cwe: "CWE-22, CWE-1333",
            summary: "Path traversal in moment.locale and inefficient regex complexity in Moment.js < 2.29.4.",
        },
        JsVulnRule {
            library: "handlebars",
            patterns: &["handlebars-", "handlebars/", "handlebars.min.js?v="],
            below: (4, 7, 7),
            at_or_above: None,
            severity: Severity::High,
            cves: "CVE-2021-23369, CVE-2021-23383, CVE-2019-19919 (GHSA-f2jv-r9rf-7988)",
            cwe: "CWE-94, CWE-1321",
            summary: "Remote code execution and prototype pollution when compiling templates in Handlebars < 4.7.7.",
        },
        JsVulnRule {
            library: "dompurify",
            patterns: &["dompurify-", "dompurify/", "purify.min.js?v="],
            below: (2, 4, 0),
            at_or_above: None,
            severity: Severity::Medium,
            cves: "CVE-2022-25887, CVE-2021-23358",
            cwe: "CWE-79",
            summary: "Mutation XSS (mXSS) bypass in DOMPurify < 2.4.0.",
        },
        JsVulnRule {
            library: "axios",
            patterns: &["axios-", "axios/", "axios.min.js?v="],
            below: (0, 21, 2),
            at_or_above: None,
            severity: Severity::Medium,
            cves: "CVE-2021-3749, CVE-2020-28168 (GHSA-cph5-m8f7-6c5x)",
            cwe: "CWE-918, CWE-1333",
            summary: "SSRF redirect bypass and ReDoS in axios < 0.21.2.",
        },
    ];

    let mut found = Vec::new();
    let lower = body.to_ascii_lowercase();
    let url_lower = url.to_ascii_lowercase();

    for rule in RULES {
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
                    if ver_str.contains('.') {
                        Some(ver_str)
                    } else {
                        None
                    }
                });

            if let Some(ver_str) = extracted_ver {
                if let Some(ver) = parse_semver(&ver_str) {
                    let above_ok = rule.at_or_above.map_or(true, |min_v| ver >= min_v);
                    if above_ok && ver < rule.below {
                        let evidence = format!(
                            "{} {} (vulnerable < {}.{}.{}): {}",
                            rule.library,
                            ver_str,
                            rule.below.0,
                            rule.below.1,
                            rule.below.2,
                            rule.cves
                        );
                        let dup = found
                            .iter()
                            .any(|f: &Finding| f.evidence == evidence);
                        if !dup {
                            found.push(Finding::new(
                                "Vulnerable JavaScript dependency",
                                rule.severity,
                                url,
                                Some(format!("{} {}", rule.library, ver_str)),
                                &evidence,
                                &format!("{} ({}) — https://nvd.nist.gov/", rule.summary, rule.cwe),
                            ));
                        }
                    }
                }
            }
        }
    }
    found
}

/// Static JavaScript DOM taint analysis (`auditing.html#javascript-analysis-phase`):
/// Detects attacker-controllable DOM sources (`location.search`, `location.hash`, `document.referrer`,
/// `window.name`) flowing into dangerous DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`,
/// `location.href`, `location.replace`).
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
    let Some(&src) = SOURCES.iter().find(|&&s| lower.contains(s)) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Some(&sink) = XSS_SINKS.iter().find(|&&k| lower.contains(k)) {
        found.push(Finding::new(
            "Cross-site scripting (DOM-based)",
            Severity::High,
            url,
            Some(src.to_string()),
            &format!("DOM source `{src}` reaches sink `{sink}`"),
            "Static JavaScript AST/taint analysis detected an untrusted DOM source flowing into an HTML/code execution sink (CWE-79, Type 0x00200320).",
        ));
    }
    if let Some(&sink) = REDIRECT_SINKS.iter().find(|&&k| lower.contains(k)) {
        found.push(Finding::new(
            "Open redirection (DOM-based)",
            Severity::Medium,
            url,
            Some(src.to_string()),
            &format!("DOM source `{src}` reaches navigation sink `{sink}`"),
            "Static JavaScript taint analysis detected an untrusted DOM source controlling a navigation sink (CWE-601, Type 0x00500120).",
        ));
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

            // Ignore HTML attributes (`name="password="`, `<input`) or URL query links (`?password=&`)
            let prefix = &lower_body[index.saturating_sub(16)..index];
            if prefix.contains("name=")
                || prefix.contains("type=")
                || prefix.contains("placeholder=")
                || prefix.contains("href=")
                || prefix.contains("action=")
            {
                continue;
            }
            let rest = &body[after_eq..];
            let candidate: String = rest
                .trim_start_matches(['"', '\''])
                .chars()
                .take_while(|c| {
                    !c.is_whitespace() && !matches!(c, '"' | '\'' | '&' | '<' | '>' | ';' | ',' | ')')
                })
                .collect();
            let cand_low = candidate.to_ascii_lowercase();
            let alnum_count = candidate.chars().filter(|c| c.is_ascii_alphanumeric()).count();
            if alnum_count < 4
                || matches!(
                    cand_low.as_str(),
                    "null" | "undefined" | "true" | "false" | "none" | "password" | "secret"
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
        if ["todo", "fixme", "password", "secret", "api key", "hack", "temp", "remove before"]
            .iter()
            .any(|hint| cl.contains(hint))
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
