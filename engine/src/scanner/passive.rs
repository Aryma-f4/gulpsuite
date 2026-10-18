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
    findings.extend(stack_trace(url, body));
    findings.extend(secrets(url, body));
    findings.extend(paths_disclosed(url, body));
    findings.extend(directory_listing(url, response));
    findings.extend(cors(url, response));
    findings.extend(mixed_content(url, body));
    findings.extend(comments(url, body));
    findings.extend(open_redirect(url, response));

    findings
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

/// Server and framework version banners.
fn version_disclosure(url: &str, response: &Response) -> Vec<Finding> {
    let mut found = Vec::new();
    for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"] {
        if let Some(value) = response.header(header) {
            // Only a version banner is worth reporting; "Server: cloudflare" is not.
            // "nginx/1.24.0" and "PHP/5.4.1" both carry a dotted numeric version; "cloudflare"
            // and "Microsoft-IIS" do not.
            let looks_like_version = value
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .any(|part| {
                    let digits = part.chars().filter(|c| c.is_ascii_digit()).count();
                    let dots = part.chars().filter(|c| *c == '.').count();
                    digits >= 2 && (dots == 0 || dots >= 1)
                });
            if looks_like_version {
                found.push(Finding::new(
                    &format!("Version disclosure via {header}"),
                    Severity::Info,
                    url,
                    None,
                    &format!("{header}: {value}"),
                    "Exact software version lets an attacker match known flaws.",
                ));
            }
        }
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
    for (needle, severity) in PATTERNS {
        let mut at = body.to_ascii_lowercase().find(&needle.to_ascii_lowercase());
        while let Some(index) = at {
            let evidence = body
                [index..]
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
            at = body.to_ascii_lowercase()[index + needle.len()..].find(&needle.to_ascii_lowercase())
                .map(|next| next + index + needle.len());
        }
    }
    // AWS access key ids are distinctive enough to look for on their own.
    if body.contains("AKIA") {
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
    found
}

/// Absolute filesystem paths leaking build layout.
fn paths_disclosed(url: &str, body: &str) -> Vec<Finding> {
    const MARKERS: [&str; 5] = ["/home/", "/Users/", "C:\\Windows", "/var/www", "/usr/lib/"]; // code
    let mut found = Vec::new();
    for marker in MARKERS {
        if let Some(index) = body.find(marker) {
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
}
