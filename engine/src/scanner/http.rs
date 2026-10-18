//! Just enough HTTP to crawl and analyse: parse a response, build a request.

/// A parsed response: status, headers, body.
#[derive(Clone, Debug, Default)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn set_cookie(&self) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.clone())
            .collect()
    }
}

/// Splits a raw response into status, headers and body. Tolerates a bare body with no head.
pub fn parse_response(raw: &str) -> Response {
    let normalised = raw.replace("\r\n", "\n");
    let (head, body) = match normalised.find("\n\n") {
        Some(at) => (&normalised[..at], normalised[at + 2..].to_string()),
        None => (normalised.as_str(), String::new()),
    };
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().unwrap_or("");
    let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.next().unwrap_or("").trim().to_string();

    let mut headers = Vec::new();
    let mut last: Option<usize> = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
            last = Some(headers.len() - 1);
        } else if let Some(index) = last.filter(|i| *i < headers.len()) {
            // Obsolete line folding: a continuation belongs to the previous header.
            headers[index].1.push(' ');
            headers[index].1.push_str(line.trim());
        }
    }
    Response { status, reason, headers, body }
}

/// Builds a `GET` request for an absolute URL, appending a parameter when one is given.
pub fn build_get(url: &str, host: &str, port: u16, tls: bool, parameter: Option<(&str, &str)>) -> String {
    let path = path_of(url);
    let host_header = host_header(host, port, tls);
    let target = match parameter {
        Some((name, value)) => {
            let separator = if path.contains('?') { '&' } else { '?' };
            format!("{path}{separator}{name}={}", encode(value))
        }
        None => path,
    };
    format!("GET {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n")
}

/// The `Host` header value, carrying the port only when it is not the scheme default.
fn host_header(host: &str, port: u16, tls: bool) -> String {
    let default_port = if tls { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// The path and query of an absolute URL, defaulting to `/`.
pub fn path_of(url: &str) -> String {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let tail = &rest[authority.len()..];
    let path = tail.split('#').next().unwrap_or("");
    // A request target must be origin-form: it always starts with "/", so "http://a.test?q=1"
    // has to become "/?q=1" rather than "?q=1".
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Percent-encodes a value for use in a query string or form body.
pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Builds a `POST` with a urlencoded form body.
pub fn build_post(
    url: &str,
    host: &str,
    port: u16,
    tls: bool,
    fields: &[(String, String)],
) -> String {
    let path = path_of(url);
    let host_header = host_header(host, port, tls);
    let body: String = fields
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_headers_and_body() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nX-A: 1\r\n\r\n<h1>nope</h1>";
        let response = parse_response(raw);
        assert_eq!(response.status, 404);
        assert_eq!(response.reason, "Not Found");
        assert_eq!(response.header("content-type"), Some("text/html"));
        assert_eq!(response.header("X-A"), Some("1"));
        assert_eq!(response.body, "<h1>nope</h1>");
    }

    #[test]
    fn folds_multi_line_headers() {
        let raw = "HTTP/1.1 200 OK\r\nX-Long: one\r\n  two\r\n\r\nbody";
        let response = parse_response(raw);
        assert_eq!(response.header("x-long"), Some("one two"));
    }

    #[test]
    fn a_body_with_no_head_does_not_panic() {
        let response = parse_response("just a body");
        assert_eq!(response.status, 0);
        assert!(response.body.is_empty());
    }

    #[test]
    fn extracts_every_set_cookie() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
        assert_eq!(parse_response(raw).set_cookie().len(), 2);
    }

    #[test]
    fn path_keeps_query_and_drops_fragment() {
        assert_eq!(path_of("http://a.test/x/y?z=1#frag"), "/x/y?z=1");
        assert_eq!(path_of("https://a.test"), "/");
        assert_eq!(path_of("http://a.test?q=1"), "/?q=1");
    }

    #[test]
    fn get_request_omits_the_port_when_it_is_the_default() {
        let plain = build_get("http://a.test/x", "a.test", 80, false, None);
        assert!(plain.starts_with("GET /x HTTP/1.1\r\n"));
        assert!(plain.contains("Host: a.test\r\n"));
        assert!(plain.ends_with("\r\n\r\n"));

        let secure = build_get("https://a.test/x", "a.test", 443, true, None);
        assert!(secure.contains("Host: a.test\r\n"));

        let custom = build_get("http://a.test/x", "a.test", 8080, false, None);
        assert!(custom.contains("Host: a.test:8080\r\n"));
    }

    #[test]
    fn get_request_appends_a_parameter_with_the_right_separator() {
        let clean = build_get("http://a.test/search", "a.test", 80, false, Some(("q", "hello world")));
        assert!(clean.starts_with("GET /search?q=hello%20world HTTP/1.1"));

        let existing = build_get("http://a.test/s?a=1", "a.test", 80, false, Some(("q", "2")));
        assert!(existing.starts_with("GET /s?a=1&q=2 HTTP/1.1"));
    }

    #[test]
    fn post_request_has_a_matching_content_length() {
        let body = vec![("q".to_string(), "a b".to_string())];
        let request = build_post("http://a.test/s", "a.test", 80, false, &body);
        let (head, encoded) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("POST /s HTTP/1.1"));
        assert!(head.contains(&format!("Content-Length: {}", encoded.len())));
        assert_eq!(encoded, "q=a%20b");
    }

    #[test]
    fn encoding_leaves_unreserved_characters_alone() {
        assert_eq!(encode("aZ0-_.~"), "aZ0-_.~");
        assert_eq!(encode("a b&c"), "a%20b%26c");
    }
}