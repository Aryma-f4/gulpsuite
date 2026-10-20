//! Connection identity shared by manually sent HTTP requests.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTarget {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl HttpTarget {
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("Target is missing a host".into());
        }
        if input.starts_with(['/', '?', '#']) {
            return Err("Target must include a host, not just a request path".into());
        }
        let address = if input.contains("://") {
            input.to_owned()
        } else {
            format!("http://{input}")
        };
        let url = url::Url::parse(&address).map_err(|error| format!("Invalid target: {error}"))?;
        let secure = match url.scheme() {
            "http" => false,
            "https" => true,
            _ => return Err("Target must use HTTP or HTTPS".into()),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err("Put credentials in the request, not the target address".into());
        }
        let host = match url.host() {
            Some(url::Host::Domain(host)) => host.to_owned(),
            Some(url::Host::Ipv4(host)) => host.to_string(),
            Some(url::Host::Ipv6(host)) => host.to_string(),
            None => return Err("Target is missing a host".into()),
        };
        let port = url
            .port_or_known_default()
            .ok_or("Target is missing a port")?;
        if port == 0 {
            return Err("Target port must be between 1 and 65535".into());
        }
        Ok(Self { host, port, secure })
    }

    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == if self.secure { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

pub fn request_url(raw: &str, secure: bool) -> Result<String, String> {
    let head = crate::analysis::split_message(raw).0;
    let target = head
        .split_whitespace()
        .nth(1)
        .ok_or("Request is missing a target")?;
    if target.to_ascii_lowercase().starts_with("http://")
        || target.to_ascii_lowercase().starts_with("https://")
    {
        HttpTarget::parse(target)?;
        return Ok(target.to_owned());
    }
    let authority = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or("Request is missing a Host header")?;
    let address = format!("{}://{authority}", if secure { "https" } else { "http" });
    HttpTarget::parse(&address)?;
    Ok(format!(
        "{address}{}",
        if target == "*" { "/" } else { target }
    ))
}
