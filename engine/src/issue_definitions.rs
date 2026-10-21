//! Complete vulnerability Knowledge Base (183 Issue Definitions).
//!
//! Provides every issue definition (`type_index`, `type_hex`, `name`, `severity`,
//! `description`, `remediation`, `references`, and `classifications`) for
//! `Target -> Issue definitions`, `Target -> Issues`, `Dashboard -> Issue activity`,
//! and the manual issue creator.

use std::sync::LazyLock;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IssueReference {
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IssueDefinition {
    pub type_index: u32,
    pub type_hex: String,
    pub name: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<IssueReference>,
    #[serde(default)]
    pub classifications: Vec<IssueReference>,
}

impl IssueDefinition {
    /// Returns a concise comma-separated list of CWE / CAPEC identifiers (e.g. `"CWE-77, CWE-78"`).
    pub fn cwe_summary(&self) -> String {
        let ids: Vec<&str> = self
            .classifications
            .iter()
            .map(|c| {
                c.title
                    .split(':')
                    .next()
                    .unwrap_or(c.title.as_str())
                    .trim()
            })
            .filter(|s| !s.is_empty())
            .collect();
        if ids.is_empty() {
            "—".into()
        } else {
            ids.join(", ")
        }
    }
}

static DEFINITIONS: LazyLock<Vec<IssueDefinition>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("issue_definitions.json"))
        .expect("valid embedded issue_definitions.json")
});

/// Returns the complete 183-entry vulnerability Knowledge Base.
pub fn all() -> &'static [IssueDefinition] {
    &DEFINITIONS
}

/// Finds the closest matching `IssueDefinition` by exact, substring, or canonical alias issue name.
pub fn find_by_name(name: &str) -> Option<&'static IssueDefinition> {
    let needle = name.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return None;
    }
    if let Some(exact) = DEFINITIONS
        .iter()
        .find(|d| d.name.to_ascii_lowercase() == needle)
    {
        return Some(exact);
    }
    if let Some(sub) = DEFINITIONS.iter().find(|d| {
        let dn = d.name.to_ascii_lowercase();
        dn.contains(&needle) || needle.contains(&dn)
    }) {
        return Some(sub);
    }
    // Canonical aliases mapping active/passive scanner finding titles to the 183 KB definitions
    let alias_target = if needle.contains("content-security-policy") {
        "content security policy: not enforced"
    } else if needle.contains("x-frame-options") || needle.contains("clickjacking") {
        "frameable response (potential clickjacking)"
    } else if needle.contains("strict-transport-security")
        || needle.contains("security header")
        || needle.starts_with("missing ")
    {
        "strict transport security not enforced"
    } else if needle.contains("cookie without secure") {
        "tls cookie without secure flag set"
    } else if needle.contains("cookie without httponly")
        || needle.contains("cookie without samesite")
        || needle.contains("session cookie")
    {
        "cookie without httponly flag set"
    } else if needle.contains("version disclosure")
        || needle.contains("technology disclosure")
        || needle.contains("stack trace")
        || needle.contains("html comment")
        || needle.contains("source code disclosure")
        || needle.contains("actuator")
    {
        "source code disclosure"
    } else if needle.contains("vulnerable javascript") || needle.contains("retire") {
        "vulnerable javascript dependency"
    } else if needle.contains("access control") || needle.contains("cve-2025-29927") {
        "access control"
    } else if needle.contains("sensitive value") || needle.contains("aws access key") {
        "private key disclosed"
    } else if needle.contains("filesystem path") {
        "file path manipulation"
    } else if needle.contains("path traversal") || needle.contains("local file inclusion") {
        "file path traversal"
    } else if needle.contains("ssrf") || needle.contains("request forgery") {
        "out-of-band resource load (http)"
    } else if needle.contains("xxe") || needle.contains("external entity") {
        "xml external entity injection"
    } else if needle.contains("nosql") || needle.contains("database error") {
        "sql injection"
    } else if needle.contains("crlf") || needle.contains("header injection") {
        "http response header injection"
    } else if needle.contains("open redirect") {
        "open redirection (reflected)"
    } else if needle.contains("cors") {
        "cross-origin resource sharing: arbitrary origin trusted"
    } else {
        return None;
    };
    DEFINITIONS
        .iter()
        .find(|d| d.name.to_ascii_lowercase() == alias_target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_base_contains_all_183_issue_definitions() {
        let defs = all();
        assert_eq!(defs.len(), 183);
        assert!(defs.iter().any(|d| d.name == "OS command injection" && d.type_hex == "0x00100100"));
        assert!(defs.iter().any(|d| d.name == "SQL injection" && d.type_hex == "0x00100200"));
        assert!(defs.iter().any(|d| d.name == "File path traversal" && d.type_hex == "0x00100300"));
        assert!(defs.iter().any(|d| d.name.contains("Cross-site scripting")));
        assert!(defs.iter().any(|d| d.name.contains("HTTP request smuggling")));
        assert!(find_by_name("SQL injection").is_some());
    }
}
