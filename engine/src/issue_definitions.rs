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

/// Finds the closest matching `IssueDefinition` by exact or substring issue name.
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
    DEFINITIONS.iter().find(|d| {
        let dn = d.name.to_ascii_lowercase();
        dn.contains(&needle) || needle.contains(&dn)
    })
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
