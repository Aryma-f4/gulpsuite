//! Project save and load.
//!
//! Burp's `project/Project` persists a whole session: the target, saved items, recorded traffic and
//! settings. This persists what this app actually holds between runs — the Organizer, login
//! recordings and the panel settings that are worth keeping — as one JSON file.

use serde::{Deserialize, Serialize};

/// Cap on a project file. A project is operator-supplied data; refusing an absurd one keeps a
/// mistyped path from reading gigabytes into memory.
pub const MAX_PROJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Bumped when the on-disk shape changes incompatibly.
pub const PROJECT_VERSION: u32 = 1;

/// One saved organizer item.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedItem {
    pub host: String,
    pub name: String,
    pub notes: String,
    pub request: String,
    pub response: String,
}

/// One saved login recording, as a list of steps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedRecording {
    pub name: String,
    pub host: String,
    pub steps: Vec<SavedStep>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedStep {
    pub method: String,
    pub url: String,
    pub request: String,
    pub response: String,
    pub status: u16,
}

/// Projects default to the dark theme, which is what this build opens with.
fn default_true() -> bool {
    true
}

/// Everything persisted between runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Project {
    pub version: u32,
    pub name: String,
    /// A display preference, so a file written before it existed still opens.
    #[serde(default = "default_true")]
    pub theme_dark: bool,
    pub items: Vec<SavedItem>,
    pub recordings: Vec<SavedRecording>,
    /// Panel settings worth keeping, kept as plain strings rather than a typed schema so an unknown
    /// key in a future version cannot make an old file unreadable.
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, String>,
}

impl Project {
    pub fn new(name: &str) -> Self {
        Project {
            version: PROJECT_VERSION,
            name: name.to_string(),
            theme_dark: true,
            ..Default::default()
        }
    }

    /// Writes the project, refusing to overwrite nothing and never leaving a half-written file:
    /// the content goes to a sibling temporary path first and is then renamed.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, json.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", temporary.display()))?;
        std::fs::rename(&temporary, path).map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            format!("cannot replace {}: {e}", path.display())
        })
    }

    /// Reads a project, checking the size cap and the version before trusting the contents.
    pub fn load(path: &std::path::Path) -> Result<Project, String> {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.len() > MAX_PROJECT_BYTES {
            return Err(format!(
                "project is {} bytes, the limit is {MAX_PROJECT_BYTES}",
                meta.len()
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let project: Project = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a valid project: {e}", path.display()))?;
        if project.version > PROJECT_VERSION {
            return Err(format!(
                "project version {} is newer than this build supports ({PROJECT_VERSION})",
                project.version
            ));
        }
        Ok(project)
    }

    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    pub fn recording_count(&self) -> usize {
        self.recordings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("gulpsuite-project-{name}-{}.json", std::process::id()));
        path
    }

    fn sample() -> Project {
        let mut project = Project::new("demo");
        project.items.push(SavedItem {
            host: "a.test".into(),
            name: "one".into(),
            notes: "n".into(),
            request: "GET / HTTP/1.1\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\n\r\n".into(),
        });
        project.recordings.push(SavedRecording {
            name: "login".into(),
            host: "a.test".into(),
            steps: vec![SavedStep {
                method: "POST".into(),
                url: "https://a.test/login".into(),
                request: "POST /login HTTP/1.1\r\n\r\n".into(),
                response: "Set-Cookie: a=1\r\n\r\n".into(),
                status: 200,
            }],
        });
        project.settings.insert("intercept".into(), "on".into());
        project
    }

    #[test]
    fn a_project_round_trips() {
        let path = temp_path("round-trip");
        let original = sample();
        original.save(&path).expect("save");
        let loaded = Project::load(&path).expect("load");
        assert_eq!(loaded.name, "demo");
        assert_eq!(loaded.item_count(), 1);
        assert_eq!(loaded.recording_count(), 1);
        assert_eq!(loaded.settings.get("intercept").map(String::as_str), Some("on"));
        assert_eq!(loaded.items[0].request, original.items[0].request);
        assert_eq!(loaded.recordings[0].steps[0].status, 200);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let path = temp_path("no-temp");
        sample().save(&path).expect("save");
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_twice_replaces_rather_than_appends() {
        let path = temp_path("replace");
        let first = sample();
        first.save(&path).expect("first save");
        let mut second = Project::new("second");
        second.items.push(SavedItem { name: "only".into(), ..Default::default() });
        second.save(&path).expect("second save");
        let loaded = Project::load(&path).expect("load");
        assert_eq!(loaded.name, "second");
        assert_eq!(loaded.item_count(), 1);
        assert_eq!(loaded.items[0].name, "only");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_reports_rather_than_panicking() {
        let error = Project::load(std::path::Path::new("/nonexistent/nope.json")).expect_err("must fail");
        assert!(error.contains("cannot stat"));
    }

    #[test]
    fn a_corrupt_file_reports_the_path() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"{ not json").expect("write");
        let error = Project::load(&path).expect_err("must fail");
        assert!(error.contains("not a valid project"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_newer_version_is_refused_rather_than_misread() {
        let path = temp_path("newer");
        let mut project = sample();
        project.version = PROJECT_VERSION + 1;
        project.save(&path).expect("save");
        let error = Project::load(&path).expect_err("must fail");
        assert!(error.contains("newer than this build"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_project_without_settings_still_loads() {
        let path = temp_path("no-settings");
        // An older file may not carry the settings map at all.
        let json = r#"{"version":1,"name":"old","items":[],"recordings":[]}"#;
        std::fs::write(&path, json).expect("write");
        let loaded = Project::load(&path).expect("load");
        assert_eq!(loaded.name, "old");
        assert!(loaded.settings.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
