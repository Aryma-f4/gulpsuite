use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ReferenceSpec {
    pub version: String,
    pub shell: ShellReference,
    pub dashboard: DashboardReference,
    pub drawer: DrawerReference,
    pub evidence: EvidenceReference,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ShellReference {
    pub tools: Vec<String>,
    pub tool_row_height: f32,
    pub sub_row_height: f32,
    pub status_height: f32,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DashboardReference {
    pub split_ratio: f32,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DrawerReference {
    pub minimum_height: f32,
    pub maximum_height: f32,
    pub default_height: f32,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EvidenceReference {
    pub archive_inventory: String,
    pub feature_classes: String,
}

pub fn burp_2026_3_3() -> &'static ReferenceSpec {
    static REFERENCE: OnceLock<ReferenceSpec> = OnceLock::new();
    REFERENCE.get_or_init(|| {
        serde_json::from_str(include_str!("../../assets/reference/burp-v2026.3.3.json"))
            .expect("Burp v2026.3.3 reference specification must be valid JSON")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_identifies_exact_version_and_evidence() {
        let reference = burp_2026_3_3();
        assert_eq!(reference.version, "2026.3.3");
        assert_eq!(
            reference.evidence.archive_inventory,
            "ev_cd380653b98d0d56dd3f20aaf03de9812c408900b14c1f25ce97d65c94c8686e"
        );
        assert_eq!(
            reference.evidence.feature_classes,
            "ev_38fe9a1e458d96cb786342eac0213bde35276dc123157ed9804122d45650eae4"
        );
    }

    #[test]
    fn reference_preserves_observed_tool_order() {
        assert_eq!(
            burp_2026_3_3().shell.tools,
            [
                "Dashboard",
                "Target",
                "Proxy",
                "Intruder",
                "Repeater",
                "Collaborator",
                "Sequencer",
                "Decoder",
                "Comparer",
                "Logger",
                "Organizer",
                "Extensions",
                "Discover",
            ]
        );
    }

    #[test]
    fn reference_dashboard_geometry_matches_capture() {
        let reference = burp_2026_3_3();
        assert_eq!(reference.shell.tool_row_height, 31.0);
        assert_eq!(reference.shell.sub_row_height, 30.0);
        assert_eq!(reference.shell.status_height, 36.0);
        assert_eq!(reference.dashboard.split_ratio, 500.0 / 1440.0);
        assert_eq!(reference.drawer.default_height, 280.0);
    }
}
