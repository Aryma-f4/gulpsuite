use eframe::egui::{RichText, Ui};

use crate::ui::theme::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WipFeature {
    Ai,
    GappStore,
}

impl WipFeature {
    pub fn title(self) -> &'static str {
        match self {
            Self::Ai => "AI — Work in progress",
            Self::GappStore => "GApp Store — Work in progress",
        }
    }

    pub fn purpose(self) -> &'static str {
        match self {
            Self::Ai => {
                "AI-assisted investigation, explanation, and workflow automation will live here."
            }
            Self::GappStore => {
                "Browse, install, update, and manage community extensions from one catalog."
            }
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::Ai => "The interface route is complete. Model integration is intentionally deferred.",
            Self::GappStore => {
                "The interface route is complete. Remote catalog and package installation are intentionally deferred."
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WipState {
    active: Option<WipFeature>,
}

impl WipState {
    pub fn open(&mut self, feature: WipFeature) {
        self.active = Some(feature);
    }

    pub fn close(&mut self) {
        self.active = None;
    }

    pub fn active(&self) -> Option<WipFeature> {
        self.active
    }
}

pub fn draw_panel(ui: &mut Ui, feature: WipFeature, theme: &Theme) -> bool {
    let mut close = false;
    ui.vertical_centered(|ui| {
        ui.add_space(48.0);
        ui.label(
            RichText::new(feature.title())
                .size(22.0)
                .strong()
                .color(theme.color("ui.text.body")),
        );
        ui.add_space(10.0);
        ui.label(RichText::new(feature.purpose()).color(theme.color("ui.text.body")));
        ui.add_space(6.0);
        ui.label(RichText::new(feature.status()).color(theme.color("ui.text.disabled")));
        ui.add_space(14.0);
        if ui
            .button("★ Star Gulpsuite on GitHub (https://github.com/Aryma-f4/gulpsuite)")
            .clicked()
        {
            ui.ctx().open_url(eframe::egui::OpenUrl::new_tab(
                "https://github.com/Aryma-f4/gulpsuite",
            ));
        }
        ui.add_space(10.0);
        close = ui.button("Return").clicked();
    });
    close
}

pub fn public_labels() -> Vec<&'static str> {
    let mut labels: Vec<_> = crate::ui::app::TOOLS.to_vec();
    labels.extend(crate::ui::app::TOOL_VIEWS.into_iter().flatten());
    labels.extend([WipFeature::Ai.title(), WipFeature::GappStore.title()]);
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_and_gapp_store_have_explicit_labeled_routes() {
        let mut state = WipState::default();
        state.open(WipFeature::Ai);
        assert_eq!(state.active(), Some(WipFeature::Ai));
        assert!(WipFeature::Ai.title().contains("AI"));
        state.open(WipFeature::GappStore);
        assert_eq!(state.active(), Some(WipFeature::GappStore));
        assert!(WipFeature::GappStore.title().contains("GApp Store"));
    }

    #[test]
    fn public_navigation_has_no_licensing_actions() {
        for label in public_labels() {
            let normalized = label.to_ascii_lowercase();
            assert!(!normalized.contains("license"), "{label}");
            assert!(!normalized.contains("licensing"), "{label}");
            assert!(!normalized.contains("activate"), "{label}");
        }
    }
}
