//! The Gulp theme, resolved from the JSON Gulp itself ships.
//!
//! Colour values are references, not literals: `@black[2]` is shade 2 of the black swatch, and
//! `$mono[1]` is shade 1 of whatever swatch the `mono` palette alias points at. Resolving those
//! references here means the UI inherits Gulp's palette exactly instead of approximating it.

use std::collections::HashMap;

use eframe::egui::Color32;
use serde::Deserialize;

const DARK: &str = include_str!("../../../theme/DarkTheme.json");
const LIGHT: &str = include_str!("../../../theme/LightTheme.json");

#[derive(Deserialize)]
struct RawTheme {
    #[serde(default)]
    dark: bool,
    colors: RawColors,
}

#[derive(Deserialize, Default)]
struct RawColors {
    #[serde(default)]
    swatches: HashMap<String, RawSwatch>,
    #[serde(default)]
    palette: HashMap<String, String>,
    #[serde(default)]
    ui: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct RawSwatch {
    core: String,
    #[serde(default)]
    shades: Vec<String>,
}

/// Flattened, resolved colours keyed exactly as the UI asks for them, e.g. `background.1`.
#[derive(Clone)]
pub struct Theme {
    pub dark: bool,
    values: HashMap<String, Color32>,
}

/// `Button.arc` from gulp/theme/GulpLaf.properties.
pub const GULP_BUTTON_ARC: u8 = 8;
/// FlatLaf passes arcWidth/arcHeight to Java2D; egui expects a corner radius.
pub const GULP_BUTTON_RADIUS: u8 = GULP_BUTTON_ARC / 2;
/// `Button.margin=2,20,2,20` from GulpLaf, expressed as egui button padding (horizontal, vertical).
pub const GULP_BUTTON_PADDING: eframe::egui::Vec2 = eframe::egui::Vec2::new(20.0, 2.0);

impl Theme {
    pub fn load(dark: bool) -> Self {
        let raw: RawTheme =
            serde_json::from_str(if dark { DARK } else { LIGHT }).expect("bundled theme parses");
        let mut leaves: HashMap<String, String> = HashMap::new();
        collect(&serde_json::Value::Object(raw.colors.ui.clone()), "", &mut leaves);

        let mut values = HashMap::with_capacity(leaves.len());
        for (key, reference) in leaves {
            values.insert(key.clone(), resolve(&reference, &raw.colors, 0));
        }

        // GulpLaf names its colours the way Gulp does, e.g. `$Colors.palette.mono.3` and
        // `$Colors.palette.secondary.core`. Only `colors.ui` is collected above, so the palette and
        // swatch namespaces are exposed here too. Panels can then quote Gulp's own key names instead
        // of guessing which `ui.background.N` happens to equal `palette.mono.N`.
        for (name, target) in &raw.colors.palette {
            values.insert(format!("palette.{name}"), resolve(target, &raw.colors, 0));
            // GulpLaf also names the core colour of a palette entry, e.g.
            // `$Colors.palette.secondary.core`, so that key has to resolve too.
            let core = target.trim().trim_start_matches('@');
            let core = core.split('[').next().unwrap_or(core);
            values.insert(
                format!("palette.{name}.core"),
                raw.colors
                    .swatches
                    .get(core)
                    .map(|swatch| parse_hex(swatch.core.trim_start_matches('#')))
                    .unwrap_or(GREY),
            );
            for shade in 1..=8 {
                values.insert(
                    format!("palette.{name}.{shade}"),
                    resolve(&format!("${name}[{shade}]"), &raw.colors, 0),
                );
            }
        }
        for (name, swatch) in &raw.colors.swatches {
            values.insert(format!("swatches.{name}.core"), resolve(&swatch.core, &raw.colors, 0));
            for (index, hex) in swatch.shades.iter().enumerate() {
                values.insert(format!("swatches.{name}.{}", index + 1), resolve(hex, &raw.colors, 0));
            }
        }

        // Gulp's JSON has no `ui.border` group, but GulpLaf draws every border with
        // `$Colors.palette.mono.4` (Button.borderColor). Measured from Gulp: the rule under the
        // tool tabs is #DFDFDF in the light theme, which is mono.4 there.
        values.insert("border.1".into(), resolve("$mono[4]", &raw.colors, 0));
        // Alias `background.0` to `$mono[1]` (#FFFFFF in Light, #2B2B2B in Dark) and
        // `icon.accent` to `@orange` (#FF6633) so panels using 0-indexed background or accent keys
        // always get Gulp's true surface and primary orange colours.
        values.insert("background.0".into(), resolve("$mono[1]", &raw.colors, 0));
        values.insert("icon.accent".into(), resolve("@orange", &raw.colors, 0));
        values.insert("icon.accent.blue".into(), resolve("@blue[3]", &raw.colors, 0));
        if let Some(&border_col) = values.get("border.1") {
            values.insert("border.default".into(), border_col);
        }
        if let Some(&disabled_col) = values.get("text.disabled") {
            values.insert("text.muted".into(), disabled_col);
            values.insert("text.secondary".into(), disabled_col);
        }
        if let Some(&header_col) = values.get("text.header") {
            values.insert("text.heading".into(), header_col);
        }

        // Gulp paints its accent with a tone the palette does not express. The light theme's
        // selected-tab underline and primary button are #CC683D in a running Gulp, and the
        // palette's nearest shade is #DB612F.
        if !raw.dark {
            values.insert("icon.link".into(), Color32::from_rgb(0xCC, 0x68, 0x3D));
            values.insert("icon.linkHover".into(), Color32::from_rgb(0xDB, 0x61, 0x2F));
        }

        Theme { dark: raw.dark, values }
    }

    /// Looks up a colour. Unknown keys fall back to a mid grey so a typo is visible, not fatal.
    pub fn color(&self, key: &str) -> Color32 {
        let key = key.strip_prefix("ui.").unwrap_or(key);
        self.values
            .get(key)
            .copied()
            .unwrap_or(Color32::from_rgb(128, 128, 128))
    }

    /// True when the key exists, so a typo is caught instead of silently rendering grey.
    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key.strip_prefix("ui.").unwrap_or(key))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.values.keys()
    }
}

/// Flattens the nested `ui` object into `background.1` style keys holding the raw reference text.
fn collect(value: &serde_json::Value, prefix: &str, out: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect(child, &path, out);
            }
        }
        serde_json::Value::String(text) => {
            out.insert(prefix.to_string(), text.clone());
        }
        _ => {}
    }
}

/// Expands one reference. `@name` is the swatch core, `@name[k]` a shade, and `$alias[k]` a shade
/// of whatever swatch that palette alias names.
fn resolve(reference: &str, colors: &RawColors, depth: usize) -> Color32 {
    // Guard against a reference chain that refers back to itself.
    if depth > 4 {
        return GREY;
    }
    let text = reference.trim();
    if let Some(hex) = text.strip_prefix('#') {
        return parse_hex(hex);
    }

    let (head, mut index) = split_reference(text);
    let swatch_name = match head.strip_prefix('$') {
        Some(alias) => match colors.palette.get(alias) {
            Some(target) => {
                let (target_head, target_index) = split_reference(target);
                index = index.or(target_index);
                target_head.trim_start_matches('@').to_string()
            }
            None => return GREY,
        },
        None => head.trim_start_matches('@').to_string(),
    };

    match colors.swatches.get(&swatch_name) {
        None => GREY,
        Some(swatch) => {
            let core = parse_hex(swatch.core.trim_start_matches('#'));
            // Gulp numbers shades from one: `$palette.mono.4` is the fourth shade of the mono
            // swatch and the swatch core is the zeroth. Measured against Gulp itself: its light
            // theme divider is #DFDFDF, which is mono.4, and its body text is #2B2B2B, which is
            // mono.8. Reading the array as zero-based would put both one shade off and drop
            // mono.8 off the end, rendering body text white on white.
            match index.and_then(|k| k.checked_sub(1)).and_then(|i| swatch.shades.get(i)) {
                Some(hex) => parse_hex(hex.trim_start_matches('#')),
                None => core,
            }
        }
    }
}

/// Splits `@black[2]` into (`@black`, Some(2)).
fn split_reference(text: &str) -> (&str, Option<usize>) {
    match text.split_once('[') {
        Some((head, tail)) => (head.trim(), tail.trim_end_matches(']').parse().ok()),
        None => (text.trim(), None),
    }
}

const GREY: Color32 = Color32::from_rgb(128, 128, 128);

fn parse_hex(hex: &str) -> Color32 {
    let hex = hex.trim();
    let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0);
    if hex.len() >= 8 {
        Color32::from_rgba_unmultiplied(byte(0), byte(2), byte(4), byte(6))
    } else {
        Color32::from_rgb(byte(0), byte(2), byte(4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gulp_palette_resolves() {
        let theme = Theme::load(true);
        assert!(theme.dark);
        // $mono[1] is one step off pure black: a real dark grey, not black and not missing.
        let background = theme.color("ui.background.1");
        assert!(background.r() < 80, "background.1 should be dark, got {background:?}");
        assert!(background.r() > 10, "background.1 should not be pure black, got {background:?}");
    }

    #[test]
    fn every_gulp_ui_key_resolves_to_a_real_colour() {
        let theme = Theme::load(true);
        for key in theme.keys() {
            let value = theme.color(key);
            assert_ne!(value, GREY, "key {key} failed to resolve");
        }
        assert!(theme.keys().count() > 100, "theme looks truncated");
    }

    #[test]
    fn status_and_issue_colours_differ_from_the_fallback() {
        let theme = Theme::load(true);
        for key in ["ui.status.new", "ui.status.done", "ui.issue.high", "ui.icon.default"] {
            assert_ne!(theme.color(key), GREY, "{key} did not resolve");
        }
    }

    #[test]
    fn unknown_key_is_grey_not_a_panic() {
        assert_eq!(Theme::load(true).color("ui.nope.missing"), GREY);
    }

    #[test]
    fn light_theme_is_not_dark() {
        assert!(!Theme::load(false).dark);
    }

    #[test]
    fn hex_parsing_handles_both_lengths() {
        assert_eq!(parse_hex("ff0000"), Color32::from_rgb(255, 0, 0));
        assert_eq!(parse_hex("80ff0000"), Color32::from_rgba_unmultiplied(128, 255, 0, 0));
    }

    #[test]
    fn reference_splitting() {
        assert_eq!(split_reference("@black[2]"), ("@black", Some(2)));
        assert_eq!(split_reference("$mono[1]"), ("$mono", Some(1)));
        assert_eq!(split_reference("@white"), ("@white", None));
    }
}

#[cfg(test)]
mod gulp_laf_tests {
    use super::*;

    /// The shipped Gulp theme maps `ui.background.N` onto `$mono[N]` for N = 1..=4. Button styling in
    /// GulpLaf is written in palette terms (`palette.mono.3` and friends), so this identity is what
    /// makes those values translatable. If it stops holding, button colours drift from Gulp's.
    #[test]
    fn background_keys_are_the_mono_shades_gulp_button_colours_name() {
        let theme = Theme::load(true);
        for shade in 1..=4u8 {
            assert_eq!(
                theme.color(&format!("ui.background.{shade}")),
                theme.color(&format!("palette.mono.{shade}")),
                "background.{shade} must equal palette.mono.{shade}"
            );
        }
    }

    /// The desktop, control, menu and text surfaces are all the same value in GulpLaf.
    #[test]
    fn the_surface_colours_gulp_uses_are_resolved_and_distinct_from_background_1() {
        let theme = Theme::load(true);
        let background_2 = theme.color("ui.background.2");
        for key in ["ui.background.2", "ui.background.3", "ui.background.4", "ui.background.5"] {
            assert!(theme.color(key) != theme.color("ui.icon.default"), "{key} unresolved");
        }
        assert_ne!(
            background_2,
            theme.color("ui.background.1"),
            "desktop must not be background.1"
        );
    }

    /// Button metrics come from GulpLaf: arc = 8 and margin = 2,20,2,20.
    #[test]
    fn the_button_metrics_match_gulp_laf() {
        assert_eq!(GULP_BUTTON_ARC, 8, "GulpLaf Button.arc");
        assert_eq!(
            GULP_BUTTON_PADDING,
            eframe::egui::Vec2::new(20.0, 2.0),
            "GulpLaf Button.margin"
        );
    }
}
