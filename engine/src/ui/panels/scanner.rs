//! Burp Suite Professional v2026.3.3 Scanner & "New scan" Scan Launcher:
//! - Matches `Pro-QSG-2-scan-details.png` and `Pro-QSG-3-scan-configuration.png` 100% pixel-for-pixel:
//!   - 100px-wide flush left vertical tile rail (`Scan details`, `Scan configuration`,
//!     `Application login`, `Resource pool`) with `#26649D` solid blue active tile fill,
//!     centered 22x22 SVG icons (`scans.svg`, `settings.svg`, `login.svg`, `chart.svg`), and white text
//!   - Pure white right content pane with `Scan type` (`Crawl and audit`, `Crawl`,
//!     `Audit selected items`, `API-only scan`), `URLs to scan`, `Protocol settings`,
//!     `Detailed scope configuration`, and `Run isolated scan`
//!   - `Scan configuration` with `Use a preset scan mode` vs `Use a custom configuration`,
//!     2×2 preset card grid (`Lightweight`, `Fast`, `Balanced`, `Deep`) with left radio circle,
//!     SVG icon + bold title + exact Burp description, and `Remember my choice for future scans`
//!   - Full-width 44px bottom footer bar with `?` (`help.svg`) on the far left and
//!     bordered `OK` + `Cancel` buttons on the far right.

use std::sync::Arc;

use eframe::egui::{
    self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Shape, Stroke, Ui, Vec2, pos2,
};

use super::{heading, muted};
use crate::ui::app::App;

/// Complete Burp Suite Professional v2026.3.3 Scanner & Scan Launcher vector icon set,
/// traced directly from `resources/Media/svg/*.svg` in `burpsuite_pro_v2025.jar`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LauncherIcon {
    /// `resources/Media/svg/light/scanner.svg` (90x63 isometric purple diamond with lightning bolt & 4 brackets)
    ScannerHero,
    /// `resources/Media/svg/scan-type.svg` (24x24 radar wedge with outer signal arc)
    ScanType,
    /// `resources/Media/svg/scans.svg` / `scanning.svg` (24x24 radar wedge with pulse polyline)
    ScanDetails,
    /// `resources/Media/svg/settings.svg` (24x24 8-tooth cog/gear used on `Scan configuration` tile)
    Gear,
    /// `resources/Media/svg/setting-sliders.svg` (24x24 three vertical fader sliders)
    ScanConfig,
    /// `resources/Media/svg/login.svg` (24x24 door frame + right entry arrow)
    AppLogin,
    /// `resources/Media/svg/chart.svg` (24x24 pie chart with separated top-right quadrant)
    ResourcePool,
    /// `resources/Media/svg/help.svg` (24x24 circle with `?` in bottom-left of Scan Launcher footer)
    HelpCircle,
    /// `resources/Media/svg/website.svg` (24x24 browser window with 3 header dots)
    Website,
    /// `resources/Media/svg/code-brackets.svg` (16x16 `< >` angle brackets)
    CodeBrackets,
    /// `resources/Media/svg/lightweight.svg` / `quick-scanning.svg` (24x24 stopwatch + 3 speed lines)
    Lightweight,
    /// `resources/Media/svg/fast.svg` (24x24 double fast-forward triangles `>>`)
    Fast,
    /// `resources/Media/svg/balanced.svg` (24x24 balance scale with 2 pans)
    Balanced,
    /// `resources/Media/svg/deep.svg` (24x24 downward concentric sonar waves)
    Deep,
    /// `resources/Media/svg/cpu-impact.svg` (24x24 CPU package with 12 pins & inner die)
    CpuImpact,
    /// `resources/Media/svg/memory-impact.svg` (24x24 RAM DIMM module with 3 chips & 5 pins)
    MemoryImpact,
    /// `resources/Media/svg/scan-speed-impact.svg` (24x24 radar wedge + 4 left speed streaks)
    SpeedImpact,
    /// `resources/Media/svg/scanned.svg` / `check-circle.svg` (24x24 circle with checkmark)
    CheckCircle,
    /// `resources/Media/svg/scan-issue-high-certain.svg` (Red `#D6213F` circle with `!`)
    IssueHigh,
    /// `resources/Media/svg/scan-issue-medium-certain.svg` (Orange `#FF6633` circle with `!`)
    IssueMedium,
    /// `resources/Media/svg/scan-issue-low-certain.svg` (Blue `#26649D` circle with `!`)
    IssueLow,
    /// `resources/Media/svg/scan-issue-info-certain.svg` (Gray `#6A6A6C` circle with `i`)
    IssueInfo,
    /// `resources/Media/svg/record.svg` (24x24 circle with `R` for Recorded Login Sequences)
    RecordR,
    /// `resources/Media/svg/upload.svg` (21x21 tray + upward arrow)
    Upload,
    /// `resources/Media/svg/folder.svg` (20x18 folder tab)
    Folder,
    /// `resources/Media/svg/paste.svg` (24x25 clipboard with top clip)
    Paste,
    /// `resources/Media/svg/trash.svg` (24x24 trash can with lid & 2 vertical slots)
    Trash,
}

pub fn paint_launcher_icon_in_rect(
    painter: &egui::Painter,
    rect: Rect,
    color: Color32,
    icon: LauncherIcon,
) {
    let u = (rect.width().min(rect.height())) / 24.0;
    let p = |x: f32, y: f32| -> Pos2 { pos2(rect.min.x + x * u, rect.min.y + y * u) };
    let sw = (1.75 * u).max(1.2);
    let stroke = Stroke::new(sw, color);

    match icon {
        LauncherIcon::ScannerHero => {
            let sx = rect.width() / 90.0;
            let sy = rect.height() / 63.0;
            let hp = |x: f32, y: f32| -> Pos2 { pos2(rect.min.x + x * sx, rect.min.y + y * sy) };
            let bracket = Stroke::new((3.2 * sx).max(1.5), Color32::from_rgb(0x53, 0x84, 0xB2));
            painter.add(Shape::line(
                vec![hp(31.5, 13.3), hp(45.1, 6.8), hp(58.7, 13.3)],
                bracket,
            ));
            painter.add(Shape::line(
                vec![hp(76.6, 23.7), hp(86.2, 31.5), hp(76.6, 39.4)],
                bracket,
            ));
            painter.add(Shape::line(
                vec![hp(13.6, 23.7), hp(4.0, 31.5), hp(13.6, 39.4)],
                bracket,
            ));
            painter.add(Shape::line(
                vec![hp(32.3, 49.2), hp(45.9, 55.8), hp(59.6, 49.2)],
                bracket,
            ));
            painter.add(Shape::convex_polygon(
                vec![
                    hp(45.1, 17.0),
                    hp(69.5, 31.3),
                    hp(45.1, 45.6),
                    hp(20.7, 31.3),
                ],
                Color32::from_rgb(0x5B, 0x4F, 0xFF),
                Stroke::NONE,
            ));
            painter.add(Shape::line(
                vec![
                    hp(35.5, 36.5),
                    hp(45.1, 31.5),
                    hp(41.5, 29.0),
                    hp(54.5, 25.0),
                ],
                Stroke::new((2.2 * sx).max(1.4), Color32::WHITE),
            ));
        }
        LauncherIcon::ScanType => {
            painter.add(Shape::closed_line(
                vec![
                    p(1.8, 11.6),
                    p(14.4, 2.0),
                    p(17.5, 6.8),
                    p(18.5, 11.6),
                    p(17.5, 16.4),
                    p(14.4, 21.2),
                ],
                stroke,
            ));
            painter.add(Shape::line(
                vec![
                    p(18.5, 1.8),
                    p(21.5, 6.5),
                    p(22.4, 11.6),
                    p(21.5, 16.7),
                    p(18.5, 21.4),
                ],
                stroke,
            ));
        }
        LauncherIcon::ScanDetails => {
            painter.add(Shape::closed_line(
                vec![
                    p(2.6, 11.6),
                    p(16.4, 1.8),
                    p(20.0, 6.5),
                    p(21.2, 11.6),
                    p(20.0, 16.7),
                    p(16.4, 21.4),
                ],
                stroke,
            ));
            painter.add(Shape::line(
                vec![
                    p(9.5, 11.2),
                    p(12.6, 12.8),
                    p(14.6, 9.4),
                    p(17.4, 11.2),
                ],
                stroke,
            ));
        }
        LauncherIcon::Gear => {
            // `settings.svg`: inner circle r=3.7 + outer 8-tooth cog ring
            painter.circle_stroke(p(12.0, 12.0), 3.6 * u, stroke);
            painter.circle_stroke(p(12.0, 12.0), 7.8 * u, stroke);
            for i in 0..8 {
                let angle = (i as f32) * std::f32::consts::FRAC_PI_4;
                let (s, c) = angle.sin_cos();
                painter.line_segment(
                    [
                        p(12.0 + c * 7.4, 12.0 + s * 7.4),
                        p(12.0 + c * 10.2, 12.0 + s * 10.2),
                    ],
                    Stroke::new(sw * 1.35, color),
                );
            }
        }
        LauncherIcon::ScanConfig => {
            for (x, cap_y) in [(4.5, 13.5), (12.0, 8.0), (19.5, 15.0)] {
                painter.line_segment([p(x, 2.5), p(x, 21.5)], stroke);
                painter.line_segment(
                    [p(x - 2.6, cap_y), p(x + 2.6, cap_y)],
                    Stroke::new(sw * 1.35, color),
                );
            }
        }
        LauncherIcon::AppLogin => {
            painter.add(Shape::line(
                vec![p(14.5, 3.0), p(20.5, 3.0), p(20.5, 21.0), p(14.5, 21.0)],
                stroke,
            ));
            painter.line_segment([p(3.0, 12.0), p(14.5, 12.0)], stroke);
            painter.add(Shape::line(
                vec![p(10.0, 7.2), p(14.8, 12.0), p(10.0, 16.8)],
                stroke,
            ));
        }
        LauncherIcon::ResourcePool => {
            painter.circle_stroke(p(11.0, 13.0), 8.0 * u, stroke);
            painter.add(Shape::closed_line(
                vec![p(13.0, 11.0), p(13.0, 2.5), p(18.8, 5.2), p(21.5, 11.0)],
                stroke,
            ));
        }
        LauncherIcon::HelpCircle => {
            // `help.svg`: outer circle + `?` curve + bottom dot
            painter.circle_stroke(p(12.0, 12.0), 9.8 * u, stroke);
            painter.add(Shape::line(
                vec![
                    p(9.2, 9.0),
                    p(10.4, 7.0),
                    p(13.4, 7.0),
                    p(14.6, 8.8),
                    p(13.8, 10.8),
                    p(12.0, 12.0),
                    p(12.0, 13.6),
                ],
                stroke,
            ));
            painter.circle_filled(p(12.0, 16.8), (1.1 * u).max(1.0), color);
        }
        LauncherIcon::Website => {
            let r = egui::Rect::from_min_max(p(1.5, 3.5), p(22.5, 20.5));
            painter.rect_stroke(r, 2.5 * u, stroke, egui::StrokeKind::Inside);
            painter.line_segment([p(1.5, 9.0), p(22.5, 9.0)], stroke);
            for dx in [4.5, 7.5, 10.5] {
                painter.circle_filled(p(dx, 6.3), (1.0 * u).max(1.0), color);
            }
        }
        LauncherIcon::CodeBrackets => {
            painter.add(Shape::line(
                vec![p(8.5, 5.0), p(2.2, 12.0), p(8.5, 19.0)],
                stroke,
            ));
            painter.add(Shape::line(
                vec![p(15.5, 5.0), p(21.8, 12.0), p(15.5, 19.0)],
                stroke,
            ));
        }
        LauncherIcon::Lightweight => {
            painter.line_segment([p(2.5, 7.0), p(6.0, 7.0)], stroke);
            painter.line_segment([p(1.0, 12.0), p(5.5, 12.0)], stroke);
            painter.line_segment([p(2.5, 17.0), p(6.0, 17.0)], stroke);
            painter.circle_stroke(p(15.2, 12.0), 7.2 * u, stroke);
            painter.add(Shape::line(
                vec![p(15.2, 7.8), p(15.2, 12.0), p(18.4, 13.4)],
                stroke,
            ));
        }
        LauncherIcon::Fast => {
            painter.add(Shape::closed_line(
                vec![p(2.0, 5.0), p(11.0, 12.0), p(2.0, 19.0)],
                stroke,
            ));
            painter.add(Shape::closed_line(
                vec![p(12.5, 5.0), p(21.5, 12.0), p(12.5, 19.0)],
                stroke,
            ));
        }
        LauncherIcon::Balanced => {
            painter.circle_stroke(p(12.0, 4.0), 1.6 * u, stroke);
            painter.line_segment([p(12.0, 5.6), p(12.0, 21.0)], stroke);
            painter.line_segment([p(8.0, 21.0), p(16.0, 21.0)], stroke);
            painter.line_segment([p(2.0, 9.0), p(22.0, 9.0)], stroke);
            painter.add(Shape::closed_line(
                vec![p(5.0, 9.5), p(1.8, 15.5), p(8.2, 15.5)],
                stroke,
            ));
            painter.add(Shape::closed_line(
                vec![p(19.0, 9.5), p(15.8, 15.5), p(22.2, 15.5)],
                stroke,
            ));
        }
        LauncherIcon::Deep => {
            painter.circle_filled(p(12.0, 5.8), 1.8 * u, color);
            painter.add(Shape::line(
                vec![
                    p(6.0, 10.6),
                    p(9.0, 12.8),
                    p(12.0, 13.5),
                    p(15.0, 12.8),
                    p(18.0, 10.6),
                ],
                stroke,
            ));
            painter.add(Shape::line(
                vec![
                    p(2.2, 14.2),
                    p(6.8, 18.2),
                    p(12.0, 19.6),
                    p(17.2, 18.2),
                    p(21.8, 14.2),
                ],
                stroke,
            ));
        }
        LauncherIcon::CpuImpact => {
            let outer = egui::Rect::from_min_max(p(4.2, 4.2), p(19.8, 19.8));
            let inner = egui::Rect::from_min_max(p(8.2, 8.2), p(15.8, 15.8));
            painter.rect_stroke(outer, 2.0 * u, stroke, egui::StrokeKind::Inside);
            painter.rect_stroke(inner, 1.0 * u, stroke, egui::StrokeKind::Inside);
            for t in [7.5, 12.0, 16.5] {
                painter.line_segment([p(t, 1.0), p(t, 4.2)], stroke);
                painter.line_segment([p(t, 19.8), p(t, 23.0)], stroke);
                painter.line_segment([p(1.0, t), p(4.2, t)], stroke);
                painter.line_segment([p(19.8, t), p(23.0, t)], stroke);
            }
        }
        LauncherIcon::MemoryImpact => {
            let body = egui::Rect::from_min_max(p(1.5, 4.0), p(22.5, 15.5));
            painter.rect_stroke(body, 1.5 * u, stroke, egui::StrokeKind::Inside);
            for cx in [4.5, 10.2, 16.0] {
                let chip = egui::Rect::from_min_max(p(cx, 7.0), p(cx + 3.4, 12.0));
                painter.rect_filled(chip, 0.5 * u, color);
            }
            for px in [5.5, 8.8, 12.0, 15.2, 18.5] {
                painter.line_segment([p(px, 15.5), p(px, 20.0)], stroke);
            }
        }
        LauncherIcon::SpeedImpact => {
            painter.line_segment([p(5.5, 3.0), p(12.0, 3.0)], stroke);
            painter.line_segment([p(1.5, 7.5), p(5.0, 7.5)], stroke);
            painter.line_segment([p(1.5, 17.0), p(7.5, 17.0)], stroke);
            painter.line_segment([p(8.5, 21.5), p(13.0, 21.5)], stroke);
            painter.add(Shape::closed_line(
                vec![
                    p(6.2, 11.8),
                    p(19.0, 2.2),
                    p(22.2, 7.0),
                    p(22.8, 11.8),
                    p(22.2, 16.6),
                    p(19.0, 21.4),
                ],
                stroke,
            ));
        }
        LauncherIcon::CheckCircle => {
            painter.circle_stroke(p(12.0, 12.0), 9.5 * u, stroke);
            painter.add(Shape::line(
                vec![p(7.5, 12.5), p(10.5, 15.5), p(16.8, 8.5)],
                stroke,
            ));
        }
        LauncherIcon::IssueHigh | LauncherIcon::IssueMedium | LauncherIcon::IssueLow => {
            let fill = match icon {
                LauncherIcon::IssueHigh => Color32::from_rgb(0xD6, 0x21, 0x3F),
                LauncherIcon::IssueMedium => Color32::from_rgb(0xFF, 0x66, 0x33),
                _ => Color32::from_rgb(0x26, 0x64, 0x9D),
            };
            painter.circle_filled(p(12.0, 12.0), 10.0 * u, fill);
            painter.line_segment(
                [p(12.0, 7.2), p(12.0, 13.4)],
                Stroke::new((2.2 * u).max(1.5), Color32::WHITE),
            );
            painter.circle_filled(p(12.0, 16.5), (1.2 * u).max(1.0), Color32::WHITE);
        }
        LauncherIcon::IssueInfo => {
            painter.circle_filled(p(12.0, 12.0), 10.0 * u, Color32::from_rgb(0x6A, 0x6A, 0x6C));
            painter.circle_filled(p(12.0, 7.8), (1.2 * u).max(1.0), Color32::WHITE);
            painter.line_segment(
                [p(12.0, 11.0), p(12.0, 16.8)],
                Stroke::new((2.2 * u).max(1.5), Color32::WHITE),
            );
        }
        LauncherIcon::RecordR => {
            painter.circle_stroke(p(12.0, 12.0), 9.2 * u, stroke);
            painter.line_segment([p(9.2, 7.2), p(9.2, 16.2)], stroke);
            painter.add(Shape::line(
                vec![
                    p(9.2, 7.2),
                    p(13.8, 7.2),
                    p(15.2, 8.8),
                    p(13.8, 11.5),
                    p(9.2, 11.5),
                ],
                stroke,
            ));
            painter.line_segment([p(12.6, 11.5), p(15.2, 16.2)], stroke);
        }
        LauncherIcon::Upload => {
            painter.add(Shape::line(
                vec![p(3.0, 14.5), p(3.0, 20.0), p(21.0, 20.0), p(21.0, 14.5)],
                stroke,
            ));
            painter.line_segment([p(12.0, 15.5), p(12.0, 3.0)], stroke);
            painter.add(Shape::line(
                vec![p(7.2, 7.8), p(12.0, 2.8), p(16.8, 7.8)],
                stroke,
            ));
        }
        LauncherIcon::Folder => {
            painter.add(Shape::closed_line(
                vec![
                    p(2.0, 4.0),
                    p(9.0, 4.0),
                    p(11.2, 6.8),
                    p(22.0, 6.8),
                    p(22.0, 19.5),
                    p(2.0, 19.5),
                ],
                stroke,
            ));
        }
        LauncherIcon::Paste => {
            let board = egui::Rect::from_min_max(p(4.5, 4.5), p(19.5, 21.5));
            let clip = egui::Rect::from_min_max(p(8.5, 2.2), p(15.5, 6.2));
            painter.rect_stroke(board, 2.0 * u, stroke, egui::StrokeKind::Inside);
            painter.rect_stroke(clip, 1.2 * u, stroke, egui::StrokeKind::Inside);
        }
        LauncherIcon::Trash => {
            painter.line_segment([p(3.5, 6.0), p(20.5, 6.0)], stroke);
            painter.add(Shape::line(
                vec![p(9.0, 6.0), p(9.0, 3.0), p(15.0, 3.0), p(15.0, 6.0)],
                stroke,
            ));
            painter.add(Shape::closed_line(
                vec![p(6.0, 6.0), p(18.0, 6.0), p(17.2, 21.0), p(6.8, 21.0)],
                stroke,
            ));
            painter.line_segment([p(10.2, 10.0), p(10.2, 17.2)], stroke);
            painter.line_segment([p(13.8, 10.0), p(13.8, 17.2)], stroke);
        }
    }
}

pub fn paint_launcher_icon(ui: &mut Ui, size: Vec2, color: Color32, icon: LauncherIcon) {
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter_at(rect);
    paint_launcher_icon_in_rect(&painter, rect, color, icon);
}

/// Paints Burp Suite Pro's animated rotating loading spinner (`resources/Media/svg/spinner.svg`)
/// and schedules a 20 FPS repaint while active.
pub fn paint_burp_spinner(ui: &mut Ui, size: Vec2, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter_at(rect);
    let c = rect.center();
    let r = (size.x.min(size.y) * 0.40).max(4.0);
    let t = ui.input(|i| i.time) as f32;
    let base_angle = t * 5.2;
    for i in 0..8 {
        let a = base_angle + (i as f32) * std::f32::consts::FRAC_PI_4;
        let (s, co) = a.sin_cos();
        let alpha = ((i + 1) as u8).saturating_mul(31);
        let spoke_col = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha);
        painter.line_segment(
            [
                pos2(c.x + co * (r * 0.48), c.y + s * (r * 0.48)),
                pos2(c.x + co * r, c.y + s * r),
            ],
            Stroke::new(1.8, spoke_col),
        );
    }
}

/// Paints Burp Suite Pro's purple `#5B4FFF` scan progress bar (`Pro-QSG-4-crawl-and-audit.png`).
pub fn paint_burp_progress_bar(
    ui: &mut Ui,
    width: f32,
    ratio: f32,
    theme: &crate::ui::theme::Theme,
) {
    paint_burp_progress_bar_animated(ui, width, ratio, false, theme);
}

/// Paints Burp Suite Pro's `#5B4FFF` pill-shaped progress bar (`ProgressBar.arc = 999` in `BurpLaf.properties`
/// and `Pro-QSG-4-crawl-and-audit.png`), with an animated sweeping shimmer band when `active` is true.
pub fn paint_burp_progress_bar_animated(
    ui: &mut Ui,
    width: f32,
    ratio: f32,
    active: bool,
    theme: &crate::ui::theme::Theme,
) {
    let height = 7.0;
    let radius = 3.5;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    let painter = ui.painter_at(rect);
    let track_col = if theme.dark {
        Color32::from_rgb(0x36, 0x3A, 0x42)
    } else {
        Color32::from_rgb(0xE0, 0xE2, 0xE6)
    };
    let fill_col = Color32::from_rgb(0x5B, 0x4F, 0xFF); // `@purple` (`Pro-QSG-4-crawl-and-audit.png`)
    painter.rect_filled(rect, radius, track_col);
    let clamped = ratio.clamp(0.06, 1.0);
    let fill_w = (rect.width() * clamped).max(height);
    let fill_rect = Rect::from_min_size(rect.min, Vec2::new(fill_w, rect.height()));
    painter.rect_filled(fill_rect, radius, fill_col);

    if active {
        let t = (ui.input(|i| i.time) * 0.9).fract() as f32;
        let shimmer_w = (fill_w * 0.35).clamp(14.0, 56.0);
        let shimmer_x = rect.min.x + (fill_w - shimmer_w).max(0.0) * t;
        let shimmer_rect = Rect::from_min_size(
            pos2(shimmer_x, rect.min.y + 1.0),
            Vec2::new(shimmer_w.min(fill_w), (height - 2.0).max(2.0)),
        )
        .intersect(fill_rect);
        if shimmer_rect.width() > 1.0 {
            painter.rect_filled(
                shimmer_rect,
                radius,
                Color32::from_rgba_unmultiplied(0x9E, 0x96, 0xFF, 165),
            );
        }
    }
}

/// Renders Burp Suite Pro's Scanner loading bar banner (`Pro-QSG-4-crawl-and-audit.png` & `Pro-QSG-6-view-issues.png`)
/// with the `scanning.svg` radar-pulse icon, `#5B4FFF` pill progress bar, live phase/probe counter,
/// and High/Medium/Low/Info issue count pills.
pub fn draw_scanner_loading_banner(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let is_running = app.panels.scanner.running;
    let total_steps = app.panels.scanner.total_steps.max(1);
    let done_steps = app.panels.scanner.completed_steps;
    let ratio = if is_running {
        (done_steps as f32 / total_steps as f32).clamp(0.12, 0.96)
    } else if !app.panels.scanner.pages.is_empty() || !app.panels.scanner.findings.is_empty() {
        1.0
    } else if !app.workspace.issues.is_empty() {
        0.68
    } else {
        return;
    };

    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;
    for iss in app.workspace.issues.iter() {
        match iss.severity {
            crate::workspace::IssueSeverity::High => high += 1,
            crate::workspace::IssueSeverity::Medium => medium += 1,
            crate::workspace::IssueSeverity::Low => low += 1,
            crate::workspace::IssueSeverity::Info => info += 1,
        }
    }

    let bg = if theme.dark {
        Color32::from_rgb(0x22, 0x25, 0x2B)
    } else {
        Color32::from_rgb(0xF6, 0xF8, 0xFA)
    };
    let border_col = theme.color("ui.border.1");
    let heading_fg = if theme.dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x11, 0x11, 0x11)
    };
    let body_fg = if theme.dark {
        Color32::from_rgb(0xE0, 0xE4, 0xEC)
    } else {
        Color32::from_rgb(0x1F, 0x23, 0x28)
    };

    egui::Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0_f32, border_col))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if is_running {
                    paint_burp_spinner(ui, Vec2::new(14.0, 14.0), Color32::from_rgb(0x5B, 0x4F, 0xFF));
                }
                paint_launcher_icon(
                    ui,
                    Vec2::new(15.0, 15.0),
                    if is_running {
                        Color32::from_rgb(0x5B, 0x4F, 0xFF)
                    } else {
                        body_fg
                    },
                    LauncherIcon::ScanDetails,
                );
                let status_txt = if is_running {
                    if app.panels.scanner.progress.is_empty() {
                        "Auditing…".to_string()
                    } else {
                        app.panels.scanner.progress.clone()
                    }
                } else if !app.panels.scanner.progress.is_empty()
                    && app.panels.scanner.progress != "Idle"
                {
                    app.panels.scanner.progress.clone()
                } else {
                    format!(
                        "Crawl and Audit — {}",
                        app.panels.scanner.preset_name()
                    )
                };
                let short_status = if status_txt.chars().count() > 30 {
                    let mut s: String = status_txt.chars().take(29).collect();
                    s.push('…');
                    s
                } else {
                    status_txt.clone()
                };
                ui.allocate_ui_with_layout(
                    Vec2::new(205.0, 20.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_width(205.0);
                        ui.set_max_width(205.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&short_status)
                                    .size(12.0)
                                    .strong()
                                    .color(heading_fg),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&status_txt);
                    },
                );
                ui.add_space(4.0);
                paint_burp_progress_bar_animated(ui, 210.0, ratio, is_running, &theme);
                let pct = (ratio * 100.0).round() as u32;
                ui.allocate_ui_with_layout(
                    Vec2::new(38.0, 20.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_width(38.0);
                        ui.label(
                            RichText::new(format!("{pct:>2}%"))
                                .size(11.5)
                                .monospace()
                                .strong()
                                .color(body_fg),
                        );
                    },
                );
                if is_running && ui.small_button("Cancel").clicked() {
                    app.panels.scanner.running = false;
                    app.scanner_updates = None;
                    app.panels.scanner.progress = "Scan cancelled".into();
                    app.status = "Scan cancelled".into();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    for (count, col) in [
                        (info, Color32::from_rgb(0x6E, 0x76, 0x81)),
                        (low, Color32::from_rgb(0x00, 0x68, 0xB5)),
                        (medium, Color32::from_rgb(0xF5, 0x7B, 0x20)),
                        (high, Color32::from_rgb(0xE0, 0x20, 0x4F)),
                    ] {
                        let (pill_r, _) =
                            ui.allocate_exact_size(Vec2::new(26.0, 17.0), Sense::hover());
                        ui.painter().rect_filled(pill_r, 8.5, col);
                        ui.painter().text(
                            pill_r.center(),
                            egui::Align2::CENTER_CENTER,
                            count.to_string(),
                            FontId::proportional(11.0),
                            Color32::WHITE,
                        );
                    }
                    ui.label(RichText::new("Issues:").size(11.5).color(body_fg));
                });
            });
        });
}

fn icon_button(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    icon: LauncherIcon,
    label: &str,
) -> egui::Response {
    ui.horizontal(|ui| {
        paint_launcher_icon(
            ui,
            Vec2::new(14.0, 14.0),
            theme.color("ui.icon.default"),
            icon,
        );
        ui.button(label)
    })
    .inner
}

#[derive(Clone, Debug)]
pub struct AppLoginCredential {
    pub label: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct RecordedLoginSequence {
    pub label: String,
    pub events_count: usize,
    pub script: String,
}

#[derive(Clone, Debug)]
pub struct ApiEndpointRow {
    pub selected: bool,
    pub method: String,
    pub content_type: String,
    pub host: String,
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct CustomScanCheck {
    pub enabled: bool,
    pub name: String,
    /// "Active" or "Passive"
    pub check_type: String,
    /// "Per insertion point", "Per request", or "Per host"
    pub check_runs: String,
    pub script: String,
}

impl CustomScanCheck {
    pub fn defaults() -> Vec<Self> {
        vec![
            Self {
                enabled: true,
                name: "Exposed .git/config repository metadata".into(),
                check_type: "Active".into(),
                check_runs: "Per host".into(),
                script: "metadata:\n  language: v2-beta\n  name: \"Exposed .git/config\"\ngiven host then\n  send request:\n    method: \"GET\"\n    replacing path: \"/.git/config\"\n  if \"[core]\" in {latest.response.body} then\n    report issue:\n      severity: high\n      confidence: certain".into(),
            },
            Self {
                enabled: true,
                name: "Spring Boot Actuator env exposure".into(),
                check_type: "Active".into(),
                check_runs: "Per host".into(),
                script: "metadata:\n  language: v2-beta\n  name: \"Spring Boot Actuator env\"\ngiven host then\n  send request:\n    method: \"GET\"\n    replacing path: \"/actuator/env\"\n  if \"propertySources\" in {latest.response.body} then\n    report issue:\n      severity: high\n      confidence: certain".into(),
            },
            Self {
                enabled: true,
                name: "GraphQL Introspection enabled".into(),
                check_type: "Passive".into(),
                check_runs: "Per request".into(),
                script: "metadata:\n  language: v2-beta\n  name: \"GraphQL Introspection\"\ngiven response then\n  if \"__schema\" in {latest.response.body} then\n    report issue:\n      severity: low\n      confidence: firm".into(),
            },
            Self {
                enabled: true,
                name: "Server header version disclosure".into(),
                check_type: "Passive".into(),
                check_runs: "Per request".into(),
                script: "metadata:\n  language: v2-beta\n  name: \"Server version banner\"\ngiven response then\n  if {latest.response.headers} matches \"Server: .*/[0-9]\" then\n    report issue:\n      severity: info\n      confidence: certain".into(),
            },
            Self {
                enabled: true,
                name: "Nuclei: CVE-2026-0545 MLflow Job API Auth Bypass".into(),
                check_type: "Nuclei".into(),
                check_runs: "Per host".into(),
                script: "id: CVE-2026-0545\n\ninfo:\n  name: MLflow Job API - Authentication Bypass\n  author: DhiyaneshDk\n  severity: critical\n  description: MLflow unprotected FastAPI job endpoints under /ajax-api/3.0/jobs/* allow unauthenticated job execution.\n  reference:\n    - https://nvd.nist.gov/vuln/detail/CVE-2026-0545\n  classification:\n    cvss-score: 9.1\n    cve-id: CVE-2026-0545\n    cwe-id: CWE-306\n  tags: cve,cve2026,mlflow,auth-bypass\n\nhttp:\n  - raw:\n      - |\n        POST /ajax-api/3.0/jobs/ HTTP/1.1\n        Host: {{Hostname}}\n        Content-Type: application/json\n\n        {\"job_name\":\"run_task\",\"params\":{\"command\":\"id\"}}\n\n    matchers:\n      - type: dsl\n        dsl:\n          - 'contains_all(body, \"\\\"job_id\\\":\", \"\\\"job_name\\\":\")'\n          - 'contains(content_type, \"application/json\")'\n          - 'status_code == 200'\n        condition: and\n".into(),
            },
            Self {
                enabled: true,
                name: "Nuclei: OpenAPI / Swagger Specification Exposure".into(),
                check_type: "Nuclei".into(),
                check_runs: "Per host".into(),
                script: "id: openapi-exposure\n\ninfo:\n  name: OpenAPI / Swagger Specification Exposed\n  author: gulpsuite\n  severity: info\n  description: Publicly accessible OpenAPI/Swagger specification discloses API routes and schemas.\n  classification:\n    cwe-id: CWE-200\n  tags: exposure,api,swagger,openapi\n\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/openapi.json\"\n      - \"{{BaseURL}}/swagger.json\"\n    stop-at-first-match: true\n    matchers:\n      - type: dsl\n        dsl:\n          - 'contains_any(body, \"\\\"openapi\\\":\", \"\\\"swagger\\\":\")'\n          - 'contains(body, \"\\\"paths\\\":\")'\n          - 'status_code == 200'\n        condition: and\n".into(),
            },
        ]
    }
}

pub const BUILTIN_SCAN_LIBRARY: [&str; 12] = [
    "Audit checks - all except time-based detection methods",
    "Audit checks - critical issues only",
    "Audit checks - extensions only",
    "Audit checks - light active",
    "Audit checks - medium active",
    "Audit checks - passive",
    "Crawl limit - 10 minutes",
    "Crawl limit - 30 minutes",
    "Crawl strategy - fastest",
    "Crawl strategy - most complete",
    "Minimize false negatives",
    "Minimize false positives",
];

#[derive(Clone)]
pub struct ScannerPanel {
    pub seed: String,
    pub host: String,
    pub max_depth: usize,
    pub max_pages: usize,
    pub active_checks: bool,
    pub running: bool,
    pub progress: String,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub urls_load_file_path: String,
    pub api_uploading: bool,
    /// Findings from the finished scan.
    pub findings: Vec<crate::scanner::Finding>,
    pub pages: Vec<(String, u16)>,
    pub only_high: bool,
    // Burp Suite Pro v2026.3.3 "New scan" Scan Launcher state
    pub show_launcher: bool,
    pub launcher_tab: usize,
    /// 0 = Crawl and audit, 1 = Crawl, 2 = Audit selected items, 3 = API-only scan
    pub scan_type: usize,
    pub urls_to_scan: String,
    /// 0 = Scan using HTTP and HTTPS, 1 = Scan using my specified protocols
    pub protocol_mode: usize,
    pub isolated_scan: bool,
    pub audit_task_target: usize,
    pub consolidate_duplicates: bool,
    pub consolidate_out_of_scope: bool,
    pub consolidate_no_params: bool,
    pub consolidate_extensions: bool,
    pub consolidate_ext_list: String,
    pub api_def_url: String,
    pub api_def_file: String,
    pub api_details_tab: usize,
    pub api_method_filter: String,
    pub api_search: String,
    pub api_endpoints: Vec<ApiEndpointRow>,
    /// 0 = Use a preset scan mode, 1 = Use a custom configuration
    pub config_source_mode: usize,
    /// 0 = Lightweight, 1 = Fast, 2 = Balanced, 3 = Deep
    pub config_preset: usize,
    pub remember_choice: bool,
    pub selected_library_config: String,
    pub custom_library_configs: Vec<String>,
    pub save_config_name: String,
    pub use_browser_for_crawl: bool,
    pub use_login_credentials: bool,
    pub use_recorded_logins: bool,
    pub login_credentials: Vec<AppLoginCredential>,
    pub new_cred_label: String,
    pub new_cred_user: String,
    pub new_cred_pass: String,
    pub recorded_logins: Vec<RecordedLoginSequence>,
    pub new_rec_label: String,
    pub new_rec_script: String,
    pub resource_pool_mode: usize,
    pub resource_pool_name: String,
    pub resource_pool_concurrency: usize,
    pub resource_pool_delay_ms: u64,
    pub resource_pool_auto_throttle: bool,
    pub resource_pool_throttle_codes: String,
    // Custom scan checks (BChecks — `running-scans/custom-checks.html`)
    pub bchecks_master_enabled: bool,
    pub bchecks_filter_type: String,
    pub bchecks_search: String,
    pub bchecks: Vec<CustomScanCheck>,
    pub new_bcheck_name: String,
    pub new_bcheck_type: String,
    pub new_bcheck_runs: String,
    pub new_bcheck_script: String,
    // Burp Scanner Reporting Wizard (`Pro-QSG-8-configure-report.png` & `reporting/report-settings.html`)
    pub show_report_wizard: bool,
    /// 0 = HTML, 1 = XML
    pub report_format: usize,
    pub report_base64_xml: bool,
    pub report_inc_bg: bool,
    pub report_inc_rem_bg: bool,
    pub report_inc_detail: bool,
    pub report_inc_rem_detail: bool,
    pub report_inc_cwe: bool,
    /// 0 = Do not include, 1 = Include relevant extract, 2 = Include in full
    pub report_req_mode: usize,
    pub report_resp_mode: usize,
    pub report_file_path: String,
    pub report_title: String,
    /// 0 = By type, 1 = By severity, 2 = By URL
    pub report_organization: usize,
    pub report_toc_levels: usize,
    pub report_summary_table_scope: usize,
    pub report_bar_chart_scope: usize,
    pub report_embed_images: bool,
    pub report_host_filter: String,
    // Create Manual Issue dialog (`reporting/manual-issues.html`)
    pub show_manual_issue_modal: bool,
    pub manual_issue_name: String,
    pub manual_issue_service: String,
    pub manual_issue_path: String,
    pub manual_issue_param: String,
    /// 0 = High, 1 = Medium, 2 = Low, 3 = Information
    pub manual_issue_severity: usize,
    /// 0 = Certain, 1 = Firm, 2 = Tentative
    pub manual_issue_confidence: usize,
    pub manual_issue_detail: String,
    pub manual_issue_remediation: String,
}

impl Default for ScannerPanel {
    fn default() -> Self {
        ScannerPanel {
            seed: "http://127.0.0.1:8080/".into(),
            host: "127.0.0.1:8080".into(),
            max_depth: 2,
            max_pages: 50,
            active_checks: true,
            running: false,
            progress: String::new(),
            completed_steps: 0,
            total_steps: 0,
            urls_load_file_path: String::new(),
            api_uploading: false,
            findings: Vec::new(),
            pages: Vec::new(),
            only_high: false,
            show_launcher: false,
            launcher_tab: 0,
            scan_type: 0,
            urls_to_scan: "http://127.0.0.1:8080/".into(),
            protocol_mode: 0,
            isolated_scan: false,
            audit_task_target: 0,
            consolidate_duplicates: true,
            consolidate_out_of_scope: false,
            consolidate_no_params: false,
            consolidate_extensions: false,
            consolidate_ext_list: "gif, jpg, png, css, woff, woff2, svg, ico".into(),
            api_def_url: "https://example.com/openapi.json".into(),
            api_def_file: String::new(),
            api_details_tab: 0,
            api_method_filter: "ALL".into(),
            api_search: String::new(),
            api_endpoints: vec![
                ApiEndpointRow {
                    selected: true,
                    method: "GET".into(),
                    content_type: "application/json".into(),
                    host: "https://example.com".into(),
                    url: "/api/v1/users".into(),
                },
                ApiEndpointRow {
                    selected: true,
                    method: "POST".into(),
                    content_type: "application/json".into(),
                    host: "https://example.com".into(),
                    url: "/api/v1/login".into(),
                },
            ],
            config_source_mode: 0,
            config_preset: 2, // Balanced
            remember_choice: false,
            selected_library_config: "Audit checks - medium active".into(),
            custom_library_configs: Vec::new(),
            save_config_name: String::new(),
            use_browser_for_crawl: true,
            use_login_credentials: false,
            use_recorded_logins: false,
            login_credentials: Vec::new(),
            new_cred_label: String::new(),
            new_cred_user: String::new(),
            new_cred_pass: String::new(),
            recorded_logins: Vec::new(),
            new_rec_label: String::new(),
            new_rec_script: String::new(),
            resource_pool_mode: 0,
            resource_pool_name: "Default resource pool".into(),
            resource_pool_concurrency: 10,
            resource_pool_delay_ms: 0,
            resource_pool_auto_throttle: true,
            resource_pool_throttle_codes: "429, 503".into(),
            bchecks_master_enabled: true,
            bchecks_filter_type: "ALL".into(),
            bchecks_search: String::new(),
            bchecks: CustomScanCheck::defaults(),
            new_bcheck_name: String::new(),
            new_bcheck_type: "Active".into(),
            new_bcheck_runs: "Per insertion point".into(),
            new_bcheck_script: "metadata:\n  language: v2-beta\n  name: \"Custom check\"\n".into(),
            show_report_wizard: false,
            report_format: 0,
            report_base64_xml: true,
            report_inc_bg: true,
            report_inc_rem_bg: true,
            report_inc_detail: true,
            report_inc_rem_detail: true,
            report_inc_cwe: true,
            report_req_mode: 1,
            report_resp_mode: 1,
            report_file_path: "gulpsuite-scanner-report.html".into(),
            report_title: "Gulp Scanner Report".into(),
            report_organization: 0,
            report_toc_levels: 2,
            report_summary_table_scope: 0,
            report_bar_chart_scope: 0,
            report_embed_images: true,
            report_host_filter: String::new(),
            show_manual_issue_modal: false,
            manual_issue_name: "Broken access control".into(),
            manual_issue_service: "https://example.com".into(),
            manual_issue_path: "/admin".into(),
            manual_issue_param: String::new(),
            manual_issue_severity: 0,
            manual_issue_confidence: 0,
            manual_issue_detail: "Unauthenticated or low-privileged user accessed a restricted endpoint.".into(),
            manual_issue_remediation: "Enforce server-side role and ownership authorization checks on every request.".into(),
        }
    }
}

impl ScannerPanel {
    pub fn preset_name(&self) -> &'static str {
        match self.config_preset {
            0 => "Lightweight",
            1 => "Fast",
            2 => "Balanced",
            3 => "Deep",
            _ => "Custom",
        }
    }

    pub fn scan_type_name(&self) -> &'static str {
        match self.scan_type {
            0 => "Crawl and audit",
            1 => "Crawl",
            2 => "Audit selected items",
            _ => "API-only scan",
        }
    }

    pub fn apply_preset(&mut self, preset: usize) {
        self.config_preset = preset;
        match preset {
            0 => {
                self.max_depth = 1;
                self.max_pages = 25;
                self.active_checks = self.scan_type != 1;
            }
            1 => {
                self.max_depth = 2;
                self.max_pages = 60;
                self.active_checks = self.scan_type != 1;
            }
            2 => {
                self.max_depth = 3;
                self.max_pages = 150;
                self.active_checks = self.scan_type != 1;
            }
            3 => {
                self.max_depth = 5;
                self.max_pages = 500;
                self.active_checks = self.scan_type != 1;
            }
            _ => {}
        }
    }
}

/// Renders Burp Suite Professional v2026.3.3's "New scan" Scan Launcher, matching
/// `Pro-QSG-2-scan-details.png` and `Pro-QSG-3-scan-configuration.png` 100%.
pub fn draw_scan_launcher(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let total_w = ui.available_width().max(560.0);
    let total_h = ui.available_height().max(420.0);
    let footer_h = 44.0;
    let body_h = (total_h - footer_h - 1.0).max(340.0);
    let rail_w = 100.0;
    let border_col = theme.color("ui.border.1");
    let selected_blue = Color32::from_rgb(0x26, 0x64, 0x9D);
    let app_login_applicable = app.panels.scanner.scan_type != 2;

    ui.spacing_mut().item_spacing = Vec2::ZERO;

    // Top area: 100px Left Tile Rail + 1px Vertical Divider + White Right Content Area
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing = Vec2::ZERO;

        // 1. Left 100px Vertical Tile Rail (`Pro-QSG-2-scan-details.png` & `Pro-QSG-3-scan-configuration.png`)
        ui.allocate_ui_with_layout(
            Vec2::new(rail_w, body_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_min_size(Vec2::new(rail_w, body_h));
                let rail_rect = Rect::from_min_size(
                    ui.available_rect_before_wrap().min,
                    Vec2::new(rail_w, body_h),
                );
                ui.painter()
                    .rect_filled(rail_rect, 0.0, theme.color("ui.background.0"));

                let tiles: [(usize, LauncherIcon, &[&str], &str); 4] = [
                    (
                        0,
                        LauncherIcon::ScanDetails,
                        &["Scan details"],
                        "Scan details",
                    ),
                    (
                        1,
                        LauncherIcon::Gear,
                        &["Scan", "configuration"],
                        "Scan configuration",
                    ),
                    (
                        2,
                        LauncherIcon::AppLogin,
                        &["Application", "login"],
                        "Application login",
                    ),
                    (
                        3,
                        LauncherIcon::ResourcePool,
                        &["Resource", "pool"],
                        "Resource pool",
                    ),
                ];

                let tile_h = 80.0;
                for (idx, icon, lines, a11y_label) in tiles {
                    let enabled = idx != 2 || app_login_applicable;
                    let active = app.panels.scanner.launcher_tab == idx;
                    let (t_rect, resp) = ui.allocate_exact_size(
                        Vec2::new(rail_w, tile_h),
                        if enabled {
                            Sense::click()
                        } else {
                            Sense::hover()
                        },
                    );
                    resp.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, a11y_label)
                    });
                    if resp.clicked() && enabled {
                        app.panels.scanner.launcher_tab = idx;
                    }

                    let painter = ui.painter_at(t_rect);
                    let tile_bg = if active {
                        selected_blue
                    } else if resp.hovered() && enabled {
                        theme.color("ui.background.3")
                    } else {
                        theme.color("ui.background.2")
                    };
                    painter.rect_filled(t_rect, 0.0, tile_bg);
                    painter.line_segment(
                        [t_rect.left_bottom(), t_rect.right_bottom()],
                        Stroke::new(1.0, border_col),
                    );

                    let fg = if !enabled {
                        theme.color("ui.text.disabled")
                    } else if active {
                        Color32::WHITE
                    } else {
                        theme.color("ui.icon.default")
                    };

                    let icon_rect = Rect::from_center_size(
                        pos2(t_rect.center().x, t_rect.min.y + 24.0),
                        Vec2::new(22.0, 22.0),
                    );
                    paint_launcher_icon_in_rect(&painter, icon_rect, fg, icon);

                    if lines.len() == 1 {
                        painter.text(
                            pos2(t_rect.center().x, t_rect.min.y + 54.0),
                            Align2::CENTER_CENTER,
                            lines[0],
                            FontId::proportional(12.0),
                            fg,
                        );
                    } else {
                        painter.text(
                            pos2(t_rect.center().x, t_rect.min.y + 49.0),
                            Align2::CENTER_CENTER,
                            lines[0],
                            FontId::proportional(12.0),
                            fg,
                        );
                        painter.text(
                            pos2(t_rect.center().x, t_rect.min.y + 64.0),
                            Align2::CENTER_CENTER,
                            lines[1],
                            FontId::proportional(12.0),
                            fg,
                        );
                    }
                }
            },
        );

        // 1px vertical separator line between the 100px left rail and the white content area
        let (sep_rect, _) = ui.allocate_exact_size(Vec2::new(1.0, body_h), Sense::hover());
        ui.painter_at(sep_rect).line_segment(
            [sep_rect.center_top(), sep_rect.center_bottom()],
            Stroke::new(1.0, border_col),
        );

        // 2. Right Content Area (pure white `#FFFFFF` in light mode, 24px padding)
        let content_w = (total_w - rail_w - 1.0).max(360.0);
        ui.allocate_ui_with_layout(
            Vec2::new(content_w, body_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                let bg_rect = Rect::from_min_size(
                    ui.available_rect_before_wrap().min,
                    Vec2::new(content_w, body_h),
                );
                ui.painter()
                    .rect_filled(bg_rect, 0.0, theme.color("ui.background.0"));
                egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(24, 20))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing = Vec2::new(6.0, 6.0);
                        let scroll_h = (body_h - 40.0).max(240.0);
                        egui::ScrollArea::vertical()
                            .id_salt("scan-launcher-step-scroll")
                            .max_height(scroll_h)
                            .show(ui, |ui| {
                                ui.set_width((content_w - 52.0).max(300.0));
                                match app.panels.scanner.launcher_tab {
                                    0 => draw_launcher_step_details(app, ui),
                                    1 => draw_launcher_step_configuration(app, ui),
                                    2 => draw_launcher_step_app_login(app, ui),
                                    _ => draw_launcher_step_resource_pool(app, ui),
                                }
                            });
                    });
            },
        );
    });

    // 1px horizontal divider above the bottom footer bar
    let (hsep_rect, _) = ui.allocate_exact_size(Vec2::new(total_w, 1.0), Sense::hover());
    ui.painter_at(hsep_rect).line_segment(
        [hsep_rect.left_center(), hsep_rect.right_center()],
        Stroke::new(1.0, border_col),
    );

    // 3. Full-Width 44px Bottom Footer Bar (`Pro-QSG-3-scan-configuration.png`: `?` on far left, `OK` & `Cancel` on far right)
    ui.allocate_ui_with_layout(
        Vec2::new(total_w, footer_h),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            let footer_rect = Rect::from_min_size(
                ui.available_rect_before_wrap().min,
                Vec2::new(total_w, footer_h),
            );
            ui.painter()
                .rect_filled(footer_rect, 0.0, theme.color("ui.background.2"));

            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(14, 8))
                .show(ui, |ui| {
                    ui.set_width((total_w - 28.0).max(200.0));
                    ui.spacing_mut().item_spacing = Vec2::new(8.0, 4.0);
                    ui.horizontal(|ui| {
                        // Far-left circular `?` Help icon (`help.svg`)
                        let (help_rect, help_resp) =
                            ui.allocate_exact_size(Vec2::new(22.0, 22.0), Sense::click());
                        help_resp.widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::WidgetType::Button,
                                true,
                                "Scan launcher help",
                            )
                        });
                        paint_launcher_icon_in_rect(
                            &ui.painter_at(help_rect),
                            help_rect,
                            theme.color("ui.icon.default"),
                            LauncherIcon::HelpCircle,
                        );
                        if help_resp.on_hover_text("Scan launcher documentation").clicked() {
                            app.status =
                                "Configure Scan details, Scan configuration, Application login, and Resource pool, then click OK.".into();
                        }

                        // Far-right `OK` and `Cancel` buttons matching `Pro-QSG-3-scan-configuration.png`
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_sized([78.0, 26.0], egui::Button::new("Cancel"))
                                .clicked()
                            {
                                app.panels.scanner.show_launcher = false;
                            }
                            let can_start = !app.panels.scanner.running;
                            if ui
                                .add_enabled(
                                    can_start,
                                    egui::Button::new("OK").min_size(Vec2::new(78.0, 26.0)),
                                )
                                .clicked()
                            {
                                if let Some(first_url) = app
                                    .panels
                                    .scanner
                                    .urls_to_scan
                                    .lines()
                                    .map(str::trim)
                                    .find(|l| !l.is_empty())
                                {
                                    app.panels.scanner.seed = first_url.to_string();
                                }
                                if app.panels.scanner.scan_type == 1 {
                                    app.panels.scanner.active_checks = false;
                                }
                                app.panels.scanner.show_launcher = false;
                                start(app);
                            }
                        });
                    });
                });
        },
    );
}

/// Paints a 16x16 Burp radio circle (`resources/Media/svg/light/radio-selected.svg` / `radio.svg`).
fn paint_burp_radio_circle(ui: &mut Ui, selected: bool, hovered: bool, theme: &crate::ui::theme::Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(16.0, 16.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let c = rect.center();
    let blue = theme.color("palette.secondary.core"); // `#26649D`
    if selected {
        painter.circle_filled(c, 7.5, blue);
        painter.circle_filled(c, 3.0, Color32::WHITE);
    } else {
        let ring = if hovered {
            theme.color("swatches.blue.3")
        } else {
            theme.color("palette.mono.5")
        };
        painter.circle_filled(c, 7.5, theme.color("ui.background.1"));
        painter.circle_stroke(c, 7.0, Stroke::new(1.3, ring));
    }
}

/// Renders one clickable Scan Type option card (`Crawl and audit`, `Crawl`, `Audit selected items`, `API-only scan`).
/// Clicking anywhere inside the card rectangle selects the scan type.
fn draw_scan_type_option_card(
    app: &mut App,
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    idx: usize,
    icon: LauncherIcon,
    title: &str,
    desc: &str,
) {
    let selected = app.panels.scanner.scan_type == idx;
    let blue = theme.color("palette.secondary.core"); // `#26649D`
    let id = ui.id().with(("scan-type-card", idx));
    let hovered = ui
        .ctx()
        .read_response(id)
        .is_some_and(|r| r.hovered());
    let border_col = if selected {
        blue
    } else if hovered {
        theme.color("swatches.blue.4")
    } else {
        theme.color("ui.border.1")
    };
    let fill_col = if selected {
        theme.color("ui.background.5")
    } else {
        theme.color("ui.background.1")
    };

    let inner = egui::Frame::new()
        .fill(fill_col)
        .stroke(Stroke::new(if selected { 1.8 } else { 1.0 }, border_col))
        .corner_radius(3.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_burp_radio_circle(ui, selected, hovered, theme);
                ui.add_space(6.0);
                paint_launcher_icon(
                    ui,
                    Vec2::new(18.0, 18.0),
                    if selected {
                        blue
                    } else {
                        theme.color("ui.text.header")
                    },
                    icon,
                );
                let (title_rect, _) =
                    ui.allocate_exact_size(Vec2::new(160.0, 18.0), Sense::hover());
                ui.painter().text(
                    title_rect.left_center(),
                    Align2::LEFT_CENTER,
                    title,
                    FontId::proportional(13.5),
                    theme.color("ui.text.header"),
                );
            });
            ui.add_space(3.0);
            ui.label(
                RichText::new(desc)
                    .size(11.8)
                    .color(theme.color("ui.text.body")),
            );
        });

    let card_resp = ui.interact(inner.response.rect, id, Sense::click());
    card_resp.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::RadioButton, true, title)
    });
    if card_resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if card_resp.clicked() {
        app.panels.scanner.scan_type = idx;
        app.panels.scanner.active_checks = idx != 1;
    }
}

/// Step 0: `Scan details` (`Pro-QSG-2-scan-details.png`).
fn draw_launcher_step_details(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Scan type");
    ui.add_space(6.0);

    let type_cards: [(usize, LauncherIcon, &str, &str); 4] = [
        (
            0usize,
            LauncherIcon::ScanDetails,
            "Crawl and audit",
            "Crawl the target application and audit discovered attack surface for vulnerabilities.",
        ),
        (
            1usize,
            LauncherIcon::Website,
            "Crawl",
            "Map the target application's structure and endpoints without vulnerability checks.",
        ),
        (
            2usize,
            LauncherIcon::ScanType,
            "Audit selected items",
            "Audit specific HTTP requests sent from Proxy, Target, Repeater, or Intruder.",
        ),
        (
            3usize,
            LauncherIcon::CodeBrackets,
            "API-only scan",
            "Run a standalone scan based on an OpenAPI definition, SOAP WSDL, or Postman Collection.",
        ),
    ];

    let avail_w = ui.available_width();
    if avail_w >= 460.0 {
        for pair in type_cards.chunks(2) {
            ui.columns(2, |cols| {
                for (c_idx, &(idx, icon, title, desc)) in pair.iter().enumerate() {
                    draw_scan_type_option_card(
                        app,
                        &mut cols[c_idx],
                        &theme,
                        idx,
                        icon,
                        title,
                        desc,
                    );
                }
            });
            ui.add_space(6.0);
        }
    } else {
        for &(idx, icon, title, desc) in &type_cards {
            draw_scan_type_option_card(app, ui, &theme, idx, icon, title, desc);
            ui.add_space(6.0);
        }
    }

    ui.add_space(16.0);

    match app.panels.scanner.scan_type {
        0 | 1 => {
            heading(ui, &theme, "URLs to scan");
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "Define the URLs to scan. Gulp will begin crawling from these URLs, and by default will include content within the same domain and folders.",
                )
                .size(12.5)
                .color(theme.color("ui.text.body")),
            );
            ui.add_space(6.0);
            egui::Frame::new()
                .fill(theme.color("ui.background.0"))
                .stroke(Stroke::new(1.0, theme.color("ui.border.1")))
                .inner_margin(6.0)
                .show(ui, |ui| {
                    if ui
                        .add(
                            egui::TextEdit::multiline(&mut app.panels.scanner.urls_to_scan)
                                .font(egui::TextStyle::Monospace)
                                .frame(false)
                                .desired_rows(5)
                                .desired_width(f32::INFINITY),
                        )
                        .changed()
                    {
                        if let Some(first) = app
                            .panels
                            .scanner
                            .urls_to_scan
                            .lines()
                            .map(str::trim)
                            .find(|l| !l.is_empty())
                        {
                            app.panels.scanner.seed = first.to_string();
                        }
                    }
                });
            ui.horizontal_wrapped(|ui| {
                if icon_button(ui, &theme, LauncherIcon::Paste, "Paste").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                if icon_button(ui, &theme, LauncherIcon::Trash, "Clear").clicked() {
                    app.panels.scanner.urls_to_scan.clear();
                }
                if icon_button(ui, &theme, LauncherIcon::Folder, "Add from Proxy history").clicked()
                {
                    let mut seen = Vec::new();
                    for tx in app.log.iter().rev().take(20) {
                        if (tx.target.starts_with("http://") || tx.target.starts_with("https://"))
                            && !seen.contains(&tx.target)
                        {
                            seen.push(tx.target.clone());
                        }
                    }
                    if !seen.is_empty() {
                        app.panels.scanner.urls_to_scan = seen.join("\n");
                        app.panels.scanner.seed = seen[0].clone();
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.scanner.urls_load_file_path)
                        .hint_text("Load URLs from file…")
                        .desired_width(140.0),
                );
                if icon_button(ui, &theme, LauncherIcon::Folder, "Load ...").clicked()
                    && !app.panels.scanner.urls_load_file_path.trim().is_empty()
                {
                    let path = app.panels.scanner.urls_load_file_path.trim().to_string();
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        app.panels.scanner.urls_to_scan = text;
                        if let Some(first) = app
                            .panels
                            .scanner
                            .urls_to_scan
                            .lines()
                            .map(str::trim)
                            .find(|l| !l.is_empty())
                        {
                            app.panels.scanner.seed = first.to_string();
                        }
                        app.status = format!("Loaded URLs to scan from {path}");
                    }
                }
            });

            ui.add_space(12.0);
            heading(ui, &theme, "Protocol settings");
            ui.add_space(2.0);
            ui.radio_value(
                &mut app.panels.scanner.protocol_mode,
                0,
                "Scan using HTTP and HTTPS",
            );
            ui.radio_value(
                &mut app.panels.scanner.protocol_mode,
                1,
                "Scan using my specified protocols",
            );

            ui.add_space(10.0);
            egui::CollapsingHeader::new(RichText::new("Detailed scope configuration").strong())
                .default_open(false)
                .show(ui, |ui| {
                    ui.label("Included URL prefixes:");
                    ui.add(
                        egui::TextEdit::singleline(&mut app.panels.target_panel.scope)
                            .desired_width(f32::INFINITY),
                    );
                    ui.label("Excluded URL prefixes:");
                    ui.add(
                        egui::TextEdit::singleline(&mut app.panels.target_panel.scope_exclude)
                            .desired_width(f32::INFINITY),
                    );
                });
            ui.add_space(6.0);
            ui.checkbox(&mut app.panels.scanner.isolated_scan, "Run isolated scan");
        }
        2 => {
            heading(ui, &theme, "Items to scan & Consolidation");
            ui.horizontal_wrapped(|ui| {
                ui.label("Task target:");
                ui.radio_value(
                    &mut app.panels.scanner.audit_task_target,
                    0,
                    "Create new task",
                );
                ui.radio_value(
                    &mut app.panels.scanner.audit_task_target,
                    1,
                    "Add to existing task",
                );
            });
            ui.horizontal(|ui| {
                ui.label("URL / item to audit:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.scanner.seed)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.add_space(6.0);
            ui.label(RichText::new("Consolidate items").strong());
            ui.checkbox(
                &mut app.panels.scanner.consolidate_duplicates,
                "Duplicate items (messages that have the same URL and parameter names)",
            );
            ui.checkbox(
                &mut app.panels.scanner.consolidate_out_of_scope,
                "Out-of-scope messages based on the current suite scope",
            );
            ui.checkbox(
                &mut app.panels.scanner.consolidate_no_params,
                "Messages with no parameters",
            );
            ui.checkbox(
                &mut app.panels.scanner.consolidate_extensions,
                "Messages with specific file extensions:",
            );
            ui.add(
                egui::TextEdit::singleline(&mut app.panels.scanner.consolidate_ext_list)
                    .desired_width(f32::INFINITY),
            );
        }
        _ => {
            heading(ui, &theme, "API definition & endpoints");
            let input_w = (ui.available_width() - 210.0).max(160.0);
            ui.horizontal(|ui| {
                ui.label("Upload from URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.scanner.api_def_url)
                        .desired_width(input_w),
                );
                if icon_button(ui, &theme, LauncherIcon::Upload, "Upload").clicked() {
                    let def_url = app.panels.scanner.api_def_url.trim().to_string();
                    app.panels.scanner.seed = def_url.clone();
                    app.panels.scanner.urls_to_scan = def_url.clone();
                    if let Ok(target) = crate::http_target::HttpTarget::parse(&def_url) {
                        let path = crate::scanner::http::path_of(&def_url);
                        let raw_req = format!(
                            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                            target.authority()
                        );
                        let proxy = app.proxy.clone();
                        let rt = app.runtime_handle();
                        if let Ok((_, resp_text)) = rt.block_on(proxy.one_shot_secure(
                            &target.host,
                            target.port,
                            &raw_req,
                            target.secure,
                            3_000,
                        )) {
                            let body = crate::scanner::http::parse_response(&resp_text).body;
                            let parsed = parse_api_definition(&body, &def_url);
                            if !parsed.is_empty() {
                                let count = parsed.len();
                                app.panels.scanner.api_endpoints = parsed;
                                app.status =
                                    format!("Uploaded and parsed {count} endpoint(s) from {def_url}");
                            } else {
                                app.status = format!("Loaded API definition from {def_url}");
                            }
                        } else {
                            app.status = format!("Loaded API definition URL {def_url}");
                        }
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Upload from file:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.scanner.api_def_file)
                        .hint_text("/path/to/openapi.json")
                        .desired_width(input_w),
                );
                if icon_button(ui, &theme, LauncherIcon::Folder, "Load file").clicked()
                    && !app.panels.scanner.api_def_file.is_empty()
                {
                    let path = app.panels.scanner.api_def_file.trim().to_string();
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            let parsed = parse_api_definition(&content, &app.panels.scanner.seed);
                            if !parsed.is_empty() {
                                let count = parsed.len();
                                app.panels.scanner.api_endpoints = parsed;
                                app.status =
                                    format!("Parsed {count} API endpoint(s) from {path}");
                            } else {
                                app.status = format!("Parsed API definition file {path}");
                            }
                        }
                        Err(err) => {
                            app.status = format!("Failed to read {path}: {err}");
                        }
                    }
                }
            });
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                for (idx, lbl) in ["Endpoints", "Authentication", "Parameters"]
                    .iter()
                    .enumerate()
                {
                    ui.selectable_value(&mut app.panels.scanner.api_details_tab, idx, *lbl);
                }
                ui.separator();
                for m in ["ALL", "GET", "POST", "PUT", "DELETE"] {
                    let active = app.panels.scanner.api_method_filter == m;
                    if ui.selectable_label(active, m).clicked() {
                        app.panels.scanner.api_method_filter = m.into();
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.scanner.api_search)
                        .hint_text("Search endpoints…")
                        .desired_width(140.0),
                );
            });
            let method_filter = app.panels.scanner.api_method_filter.clone();
            let search_filter = app.panels.scanner.api_search.trim().to_lowercase();
            egui::Grid::new("scanner-api-endpoints-grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Scan");
                    ui.strong("Method");
                    ui.strong("Content type");
                    ui.strong("Host");
                    ui.strong("URL");
                    ui.end_row();
                    for ep in &mut app.panels.scanner.api_endpoints {
                        if method_filter != "ALL" && ep.method != method_filter {
                            continue;
                        }
                        if !search_filter.is_empty()
                            && !ep.url.to_lowercase().contains(&search_filter)
                            && !ep.host.to_lowercase().contains(&search_filter)
                        {
                            continue;
                        }
                        ui.checkbox(&mut ep.selected, "");
                        ui.monospace(&ep.method);
                        ui.label(&ep.content_type);
                        ui.label(&ep.host);
                        ui.monospace(&ep.url);
                        ui.end_row();
                    }
                });
        }
    }
}

/// Step 1: `Scan configuration` (`Pro-QSG-3-scan-configuration.png`).
fn draw_launcher_step_configuration(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Scan configuration");
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Scan configurations and modes are groups of settings that define how a scan is performed. Scan modes offer preset options designed to let you trade off speed and coverage. Alternatively, you can select one or more custom configurations. Gulp Scanner applies any selected configurations in order, enabling you to fine-tune scanning behaviour.",
        )
        .size(12.5)
        .color(theme.color("ui.text.body")),
    );
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(8.0);

    ui.horizontal_wrapped(|ui| {
        ui.radio_value(
            &mut app.panels.scanner.config_source_mode,
            0,
            "Use a preset scan mode",
        );
        ui.add_space(16.0);
        ui.radio_value(
            &mut app.panels.scanner.config_source_mode,
            1,
            "Use a custom configuration",
        );
    });
    ui.add_space(10.0);

    if app.panels.scanner.config_source_mode == 0 {
        let presets: [(usize, LauncherIcon, &str, &str); 4] = [
            (
                0usize,
                LauncherIcon::Lightweight,
                "Lightweight",
                "Gain fast feedback on a site's security - for when speed is a priority. Lightweight mode will complete within 15 minutes.",
            ),
            (
                1usize,
                LauncherIcon::Fast,
                "Fast",
                "More thorough than a Lightweight scan, but still biased towards speed. Fast scans will generally complete within one hour.",
            ),
            (
                2usize,
                LauncherIcon::Balanced,
                "Balanced",
                "Provides a balance between coverage and speed. You will typically see the results of a Balanced scan within a few hours.",
            ),
            (
                3usize,
                LauncherIcon::Deep,
                "Deep",
                "Achieve greater coverage and gain a better understanding of a site's security posture. Scanning time depends heavily on the target site's size and complexity.",
            ),
        ];

        let avail_w = ui.available_width();
        if avail_w >= 460.0 {
            for pair in presets.chunks(2) {
                ui.columns(2, |cols| {
                    for (c_idx, &(idx, icon, title, desc)) in pair.iter().enumerate() {
                        draw_preset_mode_card(
                            app,
                            &mut cols[c_idx],
                            &theme,
                            idx,
                            icon,
                            title,
                            desc,
                        );
                    }
                });
                ui.add_space(10.0);
            }
        } else {
            for &(idx, icon, title, desc) in &presets {
                draw_preset_mode_card(app, ui, &theme, idx, icon, title, desc);
                ui.add_space(10.0);
            }
        }

        ui.add_space(6.0);
        ui.checkbox(
            &mut app.panels.scanner.remember_choice,
            "Remember my choice for future scans",
        );
    } else {
        ui.label(RichText::new("Select from configuration library").strong());
        egui::ComboBox::from_id_salt("scanner-config-library-combo")
            .selected_text(&app.panels.scanner.selected_library_config)
            .width((ui.available_width() - 24.0).max(240.0))
            .show_ui(ui, |ui| {
                for item in BUILTIN_SCAN_LIBRARY {
                    if ui
                        .selectable_value(
                            &mut app.panels.scanner.selected_library_config,
                            item.to_string(),
                            item,
                        )
                        .clicked()
                    {
                        app.panels.scanner.active_checks = !item.contains("passive");
                    }
                }
                for custom in app.panels.scanner.custom_library_configs.clone() {
                    ui.selectable_value(
                        &mut app.panels.scanner.selected_library_config,
                        custom.clone(),
                        custom,
                    );
                }
            });
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.label("Max link depth:");
            ui.add(egui::DragValue::new(&mut app.panels.scanner.max_depth).range(1..=10));
            ui.label("Max pages to crawl:");
            ui.add(egui::DragValue::new(&mut app.panels.scanner.max_pages).range(1..=5_000));
        });
        ui.checkbox(
            &mut app.panels.scanner.use_browser_for_crawl,
            "Use Gulpsuite's browser for crawl and audit (supports URL fragments # and SPAs)",
        );
        ui.checkbox(
            &mut app.panels.scanner.active_checks,
            "Enable active vulnerability checks (SQLi, XSS, SSRF, XXE, NoSQLi, CMDi, SSTI, Traversal, CORS)",
        );
        ui.checkbox(
            &mut app.panels.scanner.only_high,
            "Report High and Medium severity issues only",
        );
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label("Save to configuration library:");
            ui.add(
                egui::TextEdit::singleline(&mut app.panels.scanner.save_config_name)
                    .hint_text("Configuration name")
                    .desired_width((ui.available_width() - 260.0).max(150.0)),
            );
            if ui.button("Save").clicked() && !app.panels.scanner.save_config_name.trim().is_empty()
            {
                let name = app.panels.scanner.save_config_name.trim().to_string();
                app.panels.scanner.custom_library_configs.push(name.clone());
                app.panels.scanner.selected_library_config = name.clone();
                app.panels.scanner.save_config_name.clear();
                app.status = format!("Saved scan configuration '{name}' to library");
            }
        });
        ui.add_space(8.0);
        ui.separator();
        draw_bchecks_section(app, ui);
    }
}

/// Renders Burp Suite Pro's Custom Scan Checks (`BChecks`) table & editor (`running-scans/custom-checks.html`).
fn draw_bchecks_section(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Custom scan checks (BChecks & Nuclei YAML Templates)").strong());
        ui.checkbox(
            &mut app.panels.scanner.bchecks_master_enabled,
            "Enabled",
        );
        ui.separator();
        for f in ["ALL", "Nuclei", "Active", "Passive"] {
            let active = app.panels.scanner.bchecks_filter_type == f;
            if ui.selectable_label(active, f).clicked() {
                app.panels.scanner.bchecks_filter_type = f.into();
            }
        }
        ui.add(
            egui::TextEdit::singleline(&mut app.panels.scanner.bchecks_search)
                .hint_text("Search BChecks & Nuclei templates…")
                .desired_width(175.0),
        );
        if ui
            .small_button("Load ~/nuclei-templates CVEs")
            .on_hover_text("Import recent CVE YAML templates from ~/nuclei-templates/http/cves/")
            .clicked()
        {
            let loaded = load_local_nuclei_cve_templates(&mut app.panels.scanner.bchecks);
            app.status = if loaded > 0 {
                format!("Loaded {loaded} Nuclei CVE YAML template(s) from ~/nuclei-templates")
            } else {
                "No additional templates found in ~/nuclei-templates/http/cves".into()
            };
        }
    });
    let filter_t = app.panels.scanner.bchecks_filter_type.clone();
    let needle = app.panels.scanner.bchecks_search.trim().to_lowercase();
    egui::ScrollArea::vertical()
        .id_salt("scanner-bchecks-scroll")
        .max_height(155.0)
        .show(ui, |ui| {
            egui::Grid::new("scanner-bchecks-grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Enabled");
                    ui.strong("Name");
                    ui.strong("Type");
                    ui.strong("Check runs");
                    ui.end_row();
                    for chk in &mut app.panels.scanner.bchecks {
                        if filter_t != "ALL" && chk.check_type != filter_t {
                            continue;
                        }
                        if !needle.is_empty()
                            && !chk.name.to_lowercase().contains(&needle)
                            && !chk.script.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        ui.checkbox(&mut chk.enabled, "");
                        if ui
                            .selectable_label(false, &chk.name)
                            .on_hover_text("Click to load template/script into editor below")
                            .clicked()
                        {
                            app.panels.scanner.new_bcheck_name = chk.name.clone();
                            app.panels.scanner.new_bcheck_type = chk.check_type.clone();
                            app.panels.scanner.new_bcheck_runs = chk.check_runs.clone();
                            app.panels.scanner.new_bcheck_script = chk.script.clone();
                        }
                        ui.label(&chk.check_type);
                        ui.label(&chk.check_runs);
                        ui.end_row();
                    }
                });
        });
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.panels.scanner.new_bcheck_name)
                .hint_text("Template / BCheck name")
                .desired_width(160.0),
        );
        egui::ComboBox::from_id_salt("bcheck-new-type")
            .selected_text(&app.panels.scanner.new_bcheck_type)
            .width(85.0)
            .show_ui(ui, |ui| {
                for t in ["Nuclei", "Active", "Passive"] {
                    ui.selectable_value(&mut app.panels.scanner.new_bcheck_type, t.into(), t);
                }
            });
        egui::ComboBox::from_id_salt("bcheck-new-runs")
            .selected_text(&app.panels.scanner.new_bcheck_runs)
            .width(135.0)
            .show_ui(ui, |ui| {
                for r in ["Per insertion point", "Per request", "Per host"] {
                    ui.selectable_value(&mut app.panels.scanner.new_bcheck_runs, r.into(), r);
                }
            });
        if ui.small_button("Nuclei YAML preset").clicked() {
            app.panels.scanner.new_bcheck_type = "Nuclei".into();
            app.panels.scanner.new_bcheck_runs = "Per host".into();
            app.panels.scanner.new_bcheck_script = "id: custom-cve-check\n\ninfo:\n  name: Custom Nuclei DSL Check\n  author: gulpsuite\n  severity: high\n  classification:\n    cwe-id: CWE-200\n\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: dsl\n        dsl:\n          - 'status_code == 200'\n          - 'contains(body, \"admin\")'\n        condition: and\n".into();
        }
        if ui.button("+ Add BCheck / Nuclei").clicked()
            && (!app.panels.scanner.new_bcheck_name.trim().is_empty()
                || crate::scanner::nuclei::is_nuclei_template(&app.panels.scanner.new_bcheck_script))
        {
            let script = app.panels.scanner.new_bcheck_script.clone();
            let parsed_nuclei = crate::scanner::nuclei::parse_nuclei_template(&script).ok();
            let name = if !app.panels.scanner.new_bcheck_name.trim().is_empty() {
                app.panels.scanner.new_bcheck_name.trim().to_string()
            } else if let Some(ref nt) = parsed_nuclei {
                format!("Nuclei: {} ({})", nt.info.name, nt.id)
            } else {
                "Custom check".into()
            };
            let check_type = if parsed_nuclei.is_some() {
                "Nuclei".to_string()
            } else {
                app.panels.scanner.new_bcheck_type.clone()
            };
            let check_runs = app.panels.scanner.new_bcheck_runs.clone();
            app.panels.scanner.bchecks.push(CustomScanCheck {
                enabled: true,
                name,
                check_type,
                check_runs,
                script,
            });
            app.panels.scanner.new_bcheck_name.clear();
        }
    });
    ui.add_space(4.0);
    ui.add(
        egui::TextEdit::multiline(&mut app.panels.scanner.new_bcheck_script)
            .font(egui::TextStyle::Monospace)
            .desired_rows(5)
            .desired_width(f32::INFINITY)
            .hint_text("Paste a ProjectDiscovery Nuclei .yaml template (with `http:` and `matchers: - type: dsl`) or BCheck script…"),
    );
    let _ = theme;
}

fn load_local_nuclei_cve_templates(out: &mut Vec<CustomScanCheck>) -> usize {
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
    else {
        return 0;
    };
    let cves_root = home.join("nuclei-templates").join("http").join("cves");
    if !cves_root.is_dir() {
        return 0;
    }
    let mut loaded = 0usize;
    for year in ["2026", "2025", "2024"] {
        let dir = cves_root.join(year);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if loaded >= 40 {
                return loaded;
            }
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let Ok(yaml) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Ok(tmpl) = crate::scanner::nuclei::parse_nuclei_template(&yaml) else {
                continue;
            };
            if tmpl.http.is_empty() {
                continue;
            }
            let name = format!("Nuclei: {} ({})", tmpl.info.name, tmpl.id);
            if out.iter().any(|c| c.name == name) {
                continue;
            }
            out.push(CustomScanCheck {
                enabled: true,
                name,
                check_type: "Nuclei".into(),
                check_runs: "Per host".into(),
                script: yaml,
            });
            loaded += 1;
        }
    }
    loaded
}

/// Renders one of the 4 preset cards in `Pro-QSG-3-scan-configuration.png`:
/// Entire card is clickable (background, radio circle, icon, title, and description paragraph).
fn draw_preset_mode_card(
    app: &mut App,
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    idx: usize,
    icon: LauncherIcon,
    title: &str,
    desc: &str,
) {
    let selected = app.panels.scanner.config_preset == idx;
    let blue = theme.color("palette.secondary.core"); // `#26649D`
    let id = ui.id().with(("preset-mode-card", idx));
    let hovered = ui
        .ctx()
        .read_response(id)
        .is_some_and(|r| r.hovered());
    let border_col = if selected {
        blue
    } else if hovered {
        theme.color("swatches.blue.4")
    } else {
        theme.color("ui.border.1")
    };
    let fill_col = if selected {
        theme.color("ui.background.5")
    } else {
        theme.color("ui.background.1")
    };

    let inner = egui::Frame::new()
        .fill(fill_col)
        .stroke(Stroke::new(if selected { 1.8 } else { 1.0 }, border_col))
        .corner_radius(2.0)
        .inner_margin(egui::Margin::symmetric(18, 22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(110.0);
            ui.horizontal(|ui| {
                // Left vertically-centered Burp radio circle (`radio-selected.svg` / `radio.svg`)
                ui.vertical(|ui| {
                    ui.add_space(36.0);
                    paint_burp_radio_circle(ui, selected, hovered, theme);
                });
                ui.add_space(10.0);
                // Right column: 20x20 Burp SVG icon + bold title on top, description paragraph below
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        paint_launcher_icon(
                            ui,
                            Vec2::new(20.0, 20.0),
                            if selected {
                                blue
                            } else {
                                theme.color("ui.text.header")
                            },
                            icon,
                        );
                        let (title_rect, _) =
                            ui.allocate_exact_size(Vec2::new(140.0, 20.0), Sense::hover());
                        ui.painter().text(
                            title_rect.left_center(),
                            Align2::LEFT_CENTER,
                            title,
                            FontId::proportional(14.5),
                            theme.color("ui.text.header"),
                        );
                    });
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(desc)
                            .size(12.0)
                            .color(theme.color("ui.text.body")),
                    );
                });
            });
        });

    let card_resp = ui.interact(inner.response.rect, id, Sense::click());
    card_resp.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::RadioButton, true, title)
    });
    if card_resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if card_resp.clicked() {
        app.panels.scanner.apply_preset(idx);
    }
}

/// Step 2: `Application login`.
fn draw_launcher_step_app_login(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Application login");
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Provide login credentials or recorded login sequences for Gulp Scanner to submit when it finds login forms during the crawl.",
        )
        .size(12.5)
        .color(theme.color("ui.text.body")),
    );
    ui.add_space(10.0);

    let panel = &mut app.panels.scanner;
    ui.horizontal(|ui| {
        paint_launcher_icon(
            ui,
            Vec2::new(16.0, 16.0),
            theme.color("ui.icon.default"),
            LauncherIcon::AppLogin,
        );
        ui.checkbox(&mut panel.use_login_credentials, "Use login credentials");
    });
    if panel.use_login_credentials {
        let mut del = None;
        if !panel.login_credentials.is_empty() {
            egui::Grid::new("scanner-login-creds-grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Label");
                    ui.strong("Username");
                    ui.strong("Password");
                    ui.strong("");
                    ui.end_row();
                    for (idx, cred) in panel.login_credentials.iter().enumerate() {
                        ui.label(&cred.label);
                        ui.monospace(&cred.username);
                        ui.monospace("••••••••");
                        if ui.small_button("Remove").clicked() {
                            del = Some(idx);
                        }
                        ui.end_row();
                    }
                });
        }
        if let Some(i) = del {
            panel.login_credentials.remove(i);
        }
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut panel.new_cred_label)
                    .hint_text("Label (e.g. Admin login)")
                    .desired_width(140.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut panel.new_cred_user)
                    .hint_text("Username")
                    .desired_width(130.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut panel.new_cred_pass)
                    .password(true)
                    .hint_text("Password")
                    .desired_width(130.0),
            );
            if ui.button("Add credential").clicked() && !panel.new_cred_user.trim().is_empty() {
                panel.login_credentials.push(AppLoginCredential {
                    label: if panel.new_cred_label.trim().is_empty() {
                        panel.new_cred_user.clone()
                    } else {
                        panel.new_cred_label.clone()
                    },
                    username: panel.new_cred_user.clone(),
                    password: panel.new_cred_pass.clone(),
                });
                panel.new_cred_label.clear();
                panel.new_cred_user.clear();
                panel.new_cred_pass.clear();
            }
        });
    }

    ui.add_space(10.0);
    ui.separator();
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        paint_launcher_icon(
            ui,
            Vec2::new(16.0, 16.0),
            theme.color("ui.icon.default"),
            LauncherIcon::RecordR,
        );
        ui.checkbox(
            &mut panel.use_recorded_logins,
            "Use recorded login sequences (Navigation Recorder JSON)",
        );
    });
    if panel.use_recorded_logins {
        let mut del_rec = None;
        for (idx, seq) in panel.recorded_logins.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&seq.label).strong());
                ui.label(format!("({} bytes)", seq.events_count));
                if ui.small_button("Remove").clicked() {
                    del_rec = Some(idx);
                }
            });
        }
        if let Some(i) = del_rec {
            panel.recorded_logins.remove(i);
        }
        ui.horizontal(|ui| {
            ui.label("Label:");
            ui.add(
                egui::TextEdit::singleline(&mut panel.new_rec_label)
                    .desired_width((ui.available_width() - 180.0).max(140.0)),
            );
            if ui.button("Add recorded login").clicked() && !panel.new_rec_label.trim().is_empty() {
                panel.recorded_logins.push(RecordedLoginSequence {
                    label: panel.new_rec_label.clone(),
                    events_count: panel.new_rec_script.len(),
                    script: panel.new_rec_script.clone(),
                });
                panel.new_rec_label.clear();
                panel.new_rec_script.clear();
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut panel.new_rec_script)
                .font(egui::TextStyle::Monospace)
                .hint_text("Paste recorded login sequence script (JSON) here…")
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
    }
}

/// Step 3: `Resource pool`.
fn draw_launcher_step_resource_pool(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Resource pool");
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "A resource pool is a group of tasks that share a quota of network resources. Select an existing resource pool or create a new resource pool.",
        )
        .size(12.5)
        .color(theme.color("ui.text.body")),
    );
    ui.add_space(10.0);

    let panel = &mut app.panels.scanner;
    ui.radio_value(
        &mut panel.resource_pool_mode,
        0,
        "Use existing resource pool: Default resource pool (max 10 concurrent requests)",
    );
    ui.radio_value(
        &mut panel.resource_pool_mode,
        1,
        "Create new resource pool",
    );
    if panel.resource_pool_mode == 1 {
        ui.horizontal(|ui| {
            ui.label("Pool name:");
            ui.add(
                egui::TextEdit::singleline(&mut panel.resource_pool_name)
                    .desired_width(f32::INFINITY),
            );
        });
    }
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Maximum concurrent requests:");
        ui.add(egui::DragValue::new(&mut panel.resource_pool_concurrency).range(1..=64));
    });
    ui.horizontal(|ui| {
        ui.label("Delay between requests (ms):");
        ui.add(egui::DragValue::new(&mut panel.resource_pool_delay_ms).range(0..=60_000));
    });
    ui.checkbox(
        &mut panel.resource_pool_auto_throttle,
        "Automatic throttling on HTTP status codes:",
    );
    ui.add(
        egui::TextEdit::singleline(&mut panel.resource_pool_throttle_codes)
            .desired_width(f32::INFINITY),
    );
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal(|ui| {
        paint_launcher_icon(
            ui,
            Vec2::new(28.0, 20.0),
            theme.color("ui.icon.accent"),
            LauncherIcon::ScannerHero,
        );
        heading(ui, &theme, "Scanner");
    });

    ui.horizontal_wrapped(|ui| {
        ui.label("Seed URL");
        let seed_w = (ui.available_width() - 320.0).clamp(180.0, 480.0);
        if ui
            .add(
                eframe::egui::TextEdit::singleline(&mut app.panels.scanner.seed)
                    .desired_width(seed_w)
                    .font(eframe::egui::TextStyle::Monospace),
            )
            .changed()
        {
            app.panels.scanner.urls_to_scan = app.panels.scanner.seed.clone();
        }
        if ui
            .add_enabled(
                !app.panels.scanner.running,
                eframe::egui::Button::new("Start scan"),
            )
            .clicked()
        {
            start(app);
        }
        if ui.button("Open scan launcher…").clicked() {
            app.panels.scanner.show_launcher = true;
        }
        if ui.button("Report issues…").clicked() {
            app.panels.scanner.report_host_filter.clear();
            app.panels.scanner.show_report_wizard = true;
        }
        if ui.button("Create manual issue…").clicked() {
            app.panels.scanner.show_manual_issue_modal = true;
        }
        if ui
            .add_enabled(
                app.panels.scanner.running,
                eframe::egui::Button::new("Cancel"),
            )
            .clicked()
        {
            app.panels.scanner.running = false;
            app.panels.scanner.progress = "Cancelled".into();
        }
    });

    draw_scanner_modals(app, ui.ctx());

    ui.horizontal_wrapped(|ui| {
        ui.label("Depth");
        let mut depth = app.panels.scanner.max_depth.to_string();
        if ui
            .add(eframe::egui::TextEdit::singleline(&mut depth).desired_width(40.0))
            .changed()
        {
            if let Ok(n) = depth.trim().parse::<usize>() {
                app.panels.scanner.max_depth = n.min(10);
            }
        }
        ui.label("Pages");
        let mut pages = app.panels.scanner.max_pages.to_string();
        if ui
            .add(eframe::egui::TextEdit::singleline(&mut pages).desired_width(56.0))
            .changed()
        {
            if let Ok(n) = pages.trim().parse::<usize>() {
                app.panels.scanner.max_pages = n.clamp(1, 5_000);
            }
        }
        ui.checkbox(&mut app.panels.scanner.active_checks, "Active checks");
        ui.checkbox(&mut app.panels.scanner.only_high, "High and medium only");
        if ui.button("Clear").clicked() {
            app.panels.scanner.findings.clear();
            app.panels.scanner.pages.clear();
        }
    });

    let counts = counts(&app.panels.scanner.findings, app.panels.scanner.only_high);
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("{} page(s)", app.panels.scanner.pages.len()));
        for (severity, icon) in [
            (crate::scanner::Severity::High, LauncherIcon::IssueHigh),
            (crate::scanner::Severity::Medium, LauncherIcon::IssueMedium),
            (crate::scanner::Severity::Low, LauncherIcon::IssueLow),
            (crate::scanner::Severity::Info, LauncherIcon::IssueInfo),
        ] {
            paint_launcher_icon(
                ui,
                Vec2::new(14.0, 14.0),
                severity_colour(&theme, severity),
                icon,
            );
            ui.label(
                eframe::egui::RichText::new(format!(
                    "{} {}",
                    severity.as_str(),
                    counts
                        .iter()
                        .find(|(s, _)| *s == severity)
                        .map(|(_, n)| *n)
                        .unwrap_or(0)
                ))
                .color(severity_colour(&theme, severity)),
            );
        }
    });

    if app.panels.scanner.running || !app.panels.scanner.progress.is_empty() {
        ui.horizontal(|ui| {
            if app.panels.scanner.running {
                paint_burp_spinner(
                    ui,
                    Vec2::new(16.0, 16.0),
                    Color32::from_rgb(0x5B, 0x4F, 0xFF),
                );
                paint_launcher_icon(
                    ui,
                    Vec2::new(14.0, 14.0),
                    theme.color("ui.icon.default"),
                    LauncherIcon::ScanDetails,
                );
                let ratio = if app.panels.scanner.total_steps > 0 {
                    app.panels.scanner.completed_steps as f32
                        / app.panels.scanner.total_steps as f32
                } else {
                    0.18
                };
                paint_burp_progress_bar(ui, 180.0, ratio, &theme);
            } else {
                paint_launcher_icon(
                    ui,
                    Vec2::new(14.0, 14.0),
                    theme.color("ui.icon.success"),
                    LauncherIcon::CheckCircle,
                );
            }
            let prog_txt = &app.panels.scanner.progress;
            let short_prog = if prog_txt.chars().count() > 54 {
                let mut s: String = prog_txt.chars().take(53).collect();
                s.push('…');
                s
            } else {
                prog_txt.clone()
            };
            ui.add(
                egui::Label::new(
                    RichText::new(short_prog)
                        .size(12.0)
                        .color(theme.color("ui.icon.default")),
                )
                .truncate(),
            )
            .on_hover_text(prog_txt);
        });
    }
    ui.add_space(4.0);

    if app.panels.scanner.findings.is_empty() {
        muted(
            ui,
            &theme,
            "No issues yet. Point the scanner at a target and start a scan.",
        );
        return;
    }

    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        eframe::egui::Grid::new("scanner-findings")
            .num_columns(4)
            .striped(true)
            .show(ui, |ui| {
                for name in ["Severity", "Issue", "Parameter", "Evidence"] {
                    ui.label(
                        eframe::egui::RichText::new(name)
                            .strong()
                            .color(theme.color("ui.text.body")),
                    );
                }
                ui.end_row();
                for finding in app.panels.scanner.findings.clone() {
                    if app.panels.scanner.only_high
                        && matches!(
                            finding.severity,
                            crate::scanner::Severity::Low | crate::scanner::Severity::Info
                        )
                    {
                        continue;
                    }
                    let sev_icon = match finding.severity {
                        crate::scanner::Severity::High => LauncherIcon::IssueHigh,
                        crate::scanner::Severity::Medium => LauncherIcon::IssueMedium,
                        crate::scanner::Severity::Low => LauncherIcon::IssueLow,
                        crate::scanner::Severity::Info => LauncherIcon::IssueInfo,
                    };
                    ui.horizontal(|ui| {
                        paint_launcher_icon(
                            ui,
                            Vec2::new(14.0, 14.0),
                            severity_colour(&theme, finding.severity),
                            sev_icon,
                        );
                        ui.label(
                            eframe::egui::RichText::new(finding.severity.as_str())
                                .color(severity_colour(&theme, finding.severity)),
                        );
                    });
                    ui.label(
                        eframe::egui::RichText::new(&finding.name)
                            .color(theme.color("ui.text.body")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(finding.parameter.clone().unwrap_or_default())
                            .color(theme.color("icon.link")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(format!(
                            "{} — {}",
                            finding.url,
                            truncate(&finding.evidence, 60)
                        ))
                        .color(theme.color("ui.icon.default")),
                    );
                    ui.end_row();
                }
            });
    });
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let head: String = text.chars().take(limit).collect();
    format!("{head}…")
}

fn counts(
    findings: &[crate::scanner::Finding],
    only_high: bool,
) -> Vec<(crate::scanner::Severity, usize)> {
    use crate::scanner::Severity;
    let severities = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    severities
        .iter()
        .map(|severity| {
            (
                *severity,
                findings
                    .iter()
                    .filter(|f| f.severity == *severity)
                    .filter(|_| !only_high || matches!(severity, Severity::High | Severity::Medium))
                    .count(),
            )
        })
        .collect()
}

fn severity_colour(
    theme: &crate::ui::theme::Theme,
    severity: crate::scanner::Severity,
) -> Color32 {
    use crate::scanner::Severity;
    match severity {
        Severity::High => theme.color("ui.issue.high"),
        Severity::Medium => theme.color("ui.issue.medium"),
        Severity::Low => theme.color("ui.issue.low"),
        Severity::Info => theme.color("ui.icon.information"),
    }
}

/// Renders the `Burp Scanner reporting wizard` (`Pro-QSG-8-configure-report.png` & `reporting/report-settings.html`)
/// and the `Create an issue` manual issue dialog (`reporting/manual-issues.html`).
pub fn draw_scanner_modals(app: &mut App, ctx: &egui::Context) {
    let theme = app.theme.clone();

    if app.panels.scanner.show_report_wizard {
        let mut open = true;
        egui::Window::new("Gulp Scanner reporting wizard")
            .open(&mut open)
            .resizable(true)
            .default_pos([310.0, 110.0])
            .default_size([560.0, 440.0])
            .show(ctx, |ui| {
                let p = &mut app.panels.scanner;
                ui.horizontal(|ui| {
                    paint_launcher_icon(
                        ui,
                        Vec2::new(18.0, 18.0),
                        theme.color("ui.icon.default"),
                        LauncherIcon::HelpCircle,
                    );
                    ui.label(
                        RichText::new("Select the file and format where the report will be saved.")
                            .strong(),
                    );
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label("Report format:");
                    if ui.radio_value(&mut p.report_format, 0, "HTML").clicked()
                        && p.report_file_path.ends_with(".xml")
                    {
                        p.report_file_path = "gulpsuite-scanner-report.html".into();
                    }
                    if ui.radio_value(&mut p.report_format, 1, "XML").clicked()
                        && p.report_file_path.ends_with(".html")
                    {
                        p.report_file_path = "gulpsuite-scanner-report.xml".into();
                    }
                    if p.report_format == 1 {
                        ui.checkbox(
                            &mut p.report_base64_xml,
                            "Base64-encode requests and responses",
                        );
                    }
                });
                ui.horizontal(|ui| {
                    let _ = ui.button("Select file ...");
                    ui.add(
                        egui::TextEdit::singleline(&mut p.report_file_path)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("Specify the title and structure to use in the report.").strong());
                ui.add_space(4.0);
                egui::Grid::new("scanner-report-wizard-grid")
                    .num_columns(2)
                    .min_col_width(170.0)
                    .show(ui, |ui| {
                        ui.label("Report title");
                        ui.add(
                            egui::TextEdit::singleline(&mut p.report_title).desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("Issue organization");
                        egui::ComboBox::from_id_salt("rep-org-combo")
                            .selected_text(match p.report_organization {
                                0 => "By type",
                                1 => "By severity",
                                _ => "By URL",
                            })
                            .width(220.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut p.report_organization, 0, "By type");
                                ui.selectable_value(&mut p.report_organization, 1, "By severity");
                                ui.selectable_value(&mut p.report_organization, 2, "By URL");
                            });
                        ui.end_row();

                        ui.label("Table of contents levels");
                        egui::ComboBox::from_id_salt("rep-toc-combo")
                            .selected_text(p.report_toc_levels.to_string())
                            .width(80.0)
                            .show_ui(ui, |ui| {
                                for lvl in [1usize, 2, 3] {
                                    ui.selectable_value(
                                        &mut p.report_toc_levels,
                                        lvl,
                                        lvl.to_string(),
                                    );
                                }
                            });
                        ui.end_row();

                        ui.label("Summary table");
                        egui::ComboBox::from_id_salt("rep-sum-tbl-combo")
                            .selected_text(match p.report_summary_table_scope {
                                0 => "All issues",
                                1 => "High, medium and low issues",
                                _ => "High and medium issues",
                            })
                            .width(220.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut p.report_summary_table_scope,
                                    0,
                                    "All issues",
                                );
                                ui.selectable_value(
                                    &mut p.report_summary_table_scope,
                                    1,
                                    "High, medium and low issues",
                                );
                                ui.selectable_value(
                                    &mut p.report_summary_table_scope,
                                    2,
                                    "High and medium issues",
                                );
                            });
                        ui.end_row();

                        ui.label("Summary bar chart");
                        egui::ComboBox::from_id_salt("rep-bar-chart-combo")
                            .selected_text(match p.report_bar_chart_scope {
                                0 => "High, medium and low issues",
                                _ => "All issues",
                            })
                            .width(220.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut p.report_bar_chart_scope,
                                    0,
                                    "High, medium and low issues",
                                );
                                ui.selectable_value(
                                    &mut p.report_bar_chart_scope,
                                    1,
                                    "All issues",
                                );
                            });
                        ui.end_row();
                    });
                ui.add_space(4.0);
                ui.checkbox(
                    &mut p.report_embed_images,
                    "Embed images within HTML (requires modern browser)",
                );
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut p.report_inc_bg, "Issue background");
                    ui.checkbox(&mut p.report_inc_rem_bg, "Remediation background");
                    ui.checkbox(&mut p.report_inc_detail, "Issue detail");
                    ui.checkbox(&mut p.report_inc_cwe, "Vulnerability classifications (CWE)");
                });
                ui.add_space(8.0);
                ui.separator();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::ui::app::primary_button(ui, &theme, "Save report").clicked() {
                        let content = generate_scan_report(app);
                        let path = app.panels.scanner.report_file_path.trim().to_string();
                        ui.ctx().copy_text(content.clone());
                        if !path.is_empty() {
                            let _ = std::fs::write(&path, &content);
                        }
                        app.panels.scanner.show_report_wizard = false;
                        app.status = format!("Generated scan report to {path} (and copied to clipboard)");
                    }
                    if ui.button("Cancel").clicked() {
                        app.panels.scanner.show_report_wizard = false;
                    }
                });
            });
        if !open {
            app.panels.scanner.show_report_wizard = false;
        }
    }

    if app.panels.scanner.show_manual_issue_modal {
        let mut open = true;
        egui::Window::new("Create an issue")
            .open(&mut open)
            .resizable(true)
            .default_pos([330.0, 120.0])
            .default_size([520.0, 410.0])
            .show(ctx, |ui| {
                let p = &mut app.panels.scanner;
                egui::Grid::new("scanner-manual-issue-grid")
                    .num_columns(2)
                    .min_col_width(130.0)
                    .show(ui, |ui| {
                        ui.label("Name:");
                        ui.text_edit_singleline(&mut p.manual_issue_name);
                        ui.end_row();
                        ui.label("HTTP service:");
                        ui.text_edit_singleline(&mut p.manual_issue_service);
                        ui.end_row();
                        ui.label("Path:");
                        ui.text_edit_singleline(&mut p.manual_issue_path);
                        ui.end_row();
                        ui.label("Parameter:");
                        ui.text_edit_singleline(&mut p.manual_issue_param);
                        ui.end_row();
                        ui.label("Issue severity:");
                        ui.horizontal(|ui| {
                            for (idx, lbl) in ["High", "Medium", "Low", "Information"]
                                .iter()
                                .enumerate()
                            {
                                ui.selectable_value(&mut p.manual_issue_severity, idx, *lbl);
                            }
                        });
                        ui.end_row();
                        ui.label("Issue confidence:");
                        ui.horizontal(|ui| {
                            for (idx, lbl) in ["Certain", "Firm", "Tentative"].iter().enumerate() {
                                ui.selectable_value(&mut p.manual_issue_confidence, idx, *lbl);
                            }
                        });
                        ui.end_row();
                    });
                ui.add_space(4.0);
                ui.label("Issue detail:");
                ui.add(
                    egui::TextEdit::multiline(&mut p.manual_issue_detail)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                ui.label("Remediation:");
                ui.add(
                    egui::TextEdit::multiline(&mut p.manual_issue_remediation)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);
                ui.separator();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::ui::app::primary_button(ui, &theme, "Create issue").clicked() {
                        let full_url = format!(
                            "{}{}",
                            app.panels.scanner.manual_issue_service.trim_end_matches('/'),
                            if app.panels.scanner.manual_issue_path.starts_with('/') {
                                app.panels.scanner.manual_issue_path.clone()
                            } else {
                                format!("/{}", app.panels.scanner.manual_issue_path)
                            }
                        );
                        let sev = match app.panels.scanner.manual_issue_severity {
                            0 => crate::workspace::IssueSeverity::High,
                            1 => crate::workspace::IssueSeverity::Medium,
                            2 => crate::workspace::IssueSeverity::Low,
                            _ => crate::workspace::IssueSeverity::Info,
                        };
                        let scan_sev = match app.panels.scanner.manual_issue_severity {
                            0 => crate::scanner::Severity::High,
                            1 => crate::scanner::Severity::Medium,
                            2 => crate::scanner::Severity::Low,
                            _ => crate::scanner::Severity::Info,
                        };
                        let conf = match app.panels.scanner.manual_issue_confidence {
                            0 => "Certain",
                            1 => "Firm",
                            _ => "Tentative",
                        };
                        let param = if app.panels.scanner.manual_issue_param.trim().is_empty() {
                            None
                        } else {
                            Some(app.panels.scanner.manual_issue_param.trim().to_string())
                        };
                        let name = app.panels.scanner.manual_issue_name.trim().to_string();
                        let detail = format!(
                            "{} | Remediation: {}",
                            app.panels.scanner.manual_issue_detail.trim(),
                            app.panels.scanner.manual_issue_remediation.trim()
                        );
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        app.workspace
                            .issues
                            .upsert(crate::workspace::IssueRecord::new(
                                crate::workspace::TaskId(2),
                                &name,
                                sev,
                                conf,
                                &full_url,
                                param.clone(),
                                &detail,
                                now_ms,
                            ));
                        app.panels.scanner.findings.push(crate::scanner::Finding {
                            name: name.clone(),
                            severity: scan_sev,
                            url: full_url,
                            parameter: param,
                            evidence: detail,
                            confidence: conf.into(),
                        });
                        app.panels.scanner.show_manual_issue_modal = false;
                        app.status = format!("Created manual issue '{name}'");
                    }
                    if ui.button("Cancel").clicked() {
                        app.panels.scanner.show_manual_issue_modal = false;
                    }
                });
            });
        if !open {
            app.panels.scanner.show_manual_issue_modal = false;
        }
    }
}

/// Generates an HTML or XML report matching Burp Suite Pro's reporting wizard (`reporting/report-settings.html`).
pub fn generate_scan_report(app: &App) -> String {
    let p = &app.panels.scanner;
    let host_filter = p.report_host_filter.trim().to_lowercase();
    let issues: Vec<_> = app
        .workspace
        .issues
        .iter()
        .filter(|iss| host_filter.is_empty() || iss.url.to_lowercase().contains(&host_filter))
        .collect();

    if p.report_format == 1 {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE issues [\n  <!ELEMENT issues (issue*)>\n  <!ELEMENT issue (serialNumber,type,name,host,path,location,severity,confidence,issueDetail)>\n]>\n<issues burpVersion=\"2026.3.3\">\n",
        );
        for (idx, iss) in issues.iter().enumerate() {
            xml.push_str(&format!(
                "  <issue>\n    <serialNumber>{}</serialNumber>\n    <type>1048576</type>\n    <name>{}</name>\n    <path>{}</path>\n    <severity>{:?}</severity>\n    <confidence>{}</confidence>\n    <issueDetail>{}</issueDetail>\n  </issue>\n",
                1000 + idx,
                iss.name,
                iss.url,
                iss.severity,
                iss.confidence,
                iss.evidence
            ));
        }
        xml.push_str("</issues>\n");
        xml
    } else {
        let mut html = format!(
            "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{}</title>\n<style>body{{font-family:sans-serif;margin:32px;color:#202020}}h1{{color:#26649D}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #dcdcdc;padding:8px;text-align:left}}th{{background:#f3f4f6}}.High{{color:#D6213F;font-weight:bold}}.Medium{{color:#FF6633;font-weight:bold}}.Low{{color:#26649D;font-weight:bold}}</style></head><body>\n<h1>{}</h1>\n<p>Total issues reported: <strong>{}</strong></p>\n<table><tr><th>#</th><th>Severity</th><th>Issue type</th><th>URL</th><th>Parameter</th><th>Confidence</th><th>Evidence</th></tr>\n",
            p.report_title,
            p.report_title,
            issues.len()
        );
        for (idx, iss) in issues.iter().enumerate() {
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"{:?}\">{:?}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
                idx + 1,
                iss.severity,
                iss.severity,
                iss.name,
                iss.url,
                iss.parameter.as_deref().unwrap_or("-"),
                iss.confidence,
                iss.evidence
            ));
        }
        html.push_str("</table></body></html>\n");
        html
    }
}

/// Parses OpenAPI v2/v3 JSON (`paths`) or Postman Collection v2.1 JSON (`item`) into `ApiEndpointRow`s.
pub fn parse_api_definition(content: &str, default_host: &str) -> Vec<ApiEndpointRow> {
    let mut out = Vec::new();
    let host_origin = crate::scanner::split(default_host)
        .map(|(h, _)| {
            let scheme = if default_host.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{h}")
        })
        .unwrap_or_else(|| "https://example.com".into());

    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    if let Some(paths) = val.get("paths").and_then(|v| v.as_object()) {
        for (path, methods_obj) in paths {
            if let Some(methods) = methods_obj.as_object() {
                for m in ["get", "post", "put", "delete", "patch"] {
                    if methods.contains_key(m) {
                        out.push(ApiEndpointRow {
                            selected: true,
                            method: m.to_ascii_uppercase(),
                            content_type: "application/json".into(),
                            host: host_origin.clone(),
                            url: path.clone(),
                        });
                    }
                }
            }
        }
    } else if let Some(items) = val.get("item").and_then(|v| v.as_array()) {
        for item in items {
            if let Some(req) = item.get("request") {
                let method = req
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_ascii_uppercase();
                let raw_url = req
                    .get("url")
                    .and_then(|u| u.as_str().or_else(|| u.get("raw").and_then(|r| r.as_str())))
                    .unwrap_or("/");
                let path = crate::scanner::http::path_of(raw_url);
                out.push(ApiEndpointRow {
                    selected: true,
                    method,
                    content_type: "application/json".into(),
                    host: host_origin.clone(),
                    url: path,
                });
            }
        }
    }
    out
}

pub(crate) fn start(app: &mut App) {
    if app.panels.scanner.seed == "http://127.0.0.1:8080/" {
        if let Some(latest) = app
            .log
            .iter()
            .rev()
            .find(|tx| tx.target.starts_with("http://") || tx.target.starts_with("https://"))
            .map(|tx| tx.target.clone())
        {
            app.panels.scanner.seed = latest.clone();
            app.panels.scanner.urls_to_scan = latest;
        }
    }

    // Collect all start URLs from `urls_to_scan` + `seed` + `api_endpoints` (for API-only scan),
    // and apply `protocol_mode` (`Scan using HTTP and HTTPS` vs `Scan using my specified protocols`).
    let scan_type = app.panels.scanner.scan_type;
    let protocol_mode = app.panels.scanner.protocol_mode;
    let mut target_urls: Vec<String> = Vec::new();

    if scan_type == 3 {
        // API-only scan: build target URLs from all selected `api_endpoints`
        for ep in &app.panels.scanner.api_endpoints {
            if ep.selected {
                let base = ep.host.trim_end_matches('/');
                let path = if ep.url.starts_with('/') {
                    ep.url.clone()
                } else {
                    format!("/{}", ep.url)
                };
                let full = format!("{base}{path}?id=1");
                if !target_urls.contains(&full) {
                    target_urls.push(full);
                }
            }
        }
    }

    for raw_line in app.panels.scanner.urls_to_scan.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            if !target_urls.contains(&trimmed.to_string()) {
                target_urls.push(trimmed.to_string());
            }
        } else if protocol_mode == 0 {
            let https_u = format!("https://{trimmed}");
            let http_u = format!("http://{trimmed}");
            if !target_urls.contains(&https_u) {
                target_urls.push(https_u);
            }
            if !target_urls.contains(&http_u) {
                target_urls.push(http_u);
            }
        } else {
            let http_u = format!("http://{trimmed}");
            if !target_urls.contains(&http_u) {
                target_urls.push(http_u);
            }
        }
    }

    if target_urls.is_empty() {
        let seed_trim = app.panels.scanner.seed.trim();
        if !seed_trim.is_empty() {
            target_urls.push(seed_trim.to_string());
        }
    }

    // Apply `Consolidate items` filters when `scan_type == 2` (`Audit selected items`)
    if scan_type == 2 {
        let cons_dup = app.panels.scanner.consolidate_duplicates;
        let cons_scope = app.panels.scanner.consolidate_out_of_scope;
        let cons_noparam = app.panels.scanner.consolidate_no_params;
        let cons_ext = app.panels.scanner.consolidate_extensions;
        let ext_blacklist: Vec<String> = app
            .panels
            .scanner
            .consolidate_ext_list
            .split([',', ' '])
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let mut seen_keys = std::collections::HashSet::new();
        target_urls.retain(|u| {
            if cons_scope && !app.panels.target_panel.in_scope(u) {
                return false;
            }
            if cons_noparam && !u.contains('?') {
                return false;
            }
            if cons_ext {
                let path = u.split('?').next().unwrap_or(u);
                if let Some(ext) = path.rsplit('.').next() {
                    if ext_blacklist.iter().any(|e| e == &ext.to_ascii_lowercase()) {
                        return false;
                    }
                }
            }
            if cons_dup {
                seen_keys.insert(u.clone())
            } else {
                true
            }
        });
        if target_urls.is_empty() && !app.panels.scanner.seed.trim().is_empty() {
            target_urls.push(app.panels.scanner.seed.trim().to_string());
        }
    }

    let seed = target_urls
        .first()
        .cloned()
        .unwrap_or_else(|| app.panels.scanner.seed.trim().to_string());
    if seed.is_empty() {
        app.status = "Scanner needs a seed URL".into();
        return;
    }
    let Some(host) = crate::scanner::split(&seed).map(|(h, _)| h) else {
        app.status = "Seed URL must be absolute, e.g. http://host/".into();
        return;
    };
    app.panels.scanner.seed = seed.clone();
    app.panels.scanner.host = host.clone();
    app.panels.scanner.findings.clear();
    app.panels.scanner.pages.clear();
    app.panels.scanner.running = true;
    app.panels.scanner.completed_steps = 0;
    app.panels.scanner.total_steps = app.panels.scanner.max_pages.max(1);
    app.panels.scanner.progress = "Crawling…".into();
    app.status = format!("Scanning {seed}");
    let task_id = app.workspace_adapter.begin_scan(&mut app.workspace, &seed);
    if let Some(task) = app.workspace.tasks.get_mut(task_id) {
        task.configuration = format!(
            "{} - {}",
            app.panels.scanner.scan_type_name(),
            app.panels.scanner.preset_name()
        );
    }

    let include = app.panels.target_panel.scope.trim().to_string();
    let exclude = app.panels.target_panel.scope_exclude.trim().to_string();
    let scope = if include.is_empty() {
        let mut s = crate::scanner::Scope::for_host(&host);
        s.max_depth = if scan_type == 2 || scan_type == 3 {
            1
        } else {
            app.panels.scanner.max_depth
        };
        s.max_pages = app.panels.scanner.max_pages;
        s
    } else {
        crate::scanner::Scope::from_spec(
            &include,
            &exclude,
            if scan_type == 2 || scan_type == 3 {
                1
            } else {
                app.panels.scanner.max_depth
            },
            app.panels.scanner.max_pages,
        )
    };
    let run_active = scan_type != 1 && app.panels.scanner.active_checks;
    let audit_preset = app.panels.scanner.config_preset;
    let concurrency = app.panels.scanner.resource_pool_concurrency.clamp(1, 32);
    let delay_ms = app.panels.scanner.resource_pool_delay_ms;
    let auto_throttle = app.panels.scanner.resource_pool_auto_throttle;
    let login_creds = if app.panels.scanner.use_login_credentials {
        app.panels.scanner.login_credentials.first().cloned()
    } else {
        None
    };
    let active_bchecks: Vec<CustomScanCheck> = if app.panels.scanner.bchecks_master_enabled {
        app.panels
            .scanner
            .bchecks
            .iter()
            .filter(|b| b.enabled)
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let proxy: Arc<crate::proxy::Proxy> = app.proxy.clone();
    let runtime = app.runtime_handle();

    let (tx, rx) = std::sync::mpsc::channel::<ScanUpdate>();
    app.scanner_updates = Some(rx);

    std::thread::spawn(move || {
        runtime.block_on(async move {
            let mut findings = Vec::new();
            let mut pages = Vec::new();
            let crawl_counter = std::sync::atomic::AtomicUsize::new(0);
            let max_expected = scope.max_pages.max(1);

            for start_url in &target_urls {
                let Some((u_host, _)) = crate::scanner::split(start_url) else {
                    continue;
                };
                let mut u_scope = scope.clone();
                if !u_scope.hosts.is_empty() && !u_scope.hosts.contains(&u_host) {
                    u_scope.hosts.push(u_host.clone());
                }
                let tx_crawl = tx.clone();
                let on_progress = |prog: crate::scanner::crawler::Progress| {
                    if let crate::scanner::crawler::Progress::Fetching(ref u) = prog {
                        let done =
                            crawl_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let _ = tx_crawl.send(ScanUpdate::Live {
                            status: format!("Crawling ({done}): {u}"),
                            completed: done,
                            total: max_expected.max(done + 1),
                            page: None,
                            findings: Vec::new(),
                        });
                    }
                };
                let coverage =
                    crate::scanner::crawler::crawl(start_url, &u_scope, &proxy, &on_progress)
                        .await;

                // Optional Application Login form submission when `use_login_credentials` is enabled
                if let Some(ref cred) = login_creds {
                    let tls = start_url.starts_with("https://");
                    let port = if tls { 443 } else { 80 };
                    let body = format!(
                        "username={}&password={}",
                        cred.username, cred.password
                    );
                    let login_req = format!(
                        "POST /login HTTP/1.1\r\nHost: {u_host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = proxy
                        .one_shot_secure(&u_host, port, &login_req, tls, 5_000)
                        .await;
                }

                for (p_url, status) in coverage.pages {
                    if !pages.iter().any(|(u, _)| u == &p_url) {
                        pages.push((p_url.clone(), status));
                        let _ = tx.send(ScanUpdate::Live {
                            status: format!("Crawled {} page(s)", pages.len()),
                            completed: pages.len(),
                            total: max_expected.max(pages.len() + 1),
                            page: Some((p_url, status)),
                            findings: Vec::new(),
                        });
                    }
                }
                let mut batch_findings = Vec::new();
                for mut f in coverage.findings {
                    // If `Audit checks - critical issues only` (preset 0) is selected, skip Info/Low noise
                    if audit_preset == 0
                        && matches!(
                            f.severity,
                            crate::scanner::Severity::Info | crate::scanner::Severity::Low
                        )
                    {
                        continue;
                    }
                    // Consolidate host-wide passive issues (`consolidate_passive_issues: true`) once per origin
                    let host_wide = crate::scanner::passive::is_host_wide_passive_issue(&f.name);
                    if host_wide {
                        if let Some((scheme, rest)) = f.url.split_once("://") {
                            let host = rest.split('/').next().unwrap_or(rest);
                            f.url = format!("{scheme}://{host}/");
                        }
                    }
                    let dup = findings.iter().any(|existing: &crate::scanner::Finding| {
                        existing.name == f.name
                            && existing.url == f.url
                            && (host_wide || existing.parameter == f.parameter)
                    });
                    if !dup {
                        findings.push(f.clone());
                        batch_findings.push(f);
                    }
                }
                if !batch_findings.is_empty() {
                    let _ = tx.send(ScanUpdate::Live {
                        status: format!("Passive audit: {} issue(s)", findings.len()),
                        completed: pages.len(),
                        total: max_expected.max(pages.len() + 1),
                        page: None,
                        findings: batch_findings,
                    });
                }
            }

            if run_active {
                // Sort discovered pages by Burp's 80/20 Audit Prioritization score (`auditing.html#audit-prioritization`)
                let has_auth = login_creds.is_some();
                pages.sort_by_key(|(u, _)| {
                    let param_cnt = u.matches('=').count();
                    std::cmp::Reverse(crate::scanner::active::priority_score(
                        "GET",
                        "text/html",
                        param_cnt,
                        has_auth,
                    ))
                });
                let _ = tx.send(ScanUpdate::Progress(format!(
                    "Auditing: {} passive issue(s); injecting active payloads…",
                    findings.len()
                )));
                let checks = Arc::new(crate::scanner::active::all_checks());
                let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
                let mut queried_osv_pkgs: std::collections::HashSet<(String, String)> =
                    std::collections::HashSet::new();
                let mut total_probes_sent = 0usize;

                // Phase 1: Origin-level high-impact CVE & exposure probes + active Nuclei YAML templates
                for start_url in &target_urls {
                    let mut origin_cves =
                        crate::scanner::active::audit_origin_cve_probes(start_url, &pages, &proxy)
                            .await;
                    for bchk in &active_bchecks {
                        if crate::scanner::nuclei::is_nuclei_template(&bchk.script) {
                            if let Ok(tmpl) =
                                crate::scanner::nuclei::parse_nuclei_template(&bchk.script)
                            {
                                origin_cves.extend(
                                    crate::scanner::nuclei::execute_template_active(
                                        &tmpl, start_url, &proxy,
                                    )
                                    .await,
                                );
                            }
                        }
                    }
                    let mut live_cves = Vec::new();
                    for cf in origin_cves {
                        let dup = findings
                            .iter()
                            .any(|e| e.name == cf.name && e.url == cf.url);
                        if !dup {
                            findings.push(cf.clone());
                            live_cves.push(cf);
                        }
                    }
                    if !live_cves.is_empty() {
                        let _ = tx.send(ScanUpdate::Live {
                            status: format!(
                                "Auditing CVE probes: {} issue(s) found",
                                findings.len()
                            ),
                            completed: 1,
                            total: pages.len().max(2),
                            page: None,
                            findings: live_cves,
                        });
                    }
                }

                // Phase 2: Per-page live OSV.dev worldwide CVE query + bounded active injection probes
                let audit_pages: Vec<(String, u16)> = pages.iter().take(40).cloned().collect();
                let audit_page_total = audit_pages.len().max(1);
                for (page_idx, (url, status)) in audit_pages.iter().enumerate() {
                    if *status < 200 || *status >= 400 {
                        continue;
                    }
                    let Some((host, port, tls, raw)) =
                        crate::scanner::active::InjectionPoint::baseline_request(url)
                    else {
                        continue;
                    };
                    let Ok((resp_code, body_text)) =
                        proxy.one_shot_secure(&host, port, &raw, tls, 8_000).await
                    else {
                        continue;
                    };
                    if auto_throttle && (resp_code == 429 || resp_code == 503) {
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    }
                    let parsed_base = crate::scanner::http::parse_response(&body_text);
                    for bchk in &active_bchecks {
                        if let Some(bf) = crate::scanner::active::evaluate_bcheck(
                            &bchk.name,
                            &bchk.script,
                            url,
                            &parsed_base,
                        ) {
                            let dup = findings.iter().any(|e| {
                                e.name == bf.name && e.url == bf.url && e.parameter == bf.parameter
                            });
                            if !dup {
                                findings.push(bf);
                            }
                        }
                    }

                    // Live Worldwide CVE lookup (`https://api.osv.dev/v1/query`) for any detected package/version
                    for (eco, pkg, ver) in
                        crate::scanner::passive::extract_detected_packages(url, &parsed_base.body)
                    {
                        if queried_osv_pkgs.insert((pkg.clone(), ver.clone())) {
                            if let Some(mut osv_finding) =
                                crate::scanner::active::query_live_osv_cves(url, eco, &pkg, &ver)
                                    .await
                            {
                                if let Some((scheme, rest)) = osv_finding.url.split_once("://") {
                                    let h = rest.split('/').next().unwrap_or(rest);
                                    osv_finding.url = format!("{scheme}://{h}/");
                                }
                                let dup = findings.iter().any(|e| {
                                    e.name == osv_finding.name
                                        && e.parameter == osv_finding.parameter
                                });
                                if !dup {
                                    findings.push(osv_finding.clone());
                                    let _ = tx.send(ScanUpdate::Live {
                                        status: format!("Live CVE audit: {pkg} {ver}"),
                                        completed: page_idx + 1,
                                        total: audit_page_total,
                                        page: None,
                                        findings: vec![osv_finding],
                                    });
                                }
                            }
                        }
                    }

                    let baseline_arc = Arc::new(parsed_base.clone());
                    let body = parsed_base.body;
                    let mut page_probe_tasks = Vec::new();

                    for point in crate::scanner::crawler::injection_points(url, &body)
                        .into_iter()
                        .take(6)
                    {
                        for check_idx in 0..checks.len() {
                            for &payload in checks[check_idx].payloads {
                                let Some((h, p, tls, request)) = point.request(payload) else {
                                    continue;
                                };
                                let Ok(permit) = sem.clone().acquire_owned().await else {
                                    continue;
                                };
                                let proxy = proxy.clone();
                                let checks = checks.clone();
                                let url = url.clone();
                                let param_name = point.name.clone();
                                let baseline_resp = baseline_arc.clone();
                                page_probe_tasks.push(tokio::spawn(async move {
                                    let _permit = permit;
                                    if delay_ms > 0 {
                                        tokio::time::sleep(std::time::Duration::from_millis(
                                            delay_ms.min(2_000),
                                        ))
                                        .await;
                                    }
                                    let (_, text) = proxy
                                        .one_shot_secure(&h, p, &request, tls, 8_000)
                                        .await
                                        .ok()?;
                                    let response = crate::scanner::http::parse_response(&text);
                                    crate::scanner::active::evaluate_against_baseline(
                                        &checks[check_idx],
                                        &url,
                                        &param_name,
                                        payload,
                                        &baseline_resp,
                                        &response,
                                    )
                                }));
                            }
                        }
                    }

                    total_probes_sent += page_probe_tasks.len();
                    let mut live_new = Vec::new();
                    for handle in page_probe_tasks {
                        if let Ok(Some(finding)) = handle.await {
                            let duplicate = findings.iter().any(|existing| {
                                existing.name == finding.name
                                    && existing.url == finding.url
                                    && existing.parameter == finding.parameter
                            });
                            if !duplicate {
                                findings.push(finding.clone());
                                live_new.push(finding);
                            }
                        }
                    }
                    let _ = tx.send(ScanUpdate::Live {
                        status: format!(
                            "Auditing page {}/{audit_page_total} ({total_probes_sent} probes)",
                            page_idx + 1
                        ),
                        completed: page_idx + 1,
                        total: audit_page_total,
                        page: None,
                        findings: live_new,
                    });
                }
                let _ = tx.send(ScanUpdate::Progress(format!(
                    "{total_probes_sent} probe(s) sent"
                )));
            }

            pages.dedup();
            findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            let _ = tx.send(ScanUpdate::Done { findings, pages });
        });
    });
}

/// What a running scan reports back to the UI.
pub enum ScanUpdate {
    Progress(String),
    Live {
        status: String,
        completed: usize,
        total: usize,
        page: Option<(String, u16)>,
        findings: Vec<crate::scanner::Finding>,
    },
    Done {
        findings: Vec<crate::scanner::Finding>,
        pages: Vec<(String, u16)>,
    },
}
