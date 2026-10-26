//! The Gulpsuite icon set.
//!
//! Each glyph is vector geometry on a 16x16 grid, painted at whatever size the layout asks for, so
//! the set stays sharp at any scale factor and picks up the theme colour automatically.

use eframe::egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, StrokeKind, Vec2, pos2};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Glyph {
    Dashboard,
    Target,
    Proxy,
    Intruder,
    Repeater,
    Sequencer,
    Decoder,
    Comparer,
    Logger,
    Extender,
    New,
    InProgress,
    Postponed,
    Ignored,
    Done,
    High,
    Medium,
    Low,
    Info,
    Request,
    Response,
    Play,
    Stop,
    /// The four icons Gulp keeps at the right end of the tool row.
    Globe,
    Terminal,
    Search,
    Gear,
    /// The pane header icons Gulp puts at the top right of the Dashboard.
    Pause,
    Help,
    Ellipsis,
    Funnel,
    Clock,
    Warning,
    Diamond,
    Star,
}

impl Glyph {
    pub const ALL: [Glyph; 35] = [
        Glyph::Dashboard,
        Glyph::Target,
        Glyph::Proxy,
        Glyph::Intruder,
        Glyph::Repeater,
        Glyph::Sequencer,
        Glyph::Decoder,
        Glyph::Comparer,
        Glyph::Logger,
        Glyph::Extender,
        Glyph::New,
        Glyph::InProgress,
        Glyph::Postponed,
        Glyph::Ignored,
        Glyph::Done,
        Glyph::High,
        Glyph::Medium,
        Glyph::Low,
        Glyph::Info,
        Glyph::Request,
        Glyph::Response,
        Glyph::Play,
        Glyph::Stop,
        Glyph::Globe,
        Glyph::Terminal,
        Glyph::Search,
        Glyph::Gear,
        Glyph::Pause,
        Glyph::Help,
        Glyph::Ellipsis,
        Glyph::Funnel,
        Glyph::Clock,
        Glyph::Warning,
        Glyph::Diamond,
        Glyph::Star,
    ];

    /// The glyph shown for a tool in the sidebar.
    pub fn for_tool(name: &str) -> Glyph {
        match name {
            "Dashboard" => Glyph::Dashboard,
            "Target" => Glyph::Target,
            "Proxy" => Glyph::Proxy,
            "Intruder" => Glyph::Intruder,
            "Repeater" => Glyph::Repeater,
            "Sequencer" => Glyph::Sequencer,
            "Decoder" => Glyph::Decoder,
            "Comparer" => Glyph::Comparer,
            "Logger" => Glyph::Logger,
            "Scanner" => Glyph::Target,
            "Extender" => Glyph::Extender,
            _ => Glyph::Info,
        }
    }
}

/// Draws `glyph` inside `rect`.
pub fn paint(painter: &Painter, rect: Rect, color: Color32, glyph: Glyph) {
    painter.add(Shape::Vec(shapes(rect, color, glyph)));
}

/// Builds the glyph's geometry. Exposed so tests can check it without a window.
pub fn shapes(rect: Rect, color: Color32, glyph: Glyph) -> Vec<Shape> {
    let unit = rect.width().min(rect.height()) / 16.0;
    let mut kit = Kit {
        out: Vec::new(),
        unit,
        origin: rect.min,
        color,
    };
    kit.draw(glyph);
    kit.out
}

/// Maps 16x16 grid coordinates into a rectangle and collects the shapes.
struct Kit {
    out: Vec<Shape>,
    unit: f32,
    origin: Pos2,
    color: Color32,
}

impl Kit {
    fn at(&self, x: f32, y: f32) -> Pos2 {
        pos2(self.origin.x + x * self.unit, self.origin.y + y * self.unit)
    }

    fn stroke(&self) -> Stroke {
        Stroke::new(self.unit.max(1.2), self.color)
    }

    fn line(&mut self, a: (f32, f32), b: (f32, f32)) {
        self.out.push(Shape::LineSegment {
            points: [self.at(a.0, a.1), self.at(b.0, b.1)],
            stroke: self.stroke(),
        });
    }

    fn polyline(&mut self, points: &[(f32, f32)], close: bool) {
        let points: Vec<Pos2> = points.iter().map(|(x, y)| self.at(*x, *y)).collect();
        self.out.push(if close {
            Shape::closed_line(points, self.stroke())
        } else {
            Shape::line(points, self.stroke())
        });
    }

    fn dot(&mut self, cx: f32, cy: f32, r: f32) {
        self.out.push(Shape::Circle(eframe::epaint::CircleShape::filled(
            self.at(cx, cy),
            r * self.unit,
            self.color,
        )));
    }

    fn ring(&mut self, cx: f32, cy: f32, r: f32) {
        self.out.push(Shape::Circle(eframe::epaint::CircleShape::stroke(
            self.at(cx, cy),
            r * self.unit,
            self.stroke(),
        )));
    }

    fn boxy(&mut self, x: f32, y: f32, w: f32, h: f32, radius: f32, filled: bool) {
        let rect = Rect::from_min_size(self.at(x, y), Vec2::new(w * self.unit, h * self.unit));
        self.out.push(if filled {
            Shape::Rect(eframe::epaint::RectShape::filled(
                rect,
                radius * self.unit,
                self.color,
            ))
        } else {
            Shape::Rect(eframe::epaint::RectShape::stroke(
                rect,
                radius * self.unit,
                self.stroke(),
                StrokeKind::Middle,
            ))
        });
    }

    fn triangle(&mut self, points: [(f32, f32); 3]) {
        let points: Vec<Pos2> = points.iter().map(|(x, y)| self.at(*x, *y)).collect();
        self.out.push(Shape::convex_polygon(points, self.color, Stroke::NONE));
    }

    /// epaint has no arc primitive at this version, so approximate one with a polyline.
    fn arc(&mut self, cx: f32, cy: f32, radius: f32, from: f32, to: f32) {
        let steps = (((to - from).abs() / 12.0) as usize).clamp(8, 64);
        let points: Vec<Pos2> = (0..=steps)
            .map(|step| {
                let angle = (from + (to - from) * step as f32 / steps as f32).to_radians();
                self.at(cx + angle.cos() * radius, cy + angle.sin() * radius)
            })
            .collect();
        self.out.push(Shape::line(points, self.stroke()));
    }

    fn draw(&mut self, glyph: Glyph) {
        match glyph {
            Glyph::Dashboard => {
                self.arc(8.0, 9.0, 6.0, 180.0, 360.0);
                self.line((8.0, 9.0), (12.0, 5.5));
                self.dot(8.0, 9.0, 0.8);
                self.line((2.0, 10.0), (3.5, 10.0));
                self.line((12.5, 10.0), (14.0, 10.0));
                self.line((8.0, 2.5), (8.0, 4.0));
            }
            Glyph::Target => {
                self.ring(8.0, 8.0, 6.0);
                self.ring(8.0, 8.0, 2.5);
                self.dot(8.0, 8.0, 0.8);
            }
            Glyph::Proxy => {
                self.boxy(1.5, 4.0, 5.0, 8.0, 2.0, false);
                self.boxy(9.5, 4.0, 5.0, 8.0, 2.0, false);
                self.line((6.8, 8.0), (9.2, 8.0));
                self.triangle([(10.0, 8.0), (7.6, 5.9), (7.6, 10.1)]);
            }
            Glyph::Intruder => {
                self.ring(8.0, 8.0, 6.0);
                self.ring(8.0, 8.0, 2.0);
                self.line((8.0, 0.8), (8.0, 4.0));
                self.line((8.0, 12.0), (8.0, 15.2));
                self.line((0.8, 8.0), (4.0, 8.0));
                self.line((12.0, 8.0), (15.2, 8.0));
                self.dot(8.0, 8.0, 0.7);
            }
            Glyph::Repeater => {
                self.arc(8.0, 8.0, 6.0, 40.0, 290.0);
                self.triangle([(4.0, 4.0), (1.0, 3.4), (7.0, 6.4)]);
                self.ring(8.0, 8.0, 1.4);
            }
            Glyph::Sequencer => {
                for (i, height) in [4.0f32, 8.0, 12.0, 6.0, 10.0, 3.0, 7.0].iter().enumerate() {
                    let x = 2.0 + i as f32 * 2.0;
                    self.line((x, 8.0 - height / 2.0), (x, 8.0 + height / 2.0));
                }
            }
            Glyph::Decoder => {
                self.polyline(&[(5.0, 3.0), (2.5, 3.0), (2.5, 13.0), (5.0, 13.0)], false);
                self.polyline(&[(11.0, 3.0), (13.5, 3.0), (13.5, 13.0), (11.0, 13.0)], false);
                self.line((6.0, 8.0), (10.0, 8.0));
                self.triangle([(11.0, 8.0), (8.6, 5.9), (8.6, 10.1)]);
            }
            Glyph::Comparer => {
                self.boxy(1.5, 1.5, 8.0, 8.0, 1.5, false);
                self.boxy(6.5, 6.5, 8.0, 8.0, 1.5, false);
                self.line((3.5, 4.5), (7.5, 4.5));
                self.line((3.5, 6.5), (6.0, 6.5));
                self.line((9.0, 10.0), (11.5, 10.0));
            }
            Glyph::Logger => {
                self.boxy(2.5, 1.5, 11.0, 13.0, 1.5, false);
                self.line((5.0, 4.5), (11.5, 4.5));
                self.line((5.0, 7.5), (11.5, 7.5));
                self.line((5.0, 10.5), (9.0, 10.5));
            }
            Glyph::Extender => {
                self.polyline(
                    &[
                        (6.0, 4.5),
                        (10.0, 4.5),
                        (12.5, 4.5),
                        (12.5, 9.0),
                        (10.0, 9.0),
                        (10.0, 12.5),
                        (6.0, 12.5),
                        (6.0, 9.0),
                        (3.5, 9.0),
                        (3.5, 4.5),
                    ],
                    true,
                );
                self.arc(8.0, 2.5, 2.0, 180.0, 360.0);
                self.arc(3.0, 7.0, 1.6, 270.0, 450.0);
                self.arc(10.0, 12.5, 2.0, 0.0, 180.0);
                self.arc(13.0, 7.0, 1.6, 90.0, 270.0);
            }
            Glyph::New => {
                self.dot(8.0, 8.0, 4.5);
            }
            Glyph::InProgress => {
                self.arc(8.0, 8.0, 6.0, 90.0, 270.0);
                let points = vec![self.at(8.0, 2.0), self.at(2.0, 8.0), self.at(14.0, 8.0)];
                self.out
                    .push(Shape::convex_polygon(points, self.color, Stroke::NONE));
            }
            Glyph::Postponed => {
                self.arc(8.0, 8.0, 6.0, 180.0, 360.0);
                self.line((5.0, 8.0), (5.0, 13.0));
                self.line((8.0, 8.0), (8.0, 13.0));
                self.line((11.0, 8.0), (11.0, 13.0));
            }
            Glyph::Ignored => {
                self.ring(8.0, 8.0, 6.0);
                self.line((4.0, 12.0), (12.0, 4.0));
            }
            Glyph::Done => {
                self.line((3.5, 8.5), (6.5, 11.5));
                self.line((6.5, 11.5), (12.5, 4.5));
            }
            Glyph::High => {
                // `scan-issue-high-certain.svg`: filled circle (#D6213F via self.color) with white `!`
                self.dot(8.0, 8.0, 6.6);
                self.out.push(Shape::LineSegment {
                    points: [self.at(8.0, 4.4), self.at(8.0, 8.8)],
                    stroke: Stroke::new((1.6 * self.unit).max(1.3), Color32::WHITE),
                });
                self.out.push(Shape::Circle(eframe::epaint::CircleShape::filled(
                    self.at(8.0, 11.2),
                    0.95 * self.unit,
                    Color32::WHITE,
                )));
            }
            Glyph::Medium => {
                // `scan-issue-medium-certain.svg`: filled circle (#FF6633 via self.color) with white `!`
                self.dot(8.0, 8.0, 6.4);
                self.out.push(Shape::LineSegment {
                    points: [self.at(8.0, 4.8), self.at(8.0, 9.1)],
                    stroke: Stroke::new((1.6 * self.unit).max(1.3), Color32::WHITE),
                });
                self.out.push(Shape::Circle(eframe::epaint::CircleShape::filled(
                    self.at(8.0, 11.4),
                    0.9 * self.unit,
                    Color32::WHITE,
                )));
            }
            Glyph::Low => {
                // `scan-issue-low-certain.svg`: filled circle (#26649D via self.color) with white `!`
                self.dot(8.0, 8.0, 6.2);
                self.out.push(Shape::LineSegment {
                    points: [self.at(8.0, 5.1), self.at(8.0, 9.3)],
                    stroke: Stroke::new((1.6 * self.unit).max(1.3), Color32::WHITE),
                });
                self.out.push(Shape::Circle(eframe::epaint::CircleShape::filled(
                    self.at(8.0, 11.6),
                    0.85 * self.unit,
                    Color32::WHITE,
                )));
            }
            Glyph::Info => {
                // `scan-issue-info-certain.svg`: filled circle (#6A6A6C via self.color) with white `i`
                self.dot(8.0, 8.0, 6.4);
                self.out.push(Shape::Circle(eframe::epaint::CircleShape::filled(
                    self.at(8.0, 5.0),
                    0.9 * self.unit,
                    Color32::WHITE,
                )));
                self.out.push(Shape::LineSegment {
                    points: [self.at(8.0, 7.2), self.at(8.0, 11.6)],
                    stroke: Stroke::new((1.6 * self.unit).max(1.3), Color32::WHITE),
                });
            }
            Glyph::Request => {
                self.line((3.0, 8.0), (13.0, 8.0));
                self.triangle([(13.0, 8.0), (9.0, 5.0), (9.0, 11.0)]);
            }
            Glyph::Response => {
                self.line((13.0, 8.0), (3.0, 8.0));
                self.triangle([(3.0, 8.0), (7.0, 5.0), (7.0, 11.0)]);
            }
            Glyph::Globe => {
                // `globe.svg`: outer circle, equator, and curved left/right meridians.
                self.ring(8.0, 8.0, 6.4);
                self.line((1.8, 8.0), (14.2, 8.0));
                self.arc(11.4, 8.0, 7.2, 148.0, 212.0);
                self.arc(4.6, 8.0, 7.2, -32.0, 32.0);
            }
            Glyph::Terminal => {
                self.line((3.0, 5.0), (6.5, 8.0));
                self.line((6.5, 8.0), (3.0, 11.0));
                self.line((9.0, 11.0), (13.0, 11.0));
            }
            Glyph::Search => {
                self.ring(6.8, 6.8, 4.2);
                self.line((10.0, 10.0), (13.5, 13.5));
            }
            Glyph::Gear => {
                // A cog: an inner hub, a toothed outer ring, and no diagonals, which would read
                // as a crossed-out sign rather than a gear.
                self.ring(8.0, 8.0, 2.6);
                self.ring(8.0, 8.0, 4.6);
                for step in 0..8 {
                    let angle = (step as f32) * std::f32::consts::TAU / 8.0;
                    let (sin, cos) = angle.sin_cos();
                    self.line(
                        (8.0 + sin * 4.6, 8.0 - cos * 4.6),
                        (8.0 + sin * 6.6, 8.0 - cos * 6.6),
                    );
                }
            }
            Glyph::Play => {
                self.triangle([(5.0, 3.0), (13.0, 8.0), (5.0, 13.0)]);
            }
            Glyph::Stop => {
                self.boxy(4.0, 4.0, 8.0, 8.0, 1.5, true);
            }
            Glyph::Pause => {
                // Gulp's pane header pause button: a circle with two bars.
                self.ring(8.0, 8.0, 6.4);
                self.boxy(5.6, 4.6, 1.6, 6.8, 0.4, true);
                self.boxy(8.8, 4.6, 1.6, 6.8, 0.4, true);
            }
            Glyph::Help => {
                // A circle around a question mark.
                self.ring(8.0, 8.0, 6.4);
                self.arc(8.0, 6.2, 2.2, 190.0, 20.0);
                self.line((8.0, 8.4), (8.0, 10.4));
                self.dot(8.0, 12.2, 0.9);
            }
            Glyph::Ellipsis => {
                self.dot(8.0, 3.6, 0.9);
                self.dot(8.0, 8.0, 0.9);
                self.dot(8.0, 12.4, 0.9);
            }
            Glyph::Funnel => {
                // A funnel with a drop below it, as Gulp's filter control shows.
                self.polyline(&[(2.5, 3.0), (13.5, 3.0), (9.2, 8.0), (9.2, 13.0)], false);
                self.polyline(&[(6.8, 8.0), (9.2, 13.0), (11.6, 8.0)], false);
            }
            Glyph::Clock => {
                self.ring(8.0, 8.0, 6.2);
                self.line((8.0, 4.6), (8.0, 8.2));
                self.line((8.0, 8.2), (10.8, 9.8));
            }
            Glyph::Warning => {
                // A triangle with an exclamation mark.
                self.polyline(&[(8.0, 2.2), (14.4, 13.2), (1.6, 13.2)], true);
                self.line((8.0, 6.4), (8.0, 9.6));
                self.dot(8.0, 11.6, 0.8);
            }
            Glyph::Diamond => {
                self.polyline(&[(8.0, 2.0), (14.0, 8.0), (8.0, 14.0), (2.0, 8.0)], true);
            }
            Glyph::Star => {
                // A five pointed outline star, as Gulp draws it next to "Rate this scan". The
                // character would come out of the emoji font.
                let mut points = Vec::new();
                for index in 0..10 {
                    let angle = -std::f32::consts::FRAC_PI_2
                        + index as f32 * std::f32::consts::PI / 5.0;
                    let radius = if index % 2 == 0 { 6.6 } else { 2.9 };
                    points.push((8.0 + angle.cos() * radius, 8.0 + angle.sin() * radius));
                }
                self.polyline(&points, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::epaint::Tessellator;

    fn tessellator() -> Tessellator {
        Tessellator::new(
            1.0,
            Default::default(),
            [0, 0],
            Vec::new(),
        )
    }

    fn box_at(size: f32) -> Rect {
        Rect::from_min_size(pos2(0.0, 0.0), Vec2::splat(size))
    }

    /// Tessellates one glyph and counts vertices. A glyph that draws nothing still compiles and
    /// still occupies a slot in the UI as an invisible gap, so this is the only way to prove one
    /// actually marks pixels.
    fn vertices(glyph: Glyph, size: f32) -> usize {
        let mut tessellator = tessellator();
        let mut mesh = eframe::epaint::Mesh::default();
        for shape in shapes(box_at(size), Color32::WHITE, glyph) {
            tessellator.tessellate_shape(shape, &mut mesh);
        }
        mesh.vertices.len()
    }

    /// A fingerprint of the tessellated geometry, rounded so sub-point noise cannot make two
    /// visually identical glyphs look different.
    fn fingerprint(glyph: Glyph) -> String {
        let mut tessellator = tessellator();
        let mut mesh = eframe::epaint::Mesh::default();
        for shape in shapes(box_at(16.0), Color32::WHITE, glyph) {
            tessellator.tessellate_shape(shape, &mut mesh);
        }
        mesh.vertices
            .iter()
            .map(|v| format!("{},{},", v.pos.x.round(), v.pos.y.round()))
            .collect()
    }

    #[test]
    fn every_glyph_actually_draws() {
        for glyph in Glyph::ALL {
            assert!(vertices(glyph, 16.0) > 0, "{glyph:?} produced no geometry");
        }
    }

    #[test]
    fn glyphs_are_visually_distinct() {
        for (i, a) in Glyph::ALL.iter().enumerate() {
            for b in &Glyph::ALL[i + 1..] {
                assert_ne!(fingerprint(*a), fingerprint(*b), "{a:?} and {b:?} render identically");
            }
        }
    }

    #[test]
    fn painting_at_any_size_is_safe_and_scales() {
        for glyph in Glyph::ALL {
            let mut areas = Vec::new();
            for size in [8.0f32, 16.0, 32.0] {
                assert!(vertices(glyph, size) > 0, "{glyph:?} empty at {size}px");
                areas.push(vertices(glyph, size));
            }
            // Doubling the size must not shrink the glyph.
            assert!(
                areas[2] >= areas[1],
                "{glyph:?} lost geometry when scaled up: {areas:?}"
            );
        }
    }

    #[test]
    fn every_tool_has_a_glyph() {
        for tool in [
            "Dashboard",
            "Target",
            "Proxy",
            "Intruder",
            "Repeater",
            "Sequencer",
            "Decoder",
            "Comparer",
            "Logger",
            "Extender",
        ] {
            assert_ne!(Glyph::for_tool(tool), Glyph::Info, "{tool} has no glyph");
        }
        assert_eq!(Glyph::for_tool("Nonsense"), Glyph::Info);
    }

    #[test]
    fn glyph_set_has_no_duplicates() {
        let mut names: Vec<String> = Glyph::ALL.iter().map(|g| format!("{g:?}")).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate glyph in the set");
        assert_eq!(Glyph::ALL.len(), 35, "update the count when adding a glyph");
    }
}