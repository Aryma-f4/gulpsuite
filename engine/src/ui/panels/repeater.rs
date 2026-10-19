//! Repeater: hand-edited requests.

use eframe::egui::Ui;

use crate::ui::app::App;

/// One request in the Repeater. Burp keeps several open at once, each in its own tab.
#[derive(Clone)]
pub struct RepeaterTab {
    /// The name on the tab, taken from the target.
    pub name: String,
    pub host: String,
    pub raw: String,
    pub response: String,
    pub status: Option<u16>,
    pub sending: bool,
    /// The in-flight request id, if any.
    pub pending: Option<u64>,
    /// The raw editor is shown only on demand; the coloured view is the default.
    pub editing: bool,
}

impl Default for RepeaterTab {
    fn default() -> Self {
        RepeaterTab {
            name: "1".into(),
            host: "http://example.com/".into(),
            raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            response: String::new(),
            status: None,
            sending: false,
            pending: None,
            editing: false,
        }
    }
}

#[derive(Clone)]
pub struct RepeaterPanel {
    pub tabs: Vec<RepeaterTab>,
    /// The tab that is open.
    pub active: usize,
}

impl Default for RepeaterPanel {
    fn default() -> Self {
        RepeaterPanel {
            tabs: vec![RepeaterTab::default()],
            active: 0,
        }
    }
}

impl RepeaterPanel {
    /// The tab that is open. There is always one, because a new panel starts with a tab.
    pub fn active(&self) -> &RepeaterTab {
        self.tabs.get(self.active).unwrap_or(&self.tabs[0])
    }

    pub fn active_mut(&mut self) -> &mut RepeaterTab {
        let index = self.active.min(self.tabs.len().saturating_sub(1));
        &mut self.tabs[index]
    }

    /// Opens a request in a new tab, the way Burp does when something is sent to the Repeater.
    pub fn open(&mut self, host: &str, raw: &str) {
        let name = name_for(host, self.tabs.len() + 1);
        self.tabs.push(RepeaterTab {
            name,
            host: host.to_string(),
            raw: raw.to_string(),
            response: String::new(),
            status: None,
            sending: false,
            pending: None,
            editing: false,
        });
        self.active = self.tabs.len() - 1;
    }

    /// Puts a request into the tab that is open, replacing what is in it.
    pub fn reuse(&mut self, host: &str, raw: &str, response: &str) {
        let count = self.tabs.len();
        let tab = self.active_mut();
        tab.name = name_for(host, count);
        tab.host = host.to_string();
        tab.raw = raw.to_string();
        tab.response = response.to_string();
        tab.status = None;
        tab.editing = false;
    }

    /// Closes a tab, keeping at least one open.
    pub fn close(&mut self, index: usize) {
        if self.tabs.len() <= 1 || index >= self.tabs.len() {
            return;
        }
        self.tabs.remove(index);
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len() - 1;
        }
    }
}

/// The name on a tab: the host, with a number when the name is taken.
fn name_for(host: &str, fallback: usize) -> String {
    let rest = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(host);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        fallback.to_string()
    } else {
        authority.to_string()
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    
    tabs(app, ui, &theme);

    // Collect anything that came back since the last frame.
    let pending = app.panels.repeater.active().pending;
    if let Some(id) = pending {
        if let Some((status, body)) = app.take_response(id) {
            let tab = app.panels.repeater.active_mut();
            tab.status = Some(status);
            tab.response = body;
            tab.sending = false;
            tab.pending = None;
            app.status = format!("Response {status} ({} bytes)", tab.response.len());
        }
    }

    ui.horizontal(|ui| {
        ui.label("Target");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.repeater.active_mut().host)
                .desired_width(320.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        if ui
            .add_enabled(
                !app.panels.repeater.active().sending,
                eframe::egui::Button::new("Send"),
            )
            .clicked()
        {
            send(app);
        }
    });
    ui.add_space(4.0);

    let message_bg = theme.color("ui.editor.message.background");
    let colour = match app.panels.repeater.active().status {
        Some(200..=399) => theme.color("ui.icon.success"),
        Some(400..=499) => theme.color("ui.icon.warning"),
        Some(_) => theme.color("ui.icon.error"),
        None => theme.color("ui.icon.default"),
    };
    let response = app.panels.repeater.active().response.clone();
    let request = app.panels.repeater.active().raw.clone();

    ui.columns(2, |columns| {
        columns[0].horizontal(|ui| {
            ui.label("Request");
            let editing = app.panels.repeater.active().editing;
            if ui.button(if editing { "View" } else { "Edit" }).clicked() {
                let tab = app.panels.repeater.active_mut();
                tab.editing = !tab.editing;
            }
        });
        if app.panels.repeater.active().editing {
            crate::ui::highlight::show_editable(
                &mut columns[0],
                &mut app.panels.repeater.active_mut().raw,
                &theme,
                message_bg,
            );
        } else {
            crate::ui::highlight::show_message(&mut columns[0], &request, &theme, message_bg);
        }

        columns[1].horizontal(|ui| {
            ui.label("Response");
            let status = match app.panels.repeater.active().status {
                Some(status) => status.to_string(),
                None if response.is_empty() => "no response yet".into(),
                None => "error".into(),
            };
            ui.label(eframe::egui::RichText::new(status).color(colour));
        });
        crate::ui::highlight::show_message(&mut columns[1], &response, &theme, message_bg);
    });

    ui.add_space(6.0);
    ui.separator();
    analyzers(app, ui, &response);
}

/// The row of tabs, the way Burp shows the requests that are open.
fn tabs(app: &mut App, ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    ui.horizontal_wrapped(|ui| {
        for index in 0..app.panels.repeater.tabs.len() {
            let selected = index == app.panels.repeater.active;
            let name = app.panels.repeater.tabs[index].name.clone();
            let label = eframe::egui::RichText::new(name)
                .color(theme.color(if selected {
                    "ui.text.body"
                } else {
                    "ui.icon.default"
                }));
            if ui.selectable_label(selected, label).clicked() {
                app.panels.repeater.active = index;
            }
            if app.panels.repeater.tabs.len() > 1
                && ui
                    .small_button(eframe::egui::RichText::new("x").small())
                    .on_hover_text("Close this tab")
                    .clicked()
            {
                app.panels.repeater.close(index);
                break;
            }
        }
        if ui.button("+").on_hover_text("New tab").clicked() {
            let host = app.panels.repeater.active().host.clone();
            app.panels.repeater.open(&host, "");
        }
    });
    ui.add_space(2.0);
}

/// Burp's response analyzers. Backed by `http/message/responses/analysis/*` in the shipped API:
/// a keywords analyser, a variations analyser and attribute extraction.
fn analyzers(app: &mut App, ui: &mut Ui, response: &str) {
    let theme = app.theme.clone();
    let (head, body) = crate::analysis::split_message(response);
    let content_type = head
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-type:"))
        .map(|line| line[13..].trim().to_string())
        .unwrap_or_default();

    if body.is_empty() {
        super::muted(ui, &theme, "No response body to analyse.");
        return;
    }

    let markup = crate::analysis::is_markup(&content_type, body);
    let keywords = crate::analysis::keywords(body, 40);
    let attributes = if markup {
        crate::analysis::attributes(body, 40)
    } else {
        Vec::new()
    };
    // Variations compare this response against its siblings from the same host in the history.
    let host = app.panels.repeater.active().host.clone();
    let siblings: Vec<String> = app
        .log
        .iter()
        .rev()
        .filter(|tx| {
            !tx.response.is_empty() && tx.target != host && host.ends_with(&tx.host)
        })
        .take(20)
        .map(|tx| {
            crate::analysis::split_message(&tx.response)
                .1
                .to_string()
        })
        .collect();
    let variations = crate::analysis::variations(body, &siblings);
    let (unique, partial, shared) = crate::analysis::variation_summary(&variations);

    ui.horizontal_wrapped(|ui| {
        super::label(ui, &theme, &format!("Keywords: {}", keywords.len()));
        super::label(
            ui,
            &theme,
            &format!(
                "Attributes: {}",
                if markup { attributes.len() } else { 0 }
            ),
        );
        super::label(
            ui,
            &theme,
            &format!("Variations: {unique} unique, {partial} partial, {shared} shared"),
        );
        super::muted(
            ui,
            &theme,
            &format!("(compared against {} response(s))", siblings.len()),
        );
    });

    ui.columns(3, |columns| {
        super::label(&mut columns[0], &theme, "Keywords");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[0], |ui| {
                for keyword in &keywords {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(keyword.text.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &keyword.count.to_string());
                    });
                }
            });

        super::label(&mut columns[1], &theme, "Attributes");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[1], |ui| {
                if !markup {
                    super::muted(ui, &theme, "Not a markup response.");
                }
                for attribute in &attributes {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(attribute.name.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &attribute.count.to_string());
                    });
                }
            });

        super::label(&mut columns[2], &theme, "Variations");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[2], |ui| {
                if siblings.is_empty() {
                    super::muted(
                        ui,
                        &theme,
                        "No comparable responses yet. Send a few requests to the same host.",
                    );
                }
                for (index, row) in variations.iter().take(80).enumerate() {
                    let text = match row {
                        crate::analysis::Variation::Unique => "unique".to_string(),
                        crate::analysis::Variation::Shared(n) => format!("in {n}"),
                        crate::analysis::Variation::Partial(n, total) => format!("in {n} of {total}"),
                    };
                    let colour = match row {
                        crate::analysis::Variation::Unique => theme.color("ui.icon.warning"),
                        crate::analysis::Variation::Partial(_, _) => theme.color("ui.icon.information"),
                        crate::analysis::Variation::Shared(_) => theme.color("ui.icon.default"),
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(format!("{index}"))
                                .color(theme.color("ui.icon.disabled")),
                        );
                        ui.label(eframe::egui::RichText::new(text).color(colour));
                    });
                }
            });
    });
}

pub(crate) fn send(app: &mut App) {
    let host = app.panels.repeater.active().host.trim().to_string();
    // A live Bambda script rewrites the request before it leaves, and a broken one blocks the send
    // rather than quietly sending something the operator did not intend.
    let raw = match app.panels.extender.apply_live(&app.panels.repeater.active().raw) {
        Ok(raw) => raw,
        Err(why) => {
            app.status = format!("Bambda rejected the request: {why}");
            return;
        }
    };
    let secure = host.starts_with("https://");
    let rest = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(&host)
        .to_string();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(&rest);
    let (hostname, port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), 80),
        },
        None => (authority.to_string(), 80),
    };
    if hostname.is_empty() {
        app.status = "Target is missing a host".into();
        return;
    }
    let tab = app.panels.repeater.active_mut();
    tab.status = None;
    tab.response = format!("Sending to {hostname}:{port}…");
    let id = app.send_request(hostname, port, raw, secure);
    let tab = app.panels.repeater.active_mut();
    tab.pending = Some(id);
    tab.sending = true;
    app.status = format!("Sent request #{id}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::app::App;

    /// Burp keeps several requests open at once, each in its own tab, and something sent to the
    /// Repeater arrives in a new one.
    #[test]
    fn the_repeater_keeps_several_requests_open() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.panels.repeater
            .open("http://a.test/one", "GET /one HTTP/1.1\r\nHost: a.test\r\n\r\n");
        app.panels
            .repeater
            .open("http://b.test/two", "GET /two HTTP/1.1\r\nHost: b.test\r\n\r\n");

        assert_eq!(app.panels.repeater.tabs.len(), 3, "the first tab plus two");
        assert_eq!(app.panels.repeater.active, 2, "the last one sent is open");
        assert!(
            app.panels.repeater.active().raw.contains("/two"),
            "the open tab is the one that was sent last"
        );

        // Closing a tab keeps at least one open.
        app.panels.repeater.close(2);
        assert_eq!(app.panels.repeater.tabs.len(), 2);
        app.panels.repeater.close(0);
        app.panels.repeater.close(0);
        assert_eq!(app.panels.repeater.tabs.len(), 1, "one tab always remains");
    }

    /// The tab bar is drawn, with the name of the open tab on it.
    #[test]
    fn the_repeater_draws_its_tabs() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.panels.repeater
            .open("http://b.test/two", "GET /two HTTP/1.1\r\nHost: b.test\r\n\r\n");

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                draw(&mut app, ui);
            });
        });
        let texts: Vec<String> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                eframe::egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect();
        let all = texts.join("\n");
        assert!(all.contains("b.test"), "the tab should be named after the host: {all}");
        assert!(
            all.contains("/two"),
            "the open request should be in the editor: {all}"
        );
    }
}
