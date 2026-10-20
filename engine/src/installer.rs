//! Native cross-platform Setup Wizard (macOS, Linux, Windows).
//!
//! Mirrors the four install4j wizard screens REA identified in `burpsuite_pro_v2025.jar`
//! (`ev_3d4cd0219b626b9ce64f19aebbbe4e816a3970e3632e4351411799992e751963`):
//!   1. `WelcomeScreen`
//!   2. `InstallationDirectoryScreen`
//!   3. `InstallationScreen`
//!   4. `FinishedScreen`

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use eframe::egui::{self, Align, Color32, Context, Layout, RichText, Ui, Vec2};

use crate::ui::theme::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    Welcome,
    Directory,
    Installing,
    Finished,
}

impl SetupStep {
    pub const ALL: [SetupStep; 4] = [
        SetupStep::Welcome,
        SetupStep::Directory,
        SetupStep::Installing,
        SetupStep::Finished,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SetupStep::Welcome => "1. Welcome",
            SetupStep::Directory => "2. Select Destination",
            SetupStep::Installing => "3. Installing",
            SetupStep::Finished => "4. Finished",
        }
    }
}

#[derive(Clone, Debug)]
pub enum InstallProgress {
    Log(String, f32),
    Done(Result<PathBuf, String>),
}

pub struct SetupWizard {
    pub theme: Theme,
    pub step: SetupStep,
    pub platform: String,
    pub version: String,
    pub destination: String,
    pub include_chromium: bool,
    pub create_shortcut: bool,
    pub launch_on_finish: bool,
    pub progress: f32,
    pub logs: Vec<String>,
    pub installed_path: Option<PathBuf>,
    pub error: Option<String>,
    pub source_root: PathBuf,
    rx: Option<Receiver<InstallProgress>>,
}

impl Default for SetupWizard {
    fn default() -> Self {
        let platform = crate::browser::platform().to_string();
        let destination = default_install_dir(&platform)
            .to_string_lossy()
            .into_owned();
        Self {
            theme: Theme::load(false),
            step: SetupStep::Welcome,
            platform,
            version: env!("CARGO_PKG_VERSION").to_string(),
            destination,
            include_chromium: true,
            create_shortcut: true,
            launch_on_finish: true,
            progress: 0.0,
            logs: Vec::new(),
            installed_path: None,
            error: None,
            source_root: detect_source_root(),
            rx: None,
        }
    }
}

pub fn default_install_dir(platform: &str) -> PathBuf {
    if platform.starts_with("macos-") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Applications"))
            .join("Applications")
    } else if platform == "linux-x64" {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".local/opt/gulpsuite"))
            .unwrap_or_else(|| PathBuf::from("/opt/gulpsuite"))
    } else {
        std::env::var_os("LOCALAPPDATA")
            .map(|d| PathBuf::from(d).join("Programs").join("Gulpsuite"))
            .unwrap_or_else(|| PathBuf::from("C:/Users/Public/Gulpsuite"))
    }
}

pub fn detect_source_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut cursor = exe.parent();
        for _ in 0..5 {
            let Some(dir) = cursor else { break };
            if dir.join(".build/browser-stage/resources/chromium-manifest.json").is_file()
                || dir.join("Resources/chromium-manifest.json").is_file()
                || dir.join("resources/chromium-manifest.json").is_file()
                || dir.join("engine/Cargo.toml").is_file()
            {
                return dir.to_path_buf();
            }
            cursor = dir.parent();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn find_payload_binary(source_root: &Path, platform: &str) -> Result<PathBuf, String> {
    let exe_name = if platform == "windows-x64" {
        "gulpsuite.exe"
    } else {
        "gulpsuite"
    };
    let candidates = [
        source_root.join(exe_name),
        source_root.join("engine/target/release").join(exe_name),
        source_root.join("MacOS/Gulpsuite"),
        source_root.join("Contents/MacOS/Gulpsuite"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "Gulpsuite binary not found under {}",
        source_root.display()
    ))
}

fn find_payload_resources(source_root: &Path) -> Option<PathBuf> {
    let candidates = [
        source_root.join(".build/browser-stage/resources"),
        source_root.join("Resources"),
        source_root.join("Contents/Resources"),
        source_root.join("resources"),
    ];
    candidates
        .into_iter()
        .find(|dir| dir.join("chromium-manifest.json").is_file())
}

fn copy_tree_preserving_links(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(src).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_symlink() {
            let target = std::fs::read_link(&from).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&to);
                std::os::unix::fs::symlink(&target, &to).map_err(|e| e.to_string())?;
            }
            #[cfg(not(unix))]
            {
                let _ = target;
                std::fs::copy(&from, &to).map_err(|e| e.to_string())?;
            }
        } else if file_type.is_dir() {
            copy_tree_preserving_links(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Performs the installation into `destination` for `platform`.
pub fn perform_install(
    source_root: &Path,
    destination: &Path,
    platform: &str,
    version: &str,
    include_chromium: bool,
    create_shortcut: bool,
    mut on_progress: impl FnMut(&str, f32),
) -> Result<PathBuf, String> {
    on_progress("Locating Gulpsuite binary and Chromium payload…", 0.15);
    let binary = find_payload_binary(source_root, platform)?;
    let resources = if include_chromium {
        Some(find_payload_resources(source_root).ok_or_else(|| {
            "Staged Chromium resources not found (.build/browser-stage/resources)".to_string()
        })?)
    } else {
        None
    };

    if platform.starts_with("macos-") {
        let app_dir = if destination
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.ends_with(".app"))
        {
            destination.to_path_buf()
        } else {
            destination.join("Gulpsuite.app")
        };
        on_progress(&format!("Creating bundle {}…", app_dir.display()), 0.35);
        let contents = app_dir.join("Contents");
        let macos = contents.join("MacOS");
        std::fs::create_dir_all(&macos).map_err(|e| e.to_string())?;
        let target_bin = macos.join("Gulpsuite");
        std::fs::copy(&binary, &target_bin).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target_bin, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        if let Some(res) = resources {
            on_progress("Installing integrated Chromium browser…", 0.65);
            copy_tree_preserving_links(&res, &contents.join("Resources"))?;
        }
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>CFBundleName</key><string>Gulpsuite</string>\n\
             <key>CFBundleDisplayName</key><string>Gulpsuite</string>\n\
             <key>CFBundleExecutable</key><string>Gulpsuite</string>\n\
             <key>CFBundleIdentifier</key><string>net.gulpsuite.app</string>\n\
             <key>CFBundlePackageType</key><string>APPL</string>\n\
             <key>CFBundleShortVersionString</key><string>{version}</string>\n\
             <key>CFBundleVersion</key><string>{version}</string>\n\
             <key>LSMinimumSystemVersion</key><string>11.0</string>\n\
             <key>NSHighResolutionCapable</key><true/>\n\
             </dict></plist>\n"
        );
        std::fs::write(contents.join("Info.plist"), plist).map_err(|e| e.to_string())?;
        std::fs::write(contents.join("PkgInfo"), b"APPL????").map_err(|e| e.to_string())?;
        on_progress("Signing application bundle…", 0.90);
        let _ = std::process::Command::new("codesign")
            .args(["--force", "--deep", "--sign", "-"])
            .arg(&app_dir)
            .output();
        on_progress("Installation complete.", 1.0);
        Ok(app_dir)
    } else {
        on_progress(&format!("Creating directory {}…", destination.display()), 0.35);
        std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
        let exe_name = if platform == "windows-x64" {
            "gulpsuite.exe"
        } else {
            "gulpsuite"
        };
        let target_bin = destination.join(exe_name);
        std::fs::copy(&binary, &target_bin).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target_bin, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        if let Some(res) = resources {
            on_progress("Installing integrated Chromium browser…", 0.65);
            copy_tree_preserving_links(&res, &destination.join("resources"))?;
        }
        if create_shortcut && platform == "linux-x64" {
            on_progress("Creating desktop entry and launcher symlink…", 0.90);
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                let bin_dir = home.join(".local/bin");
                let app_dir = home.join(".local/share/applications");
                let _ = std::fs::create_dir_all(&bin_dir);
                let _ = std::fs::create_dir_all(&app_dir);
                #[cfg(unix)]
                {
                    let link = bin_dir.join("gulpsuite");
                    let _ = std::fs::remove_file(&link);
                    let _ = std::os::unix::fs::symlink(&target_bin, &link);
                }
                let desktop = format!(
                    "[Desktop Entry]\nType=Application\nName=Gulpsuite\n\
                     Comment=HTTP testing suite with integrated Chromium\n\
                     Exec={}\nTerminal=false\nCategories=Development;Network;\nStartupNotify=true\n",
                    target_bin.display()
                );
                let _ = std::fs::write(app_dir.join("gulpsuite.desktop"), desktop);
            }
        }
        on_progress("Installation complete.", 1.0);
        Ok(destination.to_path_buf())
    }
}

/// Removes installed application files while preserving user browser profiles and project data.
pub fn perform_uninstall(destination: &Path, platform: &str) -> Result<(), String> {
    if platform.starts_with("macos-") {
        let app_dir = if destination
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.ends_with(".app"))
        {
            destination.to_path_buf()
        } else {
            destination.join("Gulpsuite.app")
        };
        if app_dir.is_dir() {
            std::fs::remove_dir_all(&app_dir).map_err(|e| e.to_string())?;
        }
    } else {
        for rel in [
            "resources/chromium",
            "resources/chromium-manifest.json",
            "gulpsuite",
            "gulpsuite.exe",
        ] {
            let p = destination.join(rel);
            if p.is_dir() {
                let _ = std::fs::remove_dir_all(&p);
            } else if p.is_file() {
                let _ = std::fs::remove_file(&p);
            }
        }
        let _ = std::fs::remove_dir(destination.join("resources"));
        let _ = std::fs::remove_dir(destination);
    }
    Ok(())
}

impl SetupWizard {
    pub fn start_install(&mut self, ctx: Context) {
        self.step = SetupStep::Installing;
        self.progress = 0.05;
        self.logs.clear();
        self.error = None;
        let source_root = self.source_root.clone();
        let destination = PathBuf::from(self.destination.trim());
        let platform = self.platform.clone();
        let version = self.version.clone();
        let include_chromium = self.include_chromium;
        let create_shortcut = self.create_shortcut;
        let (tx, rx) = channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let res = perform_install(
                &source_root,
                &destination,
                &platform,
                &version,
                include_chromium,
                create_shortcut,
                |msg, pct| {
                    let _ = tx.send(InstallProgress::Log(msg.to_string(), pct));
                    ctx.request_repaint();
                },
            );
            let _ = tx.send(InstallProgress::Done(res));
            ctx.request_repaint();
        });
    }

    pub fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        while let Ok(msg) = rx.try_recv() {
            match msg {
                InstallProgress::Log(line, pct) => {
                    self.logs.push(line);
                    self.progress = pct;
                }
                InstallProgress::Done(Ok(path)) => {
                    self.progress = 1.0;
                    self.installed_path = Some(path);
                    self.step = SetupStep::Finished;
                    self.rx = None;
                    return;
                }
                InstallProgress::Done(Err(err)) => {
                    self.error = Some(err);
                    self.step = SetupStep::Finished;
                    self.rx = None;
                    return;
                }
            }
        }
    }

    pub fn draw(&mut self, ui: &mut Ui) {
        self.poll();
        let theme = self.theme.clone();
        ui.horizontal_top(|ui| {
            // Left install4j step sidebar
            egui::Frame::new()
                .fill(theme.color("ui.background.3"))
                .inner_margin(egui::Margin::symmetric(16, 20))
                .show(ui, |ui| {
                    ui.set_width(185.0);
                    ui.set_min_height(380.0);
                    crate::ui::app::bold_text(
                        ui,
                        "Gulpsuite Setup",
                        15.0,
                        theme.color("ui.text.header"),
                    );
                    ui.add_space(16.0);
                    for step in SetupStep::ALL {
                        let active = self.step == step;
                        let color = if active {
                            theme.color("ui.icon.link")
                        } else {
                            theme.color("ui.text.body")
                        };
                        ui.label(RichText::new(step.label()).strong().color(color));
                        ui.add_space(8.0);
                    }
                });

            ui.add_space(16.0);
            ui.vertical(|ui| {
                ui.set_min_height(380.0);
                ui.add_space(16.0);
                match self.step {
                    SetupStep::Welcome => {
                        crate::ui::app::bold_text(
                            ui,
                            &format!("Welcome to the Gulpsuite {} Setup Wizard", self.version),
                            20.0,
                            theme.color("ui.text.header"),
                        );
                        ui.add_space(12.0);
                        ui.label(
                            "This wizard will install Gulpsuite and its preconfigured integrated \
                             Chromium browser on your computer.",
                        );
                        ui.add_space(8.0);
                        ui.label(format!("Detected platform: {}", self.platform));
                        ui.label(
                            "No global OS proxy settings or personal browser profiles are modified.",
                        );
                        ui.add_space(140.0);
                        ui.separator();
                        ui.horizontal(|ui| {
                            if crate::ui::app::primary_button(ui, &theme, "Next >").clicked() {
                                self.step = SetupStep::Directory;
                            }
                        });
                    }
                    SetupStep::Directory => {
                        crate::ui::app::bold_text(
                            ui,
                            "Select Destination Directory",
                            20.0,
                            theme.color("ui.text.header"),
                        );
                        ui.add_space(12.0);
                        ui.label("Where should Gulpsuite be installed?");
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Destination folder:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.destination)
                                    .desired_width(320.0),
                            );
                        });
                        ui.add_space(10.0);
                        ui.checkbox(
                            &mut self.include_chromium,
                            "Bundle integrated Chromium browser (pre-pinned to session CA)",
                        );
                        ui.checkbox(
                            &mut self.create_shortcut,
                            "Create application launcher shortcut",
                        );
                        ui.add_space(110.0);
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui.button("< Back").clicked() {
                                self.step = SetupStep::Welcome;
                            }
                            if crate::ui::app::primary_button(ui, &theme, "Install").clicked() {
                                let ctx = ui.ctx().clone();
                                self.start_install(ctx);
                            }
                        });
                    }
                    SetupStep::Installing => {
                        crate::ui::app::bold_text(
                            ui,
                            "Installing Gulpsuite",
                            20.0,
                            theme.color("ui.text.header"),
                        );
                        ui.add_space(12.0);
                        ui.add(
                            egui::ProgressBar::new(self.progress)
                                .show_percentage()
                                .desired_width(420.0),
                        );
                        ui.add_space(12.0);
                        for line in &self.logs {
                            ui.label(RichText::new(line).monospace());
                        }
                    }
                    SetupStep::Finished => {
                        if let Some(err) = &self.error {
                            crate::ui::app::bold_text(
                                ui,
                                "Setup Failed",
                                20.0,
                                theme.color("ui.icon.error"),
                            );
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new(err).color(theme.color("ui.icon.error")),
                            );
                            ui.add_space(120.0);
                            ui.separator();
                            if ui.button("< Back").clicked() {
                                self.step = SetupStep::Directory;
                            }
                        } else {
                            crate::ui::app::bold_text(
                                ui,
                                &format!(
                                    "Completing the Gulpsuite {} Setup Wizard",
                                    self.version
                                ),
                                20.0,
                                theme.color("ui.text.header"),
                            );
                            ui.add_space(12.0);
                            ui.label(
                                "Setup has finished installing Gulpsuite and Integrated Chromium.",
                            );
                            if let Some(path) = &self.installed_path {
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(format!("Installed at: {}", path.display()))
                                        .monospace(),
                                );
                            }
                            ui.add_space(12.0);
                            ui.checkbox(&mut self.launch_on_finish, "Run Gulpsuite now");
                            ui.add_space(110.0);
                            ui.separator();
                            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                if crate::ui::app::primary_button(ui, &theme, "Finish").clicked() {
                                    if self.launch_on_finish {
                                        if let Some(path) = &self.installed_path {
                                            let bin = if path.join("Contents/MacOS/Gulpsuite").is_file() {
                                                path.join("Contents/MacOS/Gulpsuite")
                                            } else if path.join("gulpsuite.exe").is_file() {
                                                path.join("gulpsuite.exe")
                                            } else {
                                                path.join("gulpsuite")
                                            };
                                            let _ = std::process::Command::new(bin).spawn();
                                        }
                                    }
                                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                            });
                        }
                    }
                }
            });
        });
    }
}

impl eframe::App for SetupWizard {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        let mut style = (*ctx.style()).clone();
        style.visuals.panel_fill = self.theme.color("ui.background.2");
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.visuals.widgets.noninteractive.fg_stroke.color = self.theme.color("ui.text.body");
        let _ = Color32::WHITE;
        ctx.set_style(style);

        egui::CentralPanel::default().show(ctx, |ui| {
            self.draw(ui);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_installer_installs_and_uninstalls_preserving_user_sentinel() {
        let root = std::env::temp_dir().join(format!(
            "gulp-native-setup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("src");
        let stage = source.join(".build/browser-stage/resources/chromium");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(source.join("gulpsuite"), b"fake-gulpsuite-bin").unwrap();
        std::fs::write(stage.join("chrome"), b"fake-chromium-bin").unwrap();
        std::fs::write(
            source.join(".build/browser-stage/resources/chromium-manifest.json"),
            r#"{"platform":"linux-x64","revision":"1","executable":"chrome"}"#,
        )
        .unwrap();

        let dest = root.join("dest");
        let installed = perform_install(
            &source,
            &dest,
            "linux-x64",
            "0.2.0",
            true,
            false,
            |_, _| {},
        )
        .unwrap();
        assert!(installed.join("gulpsuite").is_file());
        assert!(installed.join("resources/chromium/chrome").is_file());

        let sentinel = installed.join("user-sentinel.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        perform_uninstall(&dest, "linux-x64").unwrap();
        assert!(!installed.join("gulpsuite").exists());
        assert!(sentinel.is_file());
        std::fs::remove_dir_all(root).unwrap();
    }
}
