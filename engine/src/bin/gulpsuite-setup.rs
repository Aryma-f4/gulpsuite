//! Self-contained cross-platform Setup Wizard & Application binary (`gulpsuite-setup`).
//!
//! Dual-mode executable:
//! - When invoked as `*-setup*` or with `--setup` / `--yes`: runs the 4-step Graphical Setup Wizard
//!   (or headless CLI installer) and installs itself as `gulpsuite.exe` / `Gulpsuite.app` / `gulpsuite`
//!   plus `Uninstall.exe`, desktop/start-menu shortcuts, and publisher metadata (`Aryma-f4`).
//! - When invoked as the installed `gulpsuite.exe` / `gulpsuite` / `Gulpsuite`: launches the main
//!   `Gulpsuite` security suite directly.
//! - When invoked as `Uninstall.exe` or with `--uninstall`: removes the installation cleanly.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use gulpsuite::installer::{
    default_install_dir, detect_source_root, perform_install, perform_uninstall, SetupWizard,
};
use gulpsuite::ui::app::App;

fn main() -> eframe::Result<()> {
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default();

    let mut args = std::env::args().skip(1);
    let mut prefix: Option<PathBuf> = None;
    let mut yes = false;
    let mut uninstall = exe_name.contains("uninstall");
    let mut force_setup = false;
    let mut source_root = detect_source_root();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prefix" => {
                if let Some(p) = args.next() {
                    prefix = Some(PathBuf::from(p));
                }
            }
            "--source" => {
                if let Some(s) = args.next() {
                    source_root = PathBuf::from(s);
                }
            }
            "--yes" | "-y" | "/S" => yes = true,
            "--uninstall" => uninstall = true,
            "--setup" | "--install" => force_setup = true,
            _ if arg.starts_with("--prefix=") => {
                prefix = Some(PathBuf::from(&arg["--prefix=".len()..]));
            }
            _ => {}
        }
    }

    // If launched as the installed `gulpsuite.exe` / `gulpsuite` / `Gulpsuite` binary, run the main app!
    let is_setup_exe = exe_name.contains("setup") || exe_name.contains("install");
    if !is_setup_exe && !uninstall && !yes && !force_setup && prefix.is_none() {
        let options = eframe::NativeOptions {
            multisampling: 4,
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1280.0, 800.0])
                .with_min_inner_size([760.0, 480.0])
                .with_resizable(true)
                .with_title("Gulpsuite")
                .with_icon(gulpsuite::app_icon()),
            ..Default::default()
        };
        return eframe::run_native(
            "Gulpsuite",
            options,
            Box::new(|cc| Ok(Box::new(App::new(cc)))),
        );
    }

    let platform = gulpsuite::browser::platform();
    let dest = prefix.unwrap_or_else(|| default_install_dir(platform));

    if uninstall {
        if let Err(err) = perform_uninstall(&dest, platform) {
            eprintln!("Uninstall failed: {err}");
            std::process::exit(1);
        }
        println!("Uninstalled Gulpsuite from {}", dest.display());
        return Ok(());
    }

    if yes {
        match perform_install(
            &source_root,
            &dest,
            platform,
            env!("CARGO_PKG_VERSION"),
            true,
            true,
            |msg, pct| println!("[{:>3.0}%] {msg}", pct * 100.0),
        ) {
            Ok(installed) => {
                println!(
                    "Installed Gulpsuite (Publisher: Aryma-f4) to {}",
                    installed.display()
                );
                return Ok(());
            }
            Err(err) => {
                eprintln!("Setup failed: {err}");
                std::process::exit(1);
            }
        }
    }

    let mut wizard = SetupWizard::default();
    wizard.source_root = source_root;
    wizard.destination = dest.to_string_lossy().into_owned();

    let options = eframe::NativeOptions {
        multisampling: 4,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([720.0, 460.0])
            .with_min_inner_size([400.0, 300.0])
            .with_resizable(true)
            .with_title("Gulpsuite Setup — Publisher: Aryma-f4")
            .with_icon(gulpsuite::app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Gulpsuite Setup — Publisher: Aryma-f4",
        options,
        Box::new(|cc| {
            gulpsuite::ui::app::install_fonts(&cc.egui_ctx);
            Ok(Box::new(wizard))
        }),
    )
}
