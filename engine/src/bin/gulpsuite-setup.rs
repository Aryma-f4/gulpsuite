//! Native GUI & CLI Setup Wizard binary (`gulpsuite-setup`).
//!
//! Runs as a native GUI Setup Wizard window by default (Welcome -> Destination -> Installing ->
//! Finished), or non-interactively with `--yes [--prefix DIR]` / `--uninstall [--prefix DIR]`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use gulpsuite::installer::{
    default_install_dir, detect_source_root, perform_install, perform_uninstall, SetupWizard,
};

fn main() -> eframe::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut prefix: Option<PathBuf> = None;
    let mut yes = false;
    let mut uninstall = false;
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
            _ if arg.starts_with("--prefix=") => {
                prefix = Some(PathBuf::from(&arg["--prefix=".len()..]));
            }
            _ => {}
        }
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
                println!("Installed Gulpsuite + Integrated Chromium to {}", installed.display());
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
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([680.0, 440.0])
            .with_min_inner_size([640.0, 420.0])
            .with_resizable(false)
            .with_title("Gulpsuite Setup Wizard"),
        ..Default::default()
    };
    eframe::run_native(
        "Gulpsuite Setup Wizard",
        options,
        Box::new(|_cc| Ok(Box::new(wizard))),
    )
}
