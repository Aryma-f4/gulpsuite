use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../packaging/windows/gulpsuite.ico");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("../packaging/windows/gulpsuite.ico");
    if !ico_path.is_file() {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("gulpsuite.rc");
    let obj_path = out_dir.join("gulpsuite_icon.o");
    let ico_escaped = ico_path.to_string_lossy().replace('\\', "\\\\");
    let rc_content = format!("1 ICON \"{ico_escaped}\"\n");
    if std::fs::write(&rc_path, rc_content).is_err() {
        return;
    }

    for tool in ["x86_64-w64-mingw32-windres", "windres"] {
        if let Ok(status) = Command::new(tool)
            .args([
                rc_path.to_str().unwrap_or_default(),
                "-O",
                "coff",
                "-o",
                obj_path.to_str().unwrap_or_default(),
            ])
            .status()
        {
            if status.success() && obj_path.is_file() {
                println!("cargo:rustc-link-arg={}", obj_path.display());
                break;
            }
        }
    }
}
