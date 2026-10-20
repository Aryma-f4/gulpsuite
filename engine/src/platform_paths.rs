//! Per-user application storage. Never falls back to a shared temporary directory.
use std::path::PathBuf;

pub fn data_dir_for(
    os: &str,
    home: Option<&str>,
    override_dir: Option<&str>,
) -> Result<PathBuf, String> {
    let path = match os {
        "windows" => {
            PathBuf::from(override_dir.ok_or("LOCALAPPDATA is unavailable")?).join("Gulpsuite")
        }
        "macos" => PathBuf::from(home.ok_or("HOME is unavailable")?)
            .join("Library/Application Support/Gulpsuite"),
        "linux" => match override_dir {
            Some(path) => PathBuf::from(path).join("gulpsuite"),
            None => {
                PathBuf::from(home.ok_or("HOME is unavailable")?).join(".local/share/gulpsuite")
            }
        },
        _ => return Err("unsupported operating system".into()),
    };
    // Recognize a Windows absolute drive path in cross-platform path tests too.
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    let absolute = if os == "windows" {
        (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'/' | b'\\')) || text.starts_with("\\\\")
    } else { text.starts_with('/') };
    if !absolute {
        return Err("application data directory must be absolute".into());
    }
    Ok(path)
}

pub fn data_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").ok();
    let override_dir = std::env::var(if cfg!(windows) {
        "LOCALAPPDATA"
    } else {
        "XDG_DATA_HOME"
    })
    .ok();
    data_dir_for(
        std::env::consts::OS,
        home.as_deref(),
        override_dir.as_deref(),
    )
}
