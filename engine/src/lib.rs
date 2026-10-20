//! Gulpsuite core: the proxy, the scanner, and the analysis primitives the tools share.

pub mod analysis;
pub mod browser;
pub mod installer;
#[cfg(target_os = "macos")]
pub mod macos_menu;
pub mod platform_paths;
pub mod bambda;
pub mod automaton;
pub mod collaborator;
pub mod discover;
pub mod dns;
pub mod cookies;
pub mod logic;
pub mod http_target;
pub mod intruder;
pub mod meminfo;
pub mod project;
pub mod proxy;
pub mod ws;
pub mod replay;
pub mod scanner;
pub mod tls;
pub mod ui;
pub mod workspace;
