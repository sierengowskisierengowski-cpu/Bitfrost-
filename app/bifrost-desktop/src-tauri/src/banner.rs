//! Bifrost startup ASCII banner (terminal only).

use std::io::{stdout, IsTerminal};

const BANNER_TEMPLATE: &str = r#"╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗███████╗██████╗  ██████╗ ███████╗████████╗     ║
║   ██╔══██╗██║██╔════╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝     ║
║   ██████╔╝██║█████╗  ██████╔╝██║   ██║███████╗   ██║        ║
║   ██╔══██╗██║██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║        ║
║   ██████╔╝██║██║     ██║  ██║╚██████╔╝███████║   ██║        ║
║   ╚═════╝ ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ║
║                                                              ║
║              R A I N B O W   B R I D G E                     ║
║                                                              ║
║         Local AI-Powered Endpoint Detection & Response       ║
║                                                              ║
║                  The Bridge Is Watched                       ║
║                  Heimdall Never Sleeps                       ║
║                                                              ║
║                       v{version:<8}                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝"#;

const VERSION: &str = "0.3.0";
const PURPLE: (u8, u8, u8) = (123, 94, 167);
const PINK: (u8, u8, u8) = (196, 96, 122);
const BORDER: (u8, u8, u8) = (90, 70, 130);
const MUTED: (u8, u8, u8) = (160, 140, 180);

fn truecolor(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{r};{g};{b}m")
}

fn lerp_rgb(t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    (
        (PURPLE.0 as f32 + (PINK.0 as f32 - PURPLE.0 as f32) * t) as u8,
        (PURPLE.1 as f32 + (PINK.1 as f32 - PURPLE.1 as f32) * t) as u8,
        (PURPLE.2 as f32 + (PINK.2 as f32 - PURPLE.2 as f32) * t) as u8,
    )
}

fn colorize_line(line: &str, index: usize, total: usize) -> String {
    let reset = "\x1b[0m";
    let stripped = line.trim();
    if stripped.is_empty() {
        return line.to_string();
    }
    if stripped.starts_with('╔') || stripped.starts_with('╚') {
        return format!("{}{}{}", truecolor(BORDER.0, BORDER.1, BORDER.2), line, reset);
    }
    if line.contains('█') || line.contains("██╔") {
        let t = index as f32 / (total.saturating_sub(1).max(1) as f32);
        let (r, g, b) = lerp_rgb(t);
        return format!("{}{}{}", truecolor(r, g, b), line, reset);
    }
    if line.contains("R A I N B O W") {
        return format!("{}{}{}", truecolor(PINK.0, PINK.1, PINK.2), line, reset);
    }
    if line.contains("The Bridge Is Watched") {
        return format!("{}{}{}", truecolor(PURPLE.0, PURPLE.1, PURPLE.2), line, reset);
    }
    if line.contains("Heimdall Never") {
        return format!("{}{}{}", truecolor(PINK.0, PINK.1, PINK.2), line, reset);
    }
    if line.contains("Local AI-Powered") {
        return format!("{}{}{}", truecolor(MUTED.0, MUTED.1, MUTED.2), line, reset);
    }
    if line.contains('v') && line.contains('║') {
        return format!("{}{}{}", truecolor(PINK.0, PINK.1, PINK.2), line, reset);
    }
    format!("{}{}{}", truecolor(MUTED.0, MUTED.1, MUTED.2), line, reset)
}

/// Print the banner once when stdout is an interactive terminal.
pub fn print_startup_banner() {
    if std::env::var_os("BIFROST_NO_BANNER").is_some() {
        return;
    }
    if !stdout().is_terminal() {
        return;
    }
    let text = BANNER_TEMPLATE.replace("{version:<8}", &format!("{VERSION:<8}"));
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    for (i, line) in lines.iter().enumerate() {
        println!("{}", colorize_line(line, i, total));
    }
    println!("\x1b[0m");
}
