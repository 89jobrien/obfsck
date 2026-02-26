use obfsck::{obfuscate_text, ObfuscationLevel};
use std::env;
use std::process::Command;

fn fetch_raw(url: &str) -> Option<String> {
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "25", url])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout).ok()
}

fn synthetic_payload() -> String {
    let mut lines = Vec::new();
    for i in 0..600 {
        lines.push(format!(
            "ts=2026-02-25T18:{:02}:00Z level=info user=user{} src=10.2.{}.{} dst=203.0.113.{} email=user{}@corp.example host=svc{}.corp.example path=/home/user{}/apps/payments/file{}.log secret=AKIA{:016}",
            i % 60,
            i % 120,
            (i % 25) + 1,
            (i % 250) + 1,
            (i % 250) + 1,
            i % 120,
            i % 15,
            i % 120,
            i,
            i
        ));
    }
    lines.join("\n")
}

fn main() {
    let payload = if let Ok(url) = env::var("OBFSCK_GIST_URL") {
        match fetch_raw(&url) {
            Some(text) if !text.is_empty() => {
                println!("Loaded payload from OBFSCK_GIST_URL");
                text
            }
            _ => {
                println!("Failed to load gist payload, using synthetic fallback");
                synthetic_payload()
            }
        }
    } else {
        synthetic_payload()
    };

    let (out, map) = obfuscate_text(&payload, ObfuscationLevel::Paranoid);

    println!("Payload bytes in : {}", payload.len());
    println!("Payload bytes out: {}", out.len());
    println!(
        "Token totals => ips: {}, users: {}, emails: {}, hostnames: {}, secrets: {}",
        map.ips.len(),
        map.users.len(),
        map.emails.len(),
        map.hostnames.len(),
        map.secrets_count
    );
    println!(
        "Preview:\n{}",
        out.lines().take(8).collect::<Vec<_>>().join("\n")
    );
}
