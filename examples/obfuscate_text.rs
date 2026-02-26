use obfsck::{obfuscate_text, ObfuscationLevel};

fn main() {
    let mut lines = Vec::new();

    for i in 0..80 {
        lines.push(format!(
            "ts=2026-02-25T17:{:02}:00Z level=warn user=user{} src=10.0.{}.{} dst=203.0.113.{} email=user{}@corp.example host=api{}.corp.example path=/home/user{}/services/payment/config{}.yaml",
            i % 60,
            i,
            (i % 20) + 1,
            (i % 250) + 1,
            (i % 250) + 1,
            i,
            i % 7,
            i,
            i
        ));
    }

    let input = lines.join("\n");
    let (out, map) = obfuscate_text(&input, ObfuscationLevel::Paranoid);

    println!("Input bytes: {}", input.len());
    println!("Output bytes: {}", out.len());
    println!(
        "Mappings => ips: {}, users: {}, emails: {}, hostnames: {}, secrets: {}",
        map.ips.len(),
        map.users.len(),
        map.emails.len(),
        map.hostnames.len(),
        map.secrets_count
    );
    println!("--- output preview ---");
    println!("{}", out.lines().take(5).collect::<Vec<_>>().join("\n"));
}
