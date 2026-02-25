use obfsck::{obfuscate_text, ObfuscationLevel};
use std::process::Command;

fn fetch(url: &str) -> String {
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "20", url])
        .output()
        .expect("curl should be available to run public API test");

    assert!(
        output.status.success(),
        "curl failed for {url}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("response should be valid UTF-8")
}

#[test]
#[ignore = "network test: runs only when explicitly requested"]
fn obfuscates_live_public_api_payloads() {
    let users_json = fetch("https://jsonplaceholder.typicode.com/users");
    let (standard_out, standard_map) = obfuscate_text(&users_json, ObfuscationLevel::Standard);

    assert!(
        !standard_map.emails.is_empty(),
        "expected email redaction from users payload"
    );
    assert!(standard_out.contains("[EMAIL-"));
    assert!(
        !standard_out.contains("Sincere@april.biz"),
        "known public email should be redacted"
    );

    let (paranoid_out, paranoid_map) = obfuscate_text(&users_json, ObfuscationLevel::Paranoid);
    assert!(
        !paranoid_map.hostnames.is_empty(),
        "expected hostname redaction in paranoid mode"
    );
    assert!(paranoid_out.contains("[HOST-"));

    let ip_json = fetch("https://api64.ipify.org?format=json");
    let (ip_out, ip_map) = obfuscate_text(&ip_json, ObfuscationLevel::Standard);
    assert!(
        !ip_map.ips.is_empty(),
        "expected at least one IP token from ipify payload"
    );
    assert!(ip_out.contains("[IP-"));
}
