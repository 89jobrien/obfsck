use obfsck::{ObfuscationLevel, obfuscate_text};
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

#[test]
#[ignore = "network test: runs only when explicitly requested"]
fn obfuscates_jsonplaceholder_posts_with_user_emails_and_hosts() {
    let users_json = fetch("https://jsonplaceholder.typicode.com/users");

    let (standard_out, standard_map) = obfuscate_text(&users_json, ObfuscationLevel::Standard);
    assert!(
        !standard_map.emails.is_empty(),
        "expected at least one email token from users payload"
    );
    assert!(standard_out.contains("[EMAIL-"));

    let (paranoid_out, paranoid_map) = obfuscate_text(&users_json, ObfuscationLevel::Paranoid);
    assert!(
        !paranoid_map.hostnames.is_empty(),
        "expected at least one hostname token from users payload"
    );
    assert!(paranoid_out.contains("[HOST-"));
}

#[test]
#[ignore = "network test: runs only when explicitly requested"]
fn obfuscates_ip_payloads_from_multiple_public_services() {
    let ipify_json = fetch("https://api64.ipify.org?format=json");
    let (ipify_out, ipify_map) = obfuscate_text(&ipify_json, ObfuscationLevel::Standard);
    assert!(
        !ipify_map.ips.is_empty(),
        "expected IP token from ipify response"
    );
    assert!(ipify_out.contains("[IP-"));

    let httpbin_ip_json = fetch("https://httpbin.io/ip");
    let (httpbin_out, httpbin_map) = obfuscate_text(&httpbin_ip_json, ObfuscationLevel::Standard);
    assert!(
        !httpbin_map.ips.is_empty(),
        "expected IP token from httpbin /ip response"
    );
    assert!(httpbin_out.contains("[IP-"));
}

#[test]
#[ignore = "network test: runs only when explicitly requested"]
fn obfuscates_hosts_from_httpbin_and_restcountries() {
    let httpbin_anything = fetch("https://httpbin.io/anything/obfsck-network-test");
    let (httpbin_out, httpbin_map) = obfuscate_text(&httpbin_anything, ObfuscationLevel::Paranoid);
    assert!(
        !httpbin_map.hostnames.is_empty(),
        "expected hostname token from httpbin /anything response"
    );
    assert!(httpbin_out.contains("[HOST-"));

    let countries_json = fetch("https://restcountries.com/v3.1/name/france");
    let (countries_out, countries_map) =
        obfuscate_text(&countries_json, ObfuscationLevel::Paranoid);
    assert!(
        !countries_map.hostnames.is_empty(),
        "expected hostname token from restcountries links"
    );
    assert!(countries_out.contains("[HOST-"));
}

#[test]
#[ignore = "network test: runs only when explicitly requested"]
fn obfuscates_randomuser_email_payloads() {
    let randomuser_json = fetch("https://randomuser.me/api/?results=2&seed=obfsck");
    let (out, map) = obfuscate_text(&randomuser_json, ObfuscationLevel::Standard);

    assert!(
        !map.emails.is_empty(),
        "expected at least one email token from randomuser payload"
    );
    assert!(out.contains("[EMAIL-"));
}
