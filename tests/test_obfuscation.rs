use obfsck::{ObfuscationLevel, obfuscate_alert, obfuscate_text, secret_pattern_errors};
use std::collections::HashMap;

#[test]
fn parse_obfuscation_level_values() {
    assert_eq!(
        ObfuscationLevel::parse("minimal"),
        Some(ObfuscationLevel::Minimal)
    );
    assert_eq!(
        ObfuscationLevel::parse("standard"),
        Some(ObfuscationLevel::Standard)
    );
    assert_eq!(
        ObfuscationLevel::parse("paranoid"),
        Some(ObfuscationLevel::Paranoid)
    );
    assert_eq!(ObfuscationLevel::parse("unknown"), None);
}

#[test]
fn obfuscate_text_replaces_ip_email_and_user_tokens() {
    let input = "user=alice from 10.0.0.7 email alice@example.com";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);

    assert!(out.contains("[USER-1]"));
    assert!(out.contains("[IP-INTERNAL-1]"));
    assert!(out.contains("[EMAIL-1]"));
    assert_eq!(map.users.get("alice"), Some(&"[USER-1]".to_string()));
    assert_eq!(
        map.ips.get("10.0.0.7"),
        Some(&"[IP-INTERNAL-1]".to_string())
    );
    assert_eq!(
        map.emails.get("alice@example.com"),
        Some(&"[EMAIL-1]".to_string())
    );
}

#[test]
fn minimal_level_redacts_known_secret_patterns() {
    let input = "aws key: AKIA1234567890ABCDEF";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Minimal);

    assert!(out.contains("[REDACTED-AWS-KEY]"));
    assert!(map.secrets_count >= 1);
}

#[test]
fn obfuscate_alert_obfuscates_output_and_fields() {
    let output = Some("User bob logged in from 203.0.113.9".to_string());
    let mut fields = HashMap::new();
    fields.insert("email".to_string(), "bob@corp.example".to_string());

    let (obf_output, obf_fields, map) =
        obfuscate_alert(output.as_deref(), Some(&fields), ObfuscationLevel::Standard);

    assert!(
        obf_output
            .expect("output should exist")
            .contains("[IP-EXTERNAL-1]")
    );
    let obf_fields = obf_fields.expect("fields should exist");
    assert_eq!(obf_fields.get("email"), Some(&"[EMAIL-1]".to_string()));
    assert!(map.ips.contains_key("203.0.113.9"));
    assert!(map.emails.contains_key("bob@corp.example"));
}

#[test]
fn repeated_values_map_to_single_stable_token() {
    let input = "src=10.0.0.7 dst=10.0.0.7 user=alice user=alice";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);

    assert_eq!(out.matches("[IP-INTERNAL-1]").count(), 2);
    assert_eq!(out.matches("[USER-1]").count(), 2);
    assert_eq!(map.ips.len(), 1);
    assert_eq!(map.users.len(), 1);
}

#[test]
fn standard_level_keeps_system_users_visible() {
    let input = "user=root user=alice";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);

    assert!(out.contains("user=root"));
    assert!(out.contains("user=[USER-1]"));
    assert!(!map.users.contains_key("root"));
    assert!(map.users.contains_key("alice"));
}

#[test]
fn minimal_level_does_not_apply_non_secret_obfuscation() {
    let input = "user=alice from 10.0.0.7 email alice@example.com";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Minimal);

    assert_eq!(out, input);
    assert!(map.users.is_empty());
    assert!(map.ips.is_empty());
    assert!(map.emails.is_empty());
}

#[test]
fn paranoid_level_obfuscates_paths_hostnames_and_high_entropy_strings() {
    let entropy = "aZ9xQ2mN7pL4vT1cR8yK3dF6hJ0wS5uB";
    let input = format!(
        "path=/home/alice/notes.txt sensitive=/etc/passwd host=api.example.com local=localhost.localdomain token={entropy}"
    );

    let (out, map) = obfuscate_text(&input, ObfuscationLevel::Paranoid);

    #[cfg(not(any(
        feature = "path-policy-home-user-redact",
        feature = "path-policy-non-allowlisted-redact"
    )))]
    assert!(out.contains("/home/[USER-1]/[FILE].txt"), "got: {out}");

    #[cfg(feature = "path-policy-home-user-redact")]
    assert!(out.contains("/home/[USERDIR]/[FILE].txt"));

    #[cfg(feature = "path-policy-non-allowlisted-redact")]
    assert!(out.contains("/home/[DIR]/[FILE].txt"));
    assert!(out.contains("/etc/passwd"));
    assert!(out.contains("host=[HOST-1]"));
    assert!(out.contains("localhost.localdomain"));
    // token= now caught by password_field before high-entropy scan
    assert!(
        out.contains("[REDACTED-HIGH-ENTROPY]") || out.contains("[REDACTED-PASSWORD]"),
        "entropy string should be redacted: {out}"
    );
    assert_eq!(
        map.hostnames.get("api.example.com"),
        Some(&"[HOST-1]".to_string())
    );
    assert!(map.secrets_count >= 1);
}

#[test]
fn paranoid_only_secret_patterns_are_not_applied_in_minimal() {
    let cloudflare_key = "AbCdEfGhIjKlMnOpQrStUvWxYz01234567890";
    let input = format!("cloudflare={cloudflare_key}");

    let (minimal_out, minimal_map) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    let (paranoid_out, paranoid_map) = obfuscate_text(&input, ObfuscationLevel::Paranoid);

    assert_eq!(minimal_out, input);
    assert_eq!(minimal_map.secrets_count, 0);
    assert!(paranoid_out.contains("[REDACTED-CLOUDFLARE-KEY]"));
    assert!(paranoid_map.secrets_count >= 1);
}

#[test]
fn paranoid_level_obfuscates_windows_paths() {
    let input = r"C:\Users\alice\notes.txt \\server\share\docs\config.yml";
    let (out, _) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    #[cfg(not(any(
        feature = "path-policy-home-user-redact",
        feature = "path-policy-non-allowlisted-redact"
    )))]
    {
        assert!(
            out.contains(r"C:\Users\alice\[FILE].txt"),
            "windows drive path not obfuscated: {out}"
        );
        assert!(
            out.contains(r"\\server\share\docs\[FILE].yml"),
            "unc path not obfuscated: {out}"
        );
    }

    #[cfg(feature = "path-policy-home-user-redact")]
    {
        assert!(
            out.contains(r"C:\Users\[USERDIR]\[FILE].txt"),
            "windows drive path not obfuscated: {out}"
        );
        assert!(
            out.contains(r"\\server\share\docs\[FILE].yml"),
            "unc path not obfuscated: {out}"
        );
    }

    #[cfg(feature = "path-policy-non-allowlisted-redact")]
    {
        assert!(
            out.contains(r"C:\Users\[DIR]\[FILE].txt"),
            "windows drive path not obfuscated: {out}"
        );
        assert!(
            out.contains(r"\\server\share\[DIR]\[FILE].yml"),
            "unc path not obfuscated: {out}"
        );
    }
}

#[test]
fn paranoid_level_preserves_sensitive_windows_paths() {
    let input = r"C:\Windows\System32\config\SAM";
    let (out, _) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(out.contains(input));
}

#[test]
fn user_re_matches_dotted_username() {
    // /Users/john.smith should redact john.smith as a username
    let input = "session started /Users/john.smith/.config";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        map.users.contains_key("john.smith"),
        "dotted username not captured; map={map:?}\nout={out}"
    );
}

#[test]
fn user_re_matches_hyphenated_username() {
    // /home/deploy-user paths should redact deploy-user
    let input = "running as /home/deploy-user process";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        map.users.contains_key("deploy-user"),
        "hyphenated username not captured; map={map:?}\nout={out}"
    );
}

#[test]
fn secret_pattern_definitions_compile() {
    let errors = secret_pattern_errors();
    assert!(
        errors.is_empty(),
        "secret pattern compile errors: {errors:?}"
    );
}
