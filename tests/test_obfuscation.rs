use obfsck::{
    ObfuscationLevel, Obfuscator, obfuscate_alert, obfuscate_text, secret_pattern_errors,
};
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

#[test]
fn user_re_does_not_capture_trailing_dot() {
    // Sentence-final period should not be included in the username
    let input = "started by /Users/joe.";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        map.users.contains_key("joe"),
        "expected 'joe' in users map, got: {map:?}\nout={out}"
    );
    assert!(
        !map.users.contains_key("joe."),
        "trailing dot was incorrectly absorbed into username: {map:?}"
    );
}

#[test]
fn high_entropy_allowlist_bypass() {
    // Bug obfsck-9: obfuscate_high_entropy() ignores the runtime allowlist
    // A high-entropy string in the allowlist should pass through unredacted
    let high_entropy_token = "aZ9xQ2mN7pL4vT1cR8yK3dF6hJ0wS5uB";
    // Use 'value=' prefix (not 'token=') to avoid password field pattern
    let input = format!("value={high_entropy_token}");
    // The regex matches the entire "value=..." as one token because '=' is in the
    // character class [A-Za-z0-9+/=_-]
    let matched_by_regex = format!("value={high_entropy_token}");

    let mut obfuscator =
        Obfuscator::new(ObfuscationLevel::Paranoid).with_allowlist(vec![matched_by_regex.clone()]);
    let out = obfuscator.obfuscate(&input);

    // Without fix: will contain [REDACTED-HIGH-ENTROPY] even though token is allowlisted
    // With fix: should pass through unredacted
    assert!(
        out.contains(&matched_by_regex),
        "allowlisted high-entropy token was redacted despite allowlist: {out}"
    );
    assert!(
        !out.contains("[REDACTED-HIGH-ENTROPY]"),
        "allowlisted token should not be redacted: {out}"
    );
}

// obfsck-17: IPv6 addresses should be tagged internal for private ranges
#[test]
fn ipv6_ula_tagged_internal() {
    let input = "connected from fd12:3456:789a:0001:0000:0000:0000:0001";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        out.contains("[IP-INTERNAL-"),
        "ULA IPv6 (fc00::/7) should be tagged internal, got: {out}"
    );
    assert!(
        !out.contains("[IP-EXTERNAL-"),
        "ULA IPv6 should not be tagged external, got: {out}"
    );
    let tagged_internal = map.ips.values().any(|v| v.contains("IP-INTERNAL"));
    assert!(
        tagged_internal,
        "map should contain an IP-INTERNAL entry, got: {map:?}"
    );
}

#[test]
fn ipv6_link_local_tagged_internal() {
    let input = "host fe80:0000:0000:0000:0202:b3ff:fe1e:8329";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        out.contains("[IP-INTERNAL-"),
        "link-local IPv6 (fe80::/10) should be tagged internal, got: {out}"
    );
    let _ = map;
}

#[test]
fn ipv6_public_tagged_external() {
    let input = "server 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        out.contains("[IP-EXTERNAL-"),
        "public IPv6 should be tagged external, got: {out}"
    );
}

// obfsck-16: obfuscate_paths() must populate ObfuscationMap.paths
#[test]
fn obfuscate_paths_populates_map() {
    let input = "error reading /home/alice/projects/myapp/config.toml";
    let mut obfuscator = Obfuscator::new(ObfuscationLevel::Paranoid);
    let out = obfuscator.obfuscate(input);
    let map = obfuscator.get_mapping();

    assert!(
        !map.paths.is_empty(),
        "ObfuscationMap.paths should be populated after path redaction, got empty map.\nout={out}"
    );
    assert!(
        map.paths
            .contains_key("/home/alice/projects/myapp/config.toml"),
        "original path should be a key in map.paths, got: {map:?}"
    );
}

// obfsck-13: obfuscate_paths() unit tests

/// The map value for a redacted path must differ from the original path.
#[test]
fn obfuscate_paths_map_value_differs_from_key() {
    let input = "loading /home/alice/projects/myapp/config.toml";
    let mut obfuscator = Obfuscator::new(ObfuscationLevel::Paranoid);
    let _out = obfuscator.obfuscate(input);
    let map = obfuscator.get_mapping();

    let original = "/home/alice/projects/myapp/config.toml";
    let redacted = map.paths.get(original).expect("path must be in map");
    assert_ne!(
        redacted, original,
        "redacted value should differ from original path"
    );
}

/// Absolute paths (starting with '/') are detected and redacted.
#[test]
fn absolute_paths_are_redacted_at_paranoid() {
    let input = "opened /var/log/app/service.log";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(
        !map.paths.is_empty(),
        "absolute path should be recorded in map; out={out}"
    );
}

/// Paths are not redacted below paranoid level.
#[test]
fn paths_not_redacted_at_standard_level() {
    let input = "opened /home/alice/data/report.csv";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);

    // At standard, obfuscate_paths() is not called — map.paths stays empty
    assert!(
        map.paths.is_empty(),
        "paths should not be recorded below paranoid; out={out}"
    );
}

/// Paths are not redacted at minimal level.
#[test]
fn paths_not_redacted_at_minimal_level() {
    let input = "opened /home/alice/data/report.csv";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Minimal);

    assert_eq!(out, input, "minimal should not modify paths");
    assert!(map.paths.is_empty());
}

/// Sensitive path exemptions: /etc/passwd must not be redacted.
#[test]
fn sensitive_path_etc_passwd_preserved() {
    let input = "reading /etc/passwd for authentication";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(
        out.contains("/etc/passwd"),
        "sensitive path /etc/passwd must not be redacted: {out}"
    );
    assert!(
        !map.paths.contains_key("/etc/passwd"),
        "sensitive path must not appear in map.paths"
    );
}

/// Sensitive path exemptions: paths containing /.ssh/ must not be redacted.
#[test]
fn sensitive_path_ssh_preserved() {
    let input = "key at /home/alice/.ssh/id_rsa";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(
        out.contains("/.ssh/id_rsa"),
        "sensitive .ssh path must not be redacted: {out}"
    );
}

/// Sensitive path exemptions: .aws/credentials must not be redacted.
#[test]
fn sensitive_path_aws_credentials_preserved() {
    let input = "loaded credentials from /home/alice/.aws/credentials";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(
        out.contains("/.aws/credentials"),
        "sensitive .aws/credentials path must not be redacted: {out}"
    );
}

/// Path component obfuscation applies at paranoid even without user segments.
/// Note: obfuscate_paths() does not consult the runtime allowlist — only
/// is_sensitive_path() exemptions are honored. Allowlist entries skip
/// secret-pattern and structural-PII passes, not path rewriting.
#[test]
fn non_sensitive_absolute_path_is_rewritten_at_paranoid() {
    // /opt is a preserved segment; service is a non-preserved dir; config has > 3 chars
    let path = "/opt/service/config.toml";
    let input = format!("loading {path}");
    let (out, map) = obfuscate_text(input.as_str(), ObfuscationLevel::Paranoid);

    assert!(
        !map.paths.is_empty(),
        "non-sensitive path should be recorded in map.paths; out={out}"
    );
    assert!(
        !out.contains(path),
        "non-sensitive path should be rewritten at paranoid level; out={out}"
    );
    // File component (config > 3 chars) becomes [FILE].toml
    assert!(
        out.contains("[FILE].toml"),
        "file component should be [FILE].toml: {out}"
    );
}

/// UNC paths (Windows \\server\share\...) are detected and processed at paranoid level.
/// The \\server\share prefix is preserved (2 preserved_count segments); inner path
/// components are subject to redaction.
#[test]
fn unc_paths_are_detected_at_paranoid() {
    let input = r"config at \\fileserver\share\reports\q4.xlsx";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    // The original path should not appear verbatim — some transformation occurred
    assert!(
        !out.contains(r"\\fileserver\share\reports\q4.xlsx"),
        "UNC path should be transformed at paranoid level: {out}"
    );
}

/// Windows drive paths (C:\...) are obfuscated at paranoid level.
#[test]
fn windows_drive_paths_are_obfuscated() {
    let input = r"config at C:\Users\alice\AppData\Local\app\settings.json";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    assert!(
        !map.paths.is_empty(),
        "Windows drive path should be recorded in map; out={out}"
    );
    assert!(
        out.contains("[FILE].json"),
        "Windows path file component should be redacted: {out}"
    );
}

/// Repeated identical path tokens map to a single stable entry in map.paths.
#[test]
fn repeated_path_maps_to_single_entry() {
    let path = "/home/alice/projects/myapp/config.toml";
    let input = format!("reading {path} and also {path}");
    let mut obfuscator = Obfuscator::new(ObfuscationLevel::Paranoid);
    let _out = obfuscator.obfuscate(&input);
    let map = obfuscator.get_mapping();

    assert_eq!(
        map.paths.len(),
        1,
        "same path appearing twice should produce one map entry; map={map:?}"
    );
    assert!(
        map.paths.contains_key(path),
        "original path must be a key in map.paths"
    );
}

/// Home-user segment: with path-policy-home-user-redact the username after /home/ is
/// replaced with [USERDIR]; without it the username is preserved as a path component.
#[test]
fn home_user_segment_redaction_is_feature_gated() {
    let input = "reading /home/alice/docs/notes.txt";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    #[cfg(feature = "path-policy-home-user-redact")]
    assert!(
        out.contains("/home/[USERDIR]/"),
        "with path-policy-home-user-redact, username after /home/ must become [USERDIR]: {out}"
    );

    #[cfg(not(feature = "path-policy-home-user-redact"))]
    assert!(
        !out.contains("[USERDIR]"),
        "without path-policy-home-user-redact, [USERDIR] must not appear: {out}"
    );
}

/// Non-allowlisted-redact feature: all non-preserved segments become [DIR].
#[test]
fn non_allowlisted_segments_redacted_when_feature_enabled() {
    let input = "loading /opt/mycompany/service/config.toml";
    let (out, _map) = obfuscate_text(input, ObfuscationLevel::Paranoid);

    #[cfg(feature = "path-policy-non-allowlisted-redact")]
    assert!(
        out.contains("[DIR]"),
        "non-allowlisted segments should become [DIR]: {out}"
    );

    #[cfg(not(feature = "path-policy-non-allowlisted-redact"))]
    {
        // Without the feature, non-system segments in /opt/... are passed through
        // (opt is a preserved segment; mycompany and service are not redacted by default)
        let _ = out;
    }
}

// obfsck-21: RFC 1918 / loopback / link-local IPv4 classification tests
mod ipv4_classification {
    use obfsck::{ObfuscationLevel, obfuscate_text};

    fn assert_internal(ip: &str, label: &str) {
        let input = format!("host {ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        assert!(
            out.contains("[IP-INTERNAL-"),
            "{label}: {ip} should be tagged IP-INTERNAL, got: {out}"
        );
    }

    fn assert_external(ip: &str, label: &str) {
        let input = format!("host {ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        assert!(
            out.contains("[IP-EXTERNAL-"),
            "{label}: {ip} should be tagged IP-EXTERNAL, got: {out}"
        );
    }

    #[test]
    fn rfc1918_10_lower() {
        assert_internal("10.0.0.1", "10.0.0.0/8 lower");
    }

    #[test]
    fn rfc1918_10_upper() {
        assert_internal("10.255.255.255", "10.0.0.0/8 upper boundary");
    }

    #[test]
    fn rfc1918_172_16_lower() {
        assert_internal("172.16.0.1", "172.16.0.0/12 lower");
    }

    #[test]
    fn rfc1918_172_16_upper() {
        assert_internal("172.31.255.255", "172.16.0.0/12 upper boundary");
    }

    #[test]
    fn rfc1918_172_below_range() {
        assert_external("172.15.255.255", "below 172.16.0.0/12");
    }

    #[test]
    fn rfc1918_172_above_range() {
        assert_external("172.32.0.1", "above 172.16.0.0/12");
    }

    #[test]
    fn rfc1918_192_168_lower() {
        assert_internal("192.168.0.1", "192.168.0.0/16 lower");
    }

    #[test]
    fn rfc1918_192_168_upper() {
        assert_internal("192.168.255.255", "192.168.0.0/16 upper");
    }

    #[test]
    fn loopback_lower() {
        assert_internal("127.0.0.1", "loopback lower");
    }

    #[test]
    fn loopback_upper() {
        assert_internal("127.255.255.255", "loopback upper");
    }

    #[test]
    fn rfc3927_link_local() {
        assert_internal("169.254.1.1", "RFC 3927 link-local");
    }

    #[test]
    fn public_ip() {
        assert_external("8.8.8.8", "public IP");
    }
}
