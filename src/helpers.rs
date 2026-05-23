const BYTE_RANGE: usize = 256;

pub(super) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; BYTE_RANGE];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / len;
        ent -= p * p.log2();
    }
    ent
}

pub(super) fn is_sensitive_path(path: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/",
        "/.ssh/",
        "/id_rsa",
        "/id_ed25519",
        "/.aws/credentials",
        "/.kube/config",
        "/secrets/",
        "/vault/",
        "/.env",
        "/windows/system32/config/sam",
        "/windows/system32/config/system",
        "/windows/system32/config/security",
        "/windows/system32/config/",
    ];
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    SENSITIVE.iter().any(|s| normalized.contains(s))
}

pub(super) fn obfuscate_path_value(path: &str) -> String {
    let (separator, prefix, preserve_count, parts) =
        if let Some(trimmed) = path.strip_prefix("\\\\") {
            let parts: Vec<&str> = trimmed.split('\\').filter(|p| !p.is_empty()).collect();
            ('\\', String::from("\\\\"), 2, parts)
        } else if path.len() >= 2 && path.as_bytes()[1] == b':' {
            let drive = &path[..2];
            let rest = &path[2..];
            let separator = if rest.contains('\\') { '\\' } else { '/' };
            let mut prefix = drive.to_string();
            if rest.starts_with('\\') || rest.starts_with('/') {
                prefix.push(separator);
            }
            let parts: Vec<&str> = rest.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
            (separator, prefix, 0, parts)
        } else if path.contains('\\') {
            let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
            ('\\', String::new(), 0, parts)
        } else {
            let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
            let prefix = if path.starts_with('/') {
                String::from("/")
            } else {
                String::new()
            };
            ('/', prefix, 0, parts)
        };

    let mut out = String::with_capacity(path.len());
    out.push_str(&prefix);

    for (idx, part) in parts.iter().enumerate() {
        if !out.is_empty() && !out.ends_with(separator) && !out.ends_with('/') {
            out.push(separator);
        }

        if idx < preserve_count {
            out.push_str(part);
            continue;
        }

        if should_redact_home_user_segment(&parts, idx) {
            out.push_str("[USERDIR]");
            continue;
        }

        if should_preserve_path_segment(part) {
            out.push_str(part);
            continue;
        }

        const MIN_FILENAME_REDACT_LEN: usize = 3;
        if let Some((name, ext)) = part.rsplit_once('.') {
            if name.len() > MIN_FILENAME_REDACT_LEN {
                out.push_str("[FILE].");
                out.push_str(ext);
            } else {
                out.push_str(part);
            }
            continue;
        }

        if should_redact_non_allowlisted_segment(part) {
            out.push_str("[DIR]");
            continue;
        }

        out.push_str(part);
    }

    out
}

#[cfg(feature = "path-policy-home-user-redact")]
fn should_redact_home_user_segment(parts: &[&str], idx: usize) -> bool {
    if idx == 0 {
        return false;
    }

    matches!(
        parts[idx - 1].to_ascii_lowercase().as_str(),
        "home" | "users"
    )
}

#[cfg(not(feature = "path-policy-home-user-redact"))]
fn should_redact_home_user_segment(_parts: &[&str], _idx: usize) -> bool {
    false
}

#[cfg(feature = "path-policy-non-allowlisted-redact")]
fn should_redact_non_allowlisted_segment(_part: &str) -> bool {
    true
}

#[cfg(not(feature = "path-policy-non-allowlisted-redact"))]
fn should_redact_non_allowlisted_segment(_part: &str) -> bool {
    false
}

fn should_preserve_path_segment(part: &str) -> bool {
    matches!(
        part.to_ascii_lowercase().as_str(),
        "home"
            | "var"
            | "tmp"
            | "etc"
            | "usr"
            | "opt"
            | "root"
            | "proc"
            | "sys"
            | "dev"
            | "users"
            | "windows"
            | "programdata"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- shannon_entropy ---

    #[test]
    fn entropy_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char_repeated_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_two_equal_chars_is_one() {
        let e = shannon_entropy("ab");
        assert!((e - 1.0).abs() < 1e-10, "expected 1.0, got {e}");
    }

    #[test]
    fn entropy_high_for_random_looking_string() {
        let e = shannon_entropy("aB3$xZ9!kL2@mN5#");
        assert!(e > 3.5, "expected high entropy, got {e}");
    }

    #[test]
    fn entropy_bounded_by_eight() {
        // Maximum possible Shannon entropy for byte data is 8.0 bits
        let e = shannon_entropy("the quick brown fox jumps over the lazy dog 0123456789");
        assert!(e <= 8.0, "entropy should be <= 8.0, got {e}");
        assert!(e > 0.0);
    }

    // --- is_sensitive_path ---

    #[test]
    fn sensitive_path_etc_shadow() {
        assert!(is_sensitive_path("/etc/shadow"));
    }

    #[test]
    fn sensitive_path_ssh_dir() {
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn sensitive_path_aws_credentials() {
        assert!(is_sensitive_path("/home/user/.aws/credentials"));
    }

    #[test]
    fn sensitive_path_windows_sam() {
        assert!(is_sensitive_path("C:\\Windows\\System32\\config\\SAM"));
    }

    #[test]
    fn non_sensitive_path_var_log() {
        assert!(!is_sensitive_path("/var/log/syslog"));
    }

    #[test]
    fn non_sensitive_path_tmp() {
        assert!(!is_sensitive_path("/tmp/scratch.txt"));
    }

    // --- should_preserve_path_segment ---

    #[test]
    fn preserves_standard_dirs() {
        for dir in &[
            "home", "var", "tmp", "etc", "usr", "opt", "proc", "sys", "dev",
        ] {
            assert!(
                should_preserve_path_segment(dir),
                "{dir} should be preserved"
            );
        }
    }

    #[test]
    fn preserves_case_insensitive() {
        assert!(should_preserve_path_segment("Home"));
        assert!(should_preserve_path_segment("VAR"));
        assert!(should_preserve_path_segment("Windows"));
    }

    #[test]
    fn does_not_preserve_custom_dirs() {
        assert!(!should_preserve_path_segment("myapp"));
        assert!(!should_preserve_path_segment("data"));
        assert!(!should_preserve_path_segment("secrets"));
    }

    // --- obfuscate_path_value ---

    #[test]
    fn unix_path_preserves_standard_segments() {
        let result = obfuscate_path_value("/var/log/myapp/debug.log");
        assert!(result.starts_with("/var"));
        assert!(result.contains("var"));
    }

    #[test]
    fn windows_drive_path_preserves_drive_letter() {
        let result = obfuscate_path_value("C:\\Users\\alice\\Documents\\report.docx");
        assert!(result.starts_with("C:\\"));
    }

    #[test]
    fn unc_path_preserves_first_two_segments() {
        let result = obfuscate_path_value("\\\\server\\share\\folder\\file.txt");
        assert!(result.starts_with("\\\\server\\share"));
    }

    #[test]
    fn short_filename_not_redacted() {
        let result = obfuscate_path_value("/tmp/ab.c");
        assert!(
            result.contains("ab.c"),
            "short filename should be preserved, got: {result}"
        );
    }

    #[test]
    fn long_filename_redacted() {
        let result = obfuscate_path_value("/tmp/longfilename.log");
        assert!(
            result.contains("[FILE].log"),
            "long filename should be redacted, got: {result}"
        );
    }
}
