pub(super) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
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

        if should_preserve_path_segment(part) {
            out.push_str(part);
            continue;
        }

        if let Some((name, ext)) = part.rsplit_once('.') {
            if name.len() > 3 {
                out.push_str("[FILE].");
                out.push_str(ext);
            } else {
                out.push_str(part);
            }
            continue;
        }

        out.push_str(part);
    }

    out
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
