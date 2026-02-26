//! Obfuscator

pub mod alert_analyzer;
pub mod analysis_api;
pub mod log_agents;

use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationLevel {
    Minimal,
    Standard,
    Paranoid,
}

impl ObfuscationLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "standard" => Some(Self::Standard),
            "paranoid" => Some(Self::Paranoid),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ObfuscationMap {
    pub ips: HashMap<String, String>,
    pub hostnames: HashMap<String, String>,
    pub users: HashMap<String, String>,
    pub containers: HashMap<String, String>,
    pub paths: HashMap<String, String>,
    pub emails: HashMap<String, String>,
    secrets: HashSet<String>,
}

impl ObfuscationMap {
    pub fn export(&self) -> ObfuscationMapExport {
        ObfuscationMapExport {
            ips: self.ips.clone(),
            hostnames: self.hostnames.clone(),
            users: self.users.clone(),
            containers: self.containers.clone(),
            paths: self.paths.clone(),
            emails: self.emails.clone(),
            secrets_count: self.secrets.len(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ObfuscationMapExport {
    pub ips: HashMap<String, String>,
    pub hostnames: HashMap<String, String>,
    pub users: HashMap<String, String>,
    pub containers: HashMap<String, String>,
    pub paths: HashMap<String, String>,
    pub emails: HashMap<String, String>,
    pub secrets_count: usize,
}

#[derive(Debug, Default, Clone)]
struct Counters {
    ip_internal: usize,
    ip_external: usize,
    host: usize,
    user: usize,
    container: usize,
    email: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenCategory {
    IpInternal,
    IpExternal,
    Host,
    User,
    Container,
    Email,
}

impl TokenCategory {
    fn label(self) -> &'static str {
        match self {
            Self::IpInternal => "IP-INTERNAL",
            Self::IpExternal => "IP-EXTERNAL",
            Self::Host => "HOST",
            Self::User => "USER",
            Self::Container => "CONTAINER",
            Self::Email => "EMAIL",
        }
    }
}

impl Counters {
    fn next(&mut self, cat: TokenCategory) -> usize {
        let c = match cat {
            TokenCategory::IpInternal => &mut self.ip_internal,
            TokenCategory::IpExternal => &mut self.ip_external,
            TokenCategory::Host => &mut self.host,
            TokenCategory::User => &mut self.user,
            TokenCategory::Container => &mut self.container,
            TokenCategory::Email => &mut self.email,
        };
        *c += 1;
        *c
    }
}

pub struct Obfuscator {
    level: ObfuscationLevel,
    map: ObfuscationMap,
    counters: Counters,
}

impl Obfuscator {
    pub fn new(level: ObfuscationLevel) -> Self {
        Self {
            level,
            map: ObfuscationMap::default(),
            counters: Counters::default(),
        }
    }

    pub fn level(&self) -> ObfuscationLevel {
        self.level
    }

    pub fn get_mapping(&self) -> ObfuscationMapExport {
        self.map.export()
    }

    pub fn obfuscate(&mut self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }

        let mut s: Cow<'_, str> = Cow::Borrowed(text);

        s = Cow::Owned(self.obfuscate_secrets(s.as_ref()));
        if self.level == ObfuscationLevel::Minimal {
            return s.into_owned();
        }

        s = Cow::Owned(self.obfuscate_ips(s.as_ref()));
        s = Cow::Owned(self.obfuscate_emails(s.as_ref()));
        s = Cow::Owned(self.obfuscate_containers(s.as_ref()));
        s = Cow::Owned(self.obfuscate_users(s.as_ref()));

        if self.level == ObfuscationLevel::Paranoid {
            s = Cow::Owned(self.obfuscate_paths(s.as_ref()));
            s = Cow::Owned(self.obfuscate_hostnames(s.as_ref()));
            s = Cow::Owned(self.obfuscate_high_entropy(s.as_ref()));
        }

        s.into_owned()
    }

    fn is_private_ipv4(ip: &str) -> bool {
        let mut parts = ip.split('.');
        let a = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
            Some(v) => v,
            None => return false,
        };
        let b = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
            Some(v) => v,
            None => return false,
        };
        let c = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
            Some(v) => v,
            None => return false,
        };
        let d = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
            Some(v) => v,
            None => return false,
        };
        if parts.next().is_some() {
            return false;
        }

        let ip_int = (a << 24) + (b << 16) + (c << 8) + d;
        const PRIVATE_RANGES: &[(u32, u32)] = &[
            (0x0A000000, 0x0AFFFFFF),
            (0xAC100000, 0xAC1FFFFF),
            (0xC0A80000, 0xC0A8FFFF),
            (0x7F000000, 0x7FFFFFFF),
        ];

        PRIVATE_RANGES
            .iter()
            .any(|(start, end)| *start <= ip_int && ip_int <= *end)
    }

    fn obfuscate_ips(&mut self, text: &str) -> String {
        let mut s: Cow<'_, str> = Cow::Borrowed(text);
        if ipv4_re().is_match(s.as_ref()) {
            let counters = &mut self.counters;
            let ips = &mut self.map.ips;
            let replaced = ipv4_re()
                .replace_all(s.as_ref(), |caps: &regex::Captures<'_>| {
                    let ip = &caps[0];
                    let cat = if Self::is_private_ipv4(ip) {
                        TokenCategory::IpInternal
                    } else {
                        TokenCategory::IpExternal
                    };
                    get_or_create_token(counters, cat, ip, ips)
                })
                .into_owned();
            s = Cow::Owned(replaced);
        }

        if ipv6_re().is_match(s.as_ref()) {
            let counters = &mut self.counters;
            let ips = &mut self.map.ips;
            let replaced = ipv6_re()
                .replace_all(s.as_ref(), |caps: &regex::Captures<'_>| {
                    let ip = &caps[0];
                    get_or_create_token(counters, TokenCategory::IpExternal, ip, ips)
                })
                .into_owned();
            s = Cow::Owned(replaced);
        }

        s.into_owned()
    }

    fn obfuscate_emails(&mut self, text: &str) -> String {
        if !email_re().is_match(text) {
            return text.to_string();
        }

        let counters = &mut self.counters;
        let emails = &mut self.map.emails;

        email_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let email = &caps[0];
                get_or_create_token(counters, TokenCategory::Email, email, emails)
            })
            .into_owned()
    }

    fn obfuscate_containers(&mut self, text: &str) -> String {
        if !container_id_re().is_match(text) {
            return text.to_string();
        }

        let counters = &mut self.counters;
        let containers = &mut self.map.containers;

        container_id_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let cid = &caps[0];
                get_or_create_token(counters, TokenCategory::Container, cid, containers)
            })
            .into_owned()
    }

    fn is_system_user(user: &str) -> bool {
        matches!(
            user.to_ascii_lowercase().as_str(),
            "root" | "nobody" | "daemon" | "www-data" | "nginx" | "postgres" | "mysql" | "redis"
        )
    }

    #[cfg(feature = "legacy-user-scan")]
    fn obfuscate_users(&mut self, text: &str) -> String {
        let mut s: Cow<'_, str> = Cow::Borrowed(text);

        for re in user_res() {
            if !re.is_match(s.as_ref()) {
                continue;
            }

            let counters = &mut self.counters;
            let users = &mut self.map.users;
            let replaced = re
                .replace_all(s.as_ref(), |caps: &regex::Captures<'_>| {
                    let prefix = caps.get(1).map_or("", |m| m.as_str());
                    let user = caps.get(2).map_or("", |m| m.as_str());
                    if Self::is_system_user(user) {
                        caps[0].to_string()
                    } else {
                        let token = get_or_create_token(counters, TokenCategory::User, user, users);
                        format!("{prefix}{token}")
                    }
                })
                .into_owned();
            s = Cow::Owned(replaced);
        }

        s.into_owned()
    }

    #[cfg(not(feature = "legacy-user-scan"))]
    fn obfuscate_users(&mut self, text: &str) -> String {
        if !user_re().is_match(text) {
            return text.to_string();
        }

        let counters = &mut self.counters;
        let users = &mut self.map.users;
        user_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let prefix = caps.get(1).map_or("", |m| m.as_str());
                let user = caps.get(2).map_or("", |m| m.as_str());
                if Self::is_system_user(user) {
                    caps[0].to_string()
                } else {
                    let token = get_or_create_token(counters, TokenCategory::User, user, users);
                    format!("{prefix}{token}")
                }
            })
            .into_owned()
    }

    fn obfuscate_paths(&mut self, text: &str) -> String {
        if !path_re().is_match(text) {
            return text.to_string();
        }

        path_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let path = &caps[0];
                if is_sensitive_path(path) {
                    return path.to_string();
                }

                obfuscate_path_value(path)
            })
            .into_owned()
    }

    fn obfuscate_hostnames(&mut self, text: &str) -> String {
        if !hostname_re().is_match(text) {
            return text.to_string();
        }

        let counters = &mut self.counters;
        let hostnames = &mut self.map.hostnames;

        hostname_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let hostname = &caps[0];
                match hostname.to_ascii_lowercase().as_str() {
                    "localhost" | "localhost.localdomain" => hostname.to_string(),
                    _ => get_or_create_token(counters, TokenCategory::Host, hostname, hostnames),
                }
            })
            .into_owned()
    }

    fn obfuscate_high_entropy(&mut self, text: &str) -> String {
        if !high_entropy_candidate_re().is_match(text) {
            return text.to_string();
        }

        high_entropy_candidate_re()
            .replace_all(text, |caps: &regex::Captures<'_>| {
                let s = &caps[0];
                if s.len() >= 20 && shannon_entropy(s) > 4.5 {
                    let mut truncated = s.chars().take(10).collect::<String>();
                    truncated.push_str("...");
                    self.map.secrets.insert(truncated);
                    "[REDACTED-HIGH-ENTROPY]".to_string()
                } else {
                    s.to_string()
                }
            })
            .into_owned()
    }

    fn obfuscate_secrets(&mut self, text: &str) -> String {
        let mut s: Cow<'_, str> = Cow::Borrowed(text);
        for pat in secret_patterns() {
            if pat.paranoid_only && self.level != ObfuscationLevel::Paranoid {
                continue;
            }
            if !pat.re.is_match(s.as_ref()) {
                continue;
            }
            let label = pat.label;
            let replaced = pat
                .re
                .replace_all(s.as_ref(), |caps: &regex::Captures<'_>| {
                    let m = &caps[0];
                    let mut truncated = m.chars().take(20).collect::<String>();
                    truncated.push_str("...");
                    self.map.secrets.insert(truncated);
                    format!("[REDACTED-{label}]")
                })
                .into_owned();
            s = Cow::Owned(replaced);
        }
        s.into_owned()
    }
}

fn get_or_create_token(
    counters: &mut Counters,
    category: TokenCategory,
    original: &str,
    mapping: &mut HashMap<String, String>,
) -> String {
    if let Some(existing) = mapping.get(original) {
        return existing.clone();
    }

    let n = counters.next(category);
    let token = format!("[{}-{}]", category.label(), n);
    mapping.insert(original.to_string(), token.clone());
    token
}

pub fn obfuscate_text(text: &str, level: ObfuscationLevel) -> (String, ObfuscationMapExport) {
    let mut obfuscator = Obfuscator::new(level);
    let out = obfuscator.obfuscate(text);
    (out, obfuscator.get_mapping())
}

pub fn obfuscate_alert(
    output: Option<&str>,
    output_fields: Option<&HashMap<String, String>>,
    level: ObfuscationLevel,
) -> (
    Option<String>,
    Option<HashMap<String, String>>,
    ObfuscationMapExport,
) {
    let mut obfuscator = Obfuscator::new(level);

    let out = output.map(|s| obfuscator.obfuscate(s));
    let fields = output_fields.map(|m| {
        m.iter()
            .map(|(k, v)| (k.clone(), obfuscator.obfuscate(v)))
            .collect::<HashMap<_, _>>()
    });

    (out, fields, obfuscator.get_mapping())
}

fn shannon_entropy(s: &str) -> f64 {
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

fn is_sensitive_path(path: &str) -> bool {
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

fn obfuscate_path_value(path: &str) -> String {
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

struct SecretPattern {
    label: &'static str,
    paranoid_only: bool,
    re: Regex,
}

struct SecretPatternDef {
    name: &'static str,
    pattern: &'static str,
    label: &'static str,
    paranoid_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPatternError {
    pub name: &'static str,
    pub error: String,
}

mod secret_patterns;
use secret_patterns::SECRET_PATTERN_DEFS;

fn secret_patterns() -> &'static [SecretPattern] {
    static PATS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATS.get_or_init(|| {
        let mut errors = Vec::new();
        let patterns = SECRET_PATTERN_DEFS
            .iter()
            .filter_map(|d| {
                let re = match RegexBuilder::new(d.pattern).case_insensitive(true).build() {
                    Ok(re) => re,
                    Err(err) => {
                        errors.push(SecretPatternError {
                            name: d.name,
                            error: err.to_string(),
                        });
                        return None;
                    }
                };

                Some(SecretPattern {
                    label: d.label,
                    paranoid_only: d.paranoid_only,
                    re,
                })
            })
            .collect();

        let _ = SECRET_PATTERN_ERRORS.set(errors);
        patterns
    })
}

static SECRET_PATTERN_ERRORS: OnceLock<Vec<SecretPatternError>> = OnceLock::new();

pub fn secret_pattern_errors() -> &'static [SecretPatternError] {
    if SECRET_PATTERN_ERRORS.get().is_none() {
        let _ = secret_patterns();
    }

    SECRET_PATTERN_ERRORS.get_or_init(Vec::new)
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
            .expect("ipv4 regex")
    })
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").expect("ipv6 regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("email regex")
    })
}

fn container_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[a-f0-9]{12,64}\b").expect("container id regex"))
}

#[cfg(feature = "legacy-user-scan")]
fn user_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        [
            r"(?i)(user=)(\w+)",
            r"(?i)(uid=)(\d+)",
            r"(?i)(User )(\w+)",
            r"(?i)(by user )(\w+)",
        ]
        .into_iter()
        .map(|p| Regex::new(p).expect("user regex"))
        .collect()
    })
}

#[cfg(not(feature = "legacy-user-scan"))]
fn user_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(user=|uid=|User |by user )(\w+)").expect("user regex"))
}

fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:[a-z]:\\[^\s]+|[a-z]:/[^\s]+|\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\\\s]+)*|/[\w./-]+)"#,
        )
        .expect("path regex")
    })
}

fn hostname_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b")
            .expect("hostname regex")
    })
}

fn high_entropy_candidate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/=_-]{20,}\b").expect("entropy candidate regex"))
}
