use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use regex::Regex;
use std::collections::HashMap;

#[cfg(feature = "legacy-user-scan")]
fn legacy_user_obfuscation(text: &str) -> String {
    let patterns = [
        r"(?i)(user=)(\w+)",
        r"(?i)(uid=)(\d+)",
        r"(?i)(User )(\w+)",
        r"(?i)(by user )(\w+)",
    ];

    let mut counters: usize = 0;
    let mut users: HashMap<String, String> = HashMap::new();
    let mut current = text.to_string();

    for p in patterns {
        let re = Regex::new(p).expect("user regex");
        if !re.is_match(&current) {
            continue;
        }

        let replaced = re
            .replace_all(&current, |caps: &regex::Captures<'_>| {
                let prefix = caps.get(1).map_or("", |m| m.as_str());
                let user = caps.get(2).map_or("", |m| m.as_str());
                if is_system_user(user) {
                    caps[0].to_string()
                } else if let Some(existing) = users.get(user) {
                    format!("{prefix}{existing}")
                } else {
                    counters += 1;
                    let token = format!("[USER-{counters}]");
                    users.insert(user.to_string(), token.clone());
                    format!("{prefix}{token}")
                }
            })
            .into_owned();

        current = replaced;
    }

    current
}

fn single_regex_user_obfuscation(text: &str) -> String {
    let re = Regex::new(r"(?i)(user=|uid=|User |by user )(\w+)").expect("user regex");
    if !re.is_match(text) {
        return text.to_string();
    }

    let mut counters: usize = 0;
    let mut users: HashMap<String, String> = HashMap::new();

    re.replace_all(text, |caps: &regex::Captures<'_>| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let user = caps.get(2).map_or("", |m| m.as_str());
        if is_system_user(user) {
            caps[0].to_string()
        } else if let Some(existing) = users.get(user) {
            format!("{prefix}{existing}")
        } else {
            counters += 1;
            let token = format!("[USER-{counters}]");
            users.insert(user.to_string(), token.clone());
            format!("{prefix}{token}")
        }
    })
    .into_owned()
}

fn is_system_user(user: &str) -> bool {
    matches!(
        user.to_ascii_lowercase().as_str(),
        "root" | "nobody" | "daemon" | "www-data" | "nginx" | "postgres" | "mysql" | "redis"
    )
}

fn bench_user_obfuscation(c: &mut Criterion) {
    let input = "user=alice uid=1001 by user bob user=alice user=root User carol user=alice";
    let mut group = c.benchmark_group("user_obfuscation");
    #[cfg(feature = "legacy-user-scan")]
    group.bench_with_input(BenchmarkId::new("legacy", "short"), input, |b, i| {
        b.iter(|| black_box(legacy_user_obfuscation(black_box(i))));
    });
    group.bench_with_input(BenchmarkId::new("single_regex", "short"), input, |b, i| {
        b.iter(|| black_box(single_regex_user_obfuscation(black_box(i))));
    });
    group.finish();
}

criterion_group!(benches, bench_user_obfuscation);
criterion_main!(benches);
