use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use obfsck::{obfuscate_text, ObfuscationLevel};
use regex::Regex;
use std::collections::HashMap;

fn legacy_user_scan(text: &str) -> String {
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

fn is_system_user(user: &str) -> bool {
    matches!(
        user.to_ascii_lowercase().as_str(),
        "root" | "nobody" | "daemon" | "www-data" | "nginx" | "postgres" | "mysql" | "redis"
    )
}

fn bench_full_obfuscation(c: &mut Criterion) {
    let short = "user=alice from 10.0.0.7 email alice@example.com token=AKIA1234567890ABCDEF";
    let medium = [
        "user=alice from 10.0.0.7 email alice@example.com",
        "user=bob from 203.0.113.9 email bob@corp.example",
        "path=/home/alice/notes.txt host=api.example.com token=AKIA1234567890ABCDEF",
        "uid=1001 by user carol /etc/passwd /var/log/syslog",
    ]
    .join("\n");
    let large = medium.repeat(200);

    let mut group = c.benchmark_group("full_obfuscation");
    group.bench_with_input(BenchmarkId::new("standard", "short"), &short, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Standard)));
    });
    group.bench_with_input(BenchmarkId::new("paranoid", "short"), &short, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Paranoid)));
    });
    group.bench_with_input(BenchmarkId::new("standard", "medium"), &medium, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Standard)));
    });
    group.bench_with_input(BenchmarkId::new("paranoid", "medium"), &medium, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Paranoid)));
    });
    group.bench_with_input(BenchmarkId::new("standard", "large"), &large, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Standard)));
    });
    group.bench_with_input(BenchmarkId::new("paranoid", "large"), &large, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Paranoid)));
    });
    group.finish();

    let mut comparison = c.benchmark_group("full_obfuscation_compare");
    comparison.bench_with_input(BenchmarkId::new("current", "short"), &short, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Standard)));
    });
    comparison.bench_with_input(
        BenchmarkId::new("legacy_user_scan", "short"),
        &short,
        |b, i| {
            b.iter(|| {
                let scanned = legacy_user_scan(black_box(i));
                black_box(obfuscate_text(
                    black_box(&scanned),
                    ObfuscationLevel::Standard,
                ))
            });
        },
    );
    comparison.bench_with_input(BenchmarkId::new("current", "large"), &large, |b, i| {
        b.iter(|| black_box(obfuscate_text(black_box(i), ObfuscationLevel::Standard)));
    });
    comparison.bench_with_input(
        BenchmarkId::new("legacy_user_scan", "large"),
        &large,
        |b, i| {
            b.iter(|| {
                let scanned = legacy_user_scan(black_box(i));
                black_box(obfuscate_text(
                    black_box(&scanned),
                    ObfuscationLevel::Standard,
                ))
            });
        },
    );
    comparison.finish();
}

criterion_group!(benches, bench_full_obfuscation);
criterion_main!(benches);
