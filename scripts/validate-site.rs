#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! serde_json = "1"
//! ```
//!
//! Validate the static site under `site/`.
//!
//! Checks that every HTML page has balanced structural tags, that each JSON
//! asset parses, and that every internal `href`/`src` resolves to a file that
//! exists. Broken links are invisible until someone clicks them on the
//! deployed Pages site, so catch them here instead.
//!
//! Usage:
//!   rust-script scripts/validate-site.rs

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Tags whose balance is worth checking. Void tags are absent by construction,
/// and inline and metadata tags are skipped to keep the signal high:
/// unbalanced `<li>` or `<div>` is a real layout bug, a stray `<br>` is not.
const TRACKED_TAGS: &[&str] = &[
    "html", "head", "body", "nav", "main", "section", "header", "footer", "div", "span", "a", "p",
    "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "h1", "h2", "h3", "h4", "pre",
    "code", "figure",
];

/// Repository root. `CARGO_MANIFEST_DIR` is useless here: under `rust-script`
/// it points at the shared cache, not at this project.
fn repo_root() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("OBFSCK_REPO_ROOT") {
        return Ok(PathBuf::from(explicit));
    }
    std::env::current_dir().context("cannot determine the current directory")
}

/// True if `s` starts with `tag` followed by a proper delimiter.
///
/// This matters: a plain substring count of `<p` also matches `<pre>`, `<li`
/// matches `<link>`, and `<th` matches `<thead>`, which reports perfectly
/// valid pages as unbalanced.
fn tag_at(s: &str, tag: &str) -> bool {
    match s.strip_prefix(tag) {
        Some(after) => after
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c.is_whitespace() || c == '/'),
        None => false,
    }
}

/// Count opening and closing `tag` occurrences in `html`.
fn count_tags(html: &str, tag: &str) -> (usize, usize) {
    let mut open = 0usize;
    let mut close = 0usize;
    for (idx, _) in html.match_indices('<') {
        let rest = &html[idx + 1..];
        if let Some(after) = rest.strip_prefix('/') {
            if tag_at(after, tag) {
                close += 1;
            }
        } else if tag_at(rest, tag) {
            open += 1;
        }
    }
    (open, close)
}

fn check_balance(path: &Path, html: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for tag in TRACKED_TAGS {
        let (open, close) = count_tags(html, tag);
        if open != close {
            problems.push(format!(
                "{}: <{tag}> opened {open}x but closed {close}x",
                path.display()
            ));
        }
    }
    problems
}

/// Pull `href="..."` and `src="..."` targets out of an HTML page.
fn extract_refs(html: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for attr in ["href", "src"] {
        let needle = format!("{attr}=\"");
        let mut rest = html;
        while let Some(start) = rest.find(&needle) {
            rest = &rest[start + needle.len()..];
            let Some(end) = rest.find('"') else { break };
            refs.push(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    refs
}

fn check_links(site: &Path, path: &Path, html: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = HashSet::new();
    for raw in extract_refs(html) {
        // External links, in-page anchors, and non-file schemes are out of scope.
        if raw.starts_with("http")
            || raw.starts_with('#')
            || raw.starts_with("mailto:")
            || raw.starts_with("data:")
            || raw.is_empty()
        {
            continue;
        }
        let target = raw.split(['#', '?']).next().unwrap_or("");
        if target.is_empty() || !seen.insert(target.to_string()) {
            continue;
        }
        if !site.join(target).exists() {
            problems.push(format!(
                "{}: link to missing file '{target}'",
                path.display()
            ));
        }
    }
    problems
}

/// Recursively collect files under `dir` whose extension is in `wanted`.
fn collect(dir: &Path, wanted: &[&str], out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading an entry in {}", dir.display()))?
            .path();
        if path.is_dir() {
            collect(&path, wanted, out)?;
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if wanted.contains(&ext) {
            out.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let root = repo_root()?;
    let site = root.join("site");
    anyhow::ensure!(
        site.is_dir(),
        "no site/ directory at {}",
        root.display()
    );

    let mut problems: Vec<String> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect(&site, &["html", "json"], &mut files)?;
    files.sort();

    for path in &files {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "html" => {
                let html = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                problems.extend(check_balance(path, &html));
                problems.extend(check_links(&site, path, &html));
            }
            "json" => {
                let text = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                if let Err(e) = serde_json::from_str::<serde_json::Value>(&text) {
                    problems.push(format!("{}: invalid JSON: {e}", path.display()));
                }
            }
            _ => {}
        }
    }

    for problem in &problems {
        println!("FAIL {problem}");
    }
    println!(
        "\nvalidate-site: checked {} file(s), {} problem(s)",
        files.len(),
        problems.len()
    );

    if !problems.is_empty() {
        bail!("site validation failed");
    }
    Ok(())
}