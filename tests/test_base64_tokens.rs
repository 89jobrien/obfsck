//! Regression tests for base64 characters in vault token patterns (#20).
//!
//! `\w` does NOT match base64 `+` or `/`. Vault patterns must use
//! `[A-Za-z0-9+/_-]` to cover real-world base64-encoded payloads.

use obfsck::{ObfuscationLevel, obfuscate_text};

/// Helper: generate a repeating payload of the given length using the specified alphabet.
fn make_payload(chars: &[u8], len: usize) -> String {
    chars.iter().cycle().take(len).map(|&b| b as char).collect()
}

/// Build a payload with a special char at position 50, rest alphanumeric.
/// This ensures the special char is in the MIDDLE so the regex cannot simply
/// match a prefix before the special char.
fn payload_with_char_at_middle(special: char, total_len: usize) -> String {
    let alnum = b"abcABC0123456789";
    let prefix = make_payload(alnum, 50);
    let suffix = make_payload(alnum, total_len - 51);
    format!("{prefix}{special}{suffix}")
}

// ---------------------------------------------------------------------------
// hvs. (vault service token) -- 90-120 char payload
// ---------------------------------------------------------------------------

#[test]
fn vault_service_token_alphanumeric_only() {
    let payload = make_payload(b"abcdefABCDEF0123456789", 100);
    let token = format!("hvs.{payload}");
    let input = format!("secret: {token}");
    let (out, map) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-SERVICE]"),
        "baseline alphanumeric hvs token not redacted: {out}"
    );
    assert!(map.secrets_count >= 1);
}

#[test]
fn vault_service_token_with_underscore_and_dash() {
    let payload = make_payload(b"abcABC012_-", 100);
    let token = format!("hvs.{payload}");
    let input = format!("secret: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-SERVICE]"),
        "hvs token with _ and - not redacted: {out}"
    );
}

#[test]
fn vault_service_token_with_plus_in_middle() {
    // `+` at position 50 of a 100-char payload -- regex must match through it
    let payload = payload_with_char_at_middle('+', 100);
    let token = format!("hvs.{payload}");
    let input = format!("secret: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-SERVICE]"),
        "hvs token with + in middle not redacted: {out}"
    );
    // The suffix after `+` must not leak into output
    let suffix = &payload[51..61];
    assert!(
        !out.contains(suffix),
        "suffix after + leaked into output: {out}"
    );
}

#[test]
fn vault_service_token_with_slash_in_middle() {
    // `/` at position 50 of a 100-char payload
    let payload = payload_with_char_at_middle('/', 100);
    let token = format!("hvs.{payload}");
    let input = format!("secret: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-SERVICE]"),
        "hvs token with / in middle not redacted: {out}"
    );
    let suffix = &payload[51..61];
    assert!(
        !out.contains(suffix),
        "suffix after / leaked into output: {out}"
    );
}

// ---------------------------------------------------------------------------
// hvb. (vault batch token) -- 138-300 char payload
// ---------------------------------------------------------------------------

#[test]
fn vault_batch_token_alphanumeric_only() {
    let payload = make_payload(b"abcdefABCDEF0123456789", 150);
    let token = format!("hvb.{payload}");
    let input = format!("batch: {token}");
    let (out, map) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-BATCH]"),
        "baseline alphanumeric hvb token not redacted: {out}"
    );
    assert!(map.secrets_count >= 1);
}

#[test]
fn vault_batch_token_with_underscore_and_dash() {
    let payload = make_payload(b"abcABC012_-", 150);
    let token = format!("hvb.{payload}");
    let input = format!("batch: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-BATCH]"),
        "hvb token with _ and - not redacted: {out}"
    );
}

#[test]
fn vault_batch_token_with_plus_in_middle() {
    let payload = payload_with_char_at_middle('+', 150);
    let token = format!("hvb.{payload}");
    let input = format!("batch: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-BATCH]"),
        "hvb token with + in middle not redacted: {out}"
    );
    let suffix = &payload[51..61];
    assert!(
        !out.contains(suffix),
        "suffix after + leaked into output: {out}"
    );
}

#[test]
fn vault_batch_token_with_slash_in_middle() {
    let payload = payload_with_char_at_middle('/', 150);
    let token = format!("hvb.{payload}");
    let input = format!("batch: {token}");
    let (out, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);
    assert!(
        out.contains("[REDACTED-VAULT-BATCH]"),
        "hvb token with / in middle not redacted: {out}"
    );
    let suffix = &payload[51..61];
    assert!(
        !out.contains(suffix),
        "suffix after / leaked into output: {out}"
    );
}
