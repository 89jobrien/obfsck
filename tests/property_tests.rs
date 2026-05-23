//! Property tests for obfsck core functions.
//!
//! These test invariants that must hold for ALL valid inputs, not just
//! hand-picked examples. Uses proptest to generate arbitrary inputs.

use obfsck::{ObfuscationLevel, Obfuscator, obfuscate_text};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// shannon_entropy invariants (tested via obfuscation behaviour)
// ---------------------------------------------------------------------------

proptest! {
    /// Obfuscating any valid UTF-8 string must not panic.
    #[test]
    fn obfuscate_never_panics(input in "\\PC{0,500}") {
        let mut obfuscator = Obfuscator::new(ObfuscationLevel::Paranoid);
        let _ = obfuscator.obfuscate(&input);
    }

    /// Obfuscating an already-obfuscated string is idempotent for redaction
    /// tokens: [REDACTED-*] placeholders must survive a second pass unchanged.
    #[test]
    fn obfuscate_is_idempotent_for_redaction_tokens(input in "\\PC{0,200}") {
        let (first_pass, _) = obfuscate_text(&input, ObfuscationLevel::Minimal);

        // At minimal level, only secrets are redacted. A second pass on the
        // output should not find new secrets in the [REDACTED-*] tokens.
        let (second_pass, _) = obfuscate_text(&first_pass, ObfuscationLevel::Minimal);
        prop_assert_eq!(&first_pass, &second_pass,
            "second obfuscation pass changed the output");
    }

    /// Empty input always produces empty output.
    #[test]
    fn empty_input_produces_empty_output(level in prop_oneof![
        Just(ObfuscationLevel::Minimal),
        Just(ObfuscationLevel::Standard),
        Just(ObfuscationLevel::Paranoid),
    ]) {
        let (out, map) = obfuscate_text("", level);
        prop_assert_eq!(out, "");
        prop_assert!(map.ips.is_empty());
        prop_assert!(map.users.is_empty());
    }
}

// ---------------------------------------------------------------------------
// IP classification invariants
// ---------------------------------------------------------------------------

proptest! {
    /// All RFC 1918 10.x.x.x addresses are classified as internal.
    #[test]
    fn rfc1918_10_always_internal(
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let ip = format!("10.{b}.{c}.{d}");
        let input = format!("src={ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        prop_assert!(out.contains("IP-INTERNAL"),
            "10.x.x.x should be internal, got: {out}");
    }

    /// All RFC 1918 192.168.x.x addresses are classified as internal.
    #[test]
    fn rfc1918_192_168_always_internal(
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let ip = format!("192.168.{c}.{d}");
        let input = format!("src={ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        prop_assert!(out.contains("IP-INTERNAL"),
            "192.168.x.x should be internal, got: {out}");
    }

    /// All loopback addresses (127.x.x.x) are classified as internal.
    #[test]
    fn loopback_always_internal(
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let ip = format!("127.{b}.{c}.{d}");
        let input = format!("src={ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        prop_assert!(out.contains("IP-INTERNAL"),
            "127.x.x.x should be internal, got: {out}");
    }

    /// Addresses outside private ranges are classified as external.
    /// We pick from ranges guaranteed to be public: 1.0.0.0 - 9.255.255.255.
    #[test]
    fn public_range_always_external(
        a in 1u8..=9,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 1u8..=254,
    ) {
        let ip = format!("{a}.{b}.{c}.{d}");
        let input = format!("src={ip}");
        let (out, _) = obfuscate_text(&input, ObfuscationLevel::Standard);
        prop_assert!(out.contains("IP-EXTERNAL"),
            "{ip} should be external, got: {out}");
    }
}

// ---------------------------------------------------------------------------
// ObfuscationLevel::parse invariants
// ---------------------------------------------------------------------------

proptest! {
    /// parse(level.to_string()) round-trips for known levels.
    #[test]
    fn level_parse_roundtrips(level in prop_oneof![
        Just("minimal"),
        Just("standard"),
        Just("paranoid"),
    ]) {
        let parsed = ObfuscationLevel::parse(level);
        prop_assert!(parsed.is_some(), "failed to parse '{level}'");
    }

    /// parse returns None for arbitrary non-level strings.
    #[test]
    fn level_parse_rejects_arbitrary(input in "[a-z]{6,20}") {
        if !["minimal", "standard", "paranoid"].contains(&input.as_str()) {
            prop_assert!(ObfuscationLevel::parse(&input).is_none(),
                "should reject '{input}'");
        }
    }
}

// ---------------------------------------------------------------------------
// Allowlist invariant
// ---------------------------------------------------------------------------

proptest! {
    /// Any value in the allowlist passes through obfuscation unchanged.
    #[test]
    fn allowlisted_values_pass_through(
        // Generate a plausible IP that would normally be redacted
        b in 0u8..=255,
        c in 0u8..=255,
        d in 1u8..=254,
    ) {
        let ip = format!("10.{b}.{c}.{d}");
        let mut obfuscator = Obfuscator::new(ObfuscationLevel::Standard)
            .with_allowlist(vec![ip.clone()]);
        let out = obfuscator.obfuscate(&format!("src={ip}"));
        prop_assert!(out.contains(&ip),
            "allowlisted IP {ip} should pass through, got: {out}");
    }
}
