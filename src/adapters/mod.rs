//! Adapters: concrete implementations of hexagonal ports.

pub mod gitleaks;
pub mod regex_patterns;

pub use gitleaks::GitleaksAdapter;
pub use regex_patterns::RegexPatternSource;
