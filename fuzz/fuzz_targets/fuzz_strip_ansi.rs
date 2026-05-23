#![no_main]
use libfuzzer_sys::fuzz_target;

// strip_ansi is pub(crate) in the adapter — we re-implement the call path
// through the public SecretScanner::scan_diff interface. However, for a
// targeted fuzz of the ANSI parser, we inline the function here.

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = strip_ansi(s);
    }
});
