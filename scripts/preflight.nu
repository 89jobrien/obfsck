#!/usr/bin/env nu
# preflight.nu — obfsck environment validation

def check [label: string, pass: bool, detail: string = ""] {
    if $pass {
        print $"[ok]   ($label)"
    } else if $detail != "" {
        print $"[fail] ($label) — ($detail)"
    } else {
        print $"[fail] ($label)"
    }
    $pass
}

print "=== obfsck preflight ==="

let has_anthropic = ($env | get -i ANTHROPIC_API_KEY | is-not-empty)
let secrets_yaml = ("config/secrets.yaml" | path exists)

let results = [
    (check "cargo on PATH" (which cargo | length) > 0),
    (check "mise on PATH" (which mise | length) > 0),
    (check "ANTHROPIC_API_KEY set" $has_anthropic "required for analyzer feature"),
    (check "config/secrets.yaml present" $secrets_yaml "required — checked at compile time via build.rs"),
    (check "op on PATH" (which op | length) > 0),
    (check "1Password authed" (do { op account list } | complete | get exit_code) == 0),
    (check "git repo clean" (do { git status --porcelain } | complete | get stdout | str trim | is-empty)),
]

let failed = $results | where { |r| not $r } | length
let total = $results | length

print ""
if $failed == 0 {
    print $"preflight passed ($total)/($total)"
} else {
    print $"preflight ($total - $failed)/($total) — ($failed) check(s) failed"
}
