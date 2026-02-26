# Streaming log redaction

## Idea

Run `obfsck` on each log event before forwarding to your SIEM.

## Why

- Prevents sensitive leakage in near real-time
- Keeps token consistency for correlation (`same input => same token`)

## Minimal flow

1. Read line/event from source (syslog, Kafka, Fluent Bit)
2. `obfuscate_text(event, ObfuscationLevel::Standard)`
3. Emit redacted event + optionally emit mapping metadata to secure storage

## Notes

- Use `Paranoid` when hostnames and high-entropy strings should also be masked
- Keep mappings out of general logs if they can be sensitive in your environment
