# Examples

Runnable examples for using `obfsck`.

## Run

```bash
cargo run --example obfuscate_text
cargo run --example obfuscate_alert
cargo run --example batch_redaction
cargo run --example large_payload
```

Optional gist-backed input for large payload example:

```bash
OBFSCK_GIST_URL="https://gist.githubusercontent.com/<user>/<id>/raw/<file>.txt" \
  cargo run --example large_payload
```

## Files

- [`obfuscate_text.rs`](./obfuscate_text.rs): larger multi-line log payload redaction
- [`obfuscate_alert.rs`](./obfuscate_alert.rs): rich alert + many structured fields
- [`batch_redaction.rs`](./batch_redaction.rs): 250-record batch-style processing
- [`large_payload.rs`](./large_payload.rs): very large payload test (synthetic or raw gist input)
