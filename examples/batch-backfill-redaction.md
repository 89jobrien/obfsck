# Batch backfill redaction

## Idea

Use `obfsck` in offline jobs to sanitize historical alert/log datasets.

## Why

- Enables safer analytics on old data
- Reduces compliance risk for retained records

## Minimal flow

1. Read archived records in chunks
2. For each record, run `obfuscate_text` or `obfuscate_alert`
3. Write redacted output to a new dataset/table
4. Validate sample records for token consistency and expected redaction

## Operational tips

- Track throughput and memory usage by chunk size
- Consider separate runs by privacy level (`Standard` vs `Paranoid`)
