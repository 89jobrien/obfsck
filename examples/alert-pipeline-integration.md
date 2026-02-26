# Alert pipeline integration

## Idea

Apply `obfuscate_alert` right before outbound alert delivery (Slack, ticketing, email).

## Why

- Keeps internal raw signals private
- Preserves enough shape for triage workflows

## Minimal flow

1. Build alert payload (`output`, `output_fields`)
2. Call `obfuscate_alert(output, output_fields, level)`
3. Send obfuscated payload to external systems
4. Persist `ObfuscationMapExport` only where authorized

## Recommended level

- `Standard` for general SOC workflows
- `Paranoid` for high-sensitivity or external sharing
