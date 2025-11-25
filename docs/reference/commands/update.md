# update

Apply configuration changes or remediate drift for a service.

## Usage
```bash
eos update <service> [--fix] [flags]
```

## Examples
- `eos update vault --fix`
- `eos update consul --fix`
- `eos update ceph --fix --dry-run` (where supported)

## Notes
- Follow Assess → Intervene → Evaluate: detect, prompt, apply, verify.
- `--fix` should remain idempotent; log any items that could not be corrected automatically.
- Capture significant changes and risk trade-offs in an ADR.
