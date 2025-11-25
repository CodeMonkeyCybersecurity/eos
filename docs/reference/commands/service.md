# service

Helpers for service lifecycle operations (start, stop, restart, status) where applicable.

## Usage
```bash
eos service <service> <action> [flags]
```

## Examples
- `eos service vault status`
- `eos service consul restart`
- `eos service <service> logs --tail 100` (if exposed)

## Notes
- Keep actions minimal and reversible; prefer `update --fix` for configuration changes.
- Document supported actions per service once implemented in code.
- Ensure outputs are safe for scripting and troubleshooting workflows.
