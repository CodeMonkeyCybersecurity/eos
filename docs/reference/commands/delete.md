# delete

Remove a service or resource safely, with guardrails to avoid accidental data loss.

## Usage
```bash
eos delete <service> [flags]
```

## Examples
- `eos delete vault`
- `eos delete consul`
- `eos delete <service> --force` (if/when force flags are available; document carefully.)

## Notes
- Always confirm backups and data retention before deletion.
- Use explicit prompts and dry-run modes where available.
- Record deviations or irreversible actions in an ADR.
