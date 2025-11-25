# list

Enumerate resources managed by Eos.

## Usage
```bash
eos list <resource> [flags]
```

## Examples
- `eos list services`
- `eos list env`
- `eos list containers`
- `eos list ceph pools`

## Notes
- Outputs should be script-friendly where possible.
- Keep parity between list/read/update verbs for each resource type.
