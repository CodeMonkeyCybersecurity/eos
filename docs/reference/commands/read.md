# read

Inspect the current state or configuration of a resource.

## Usage
```bash
eos read <service> [flags]
```

## Examples
- `eos read vault`
- `eos read consul`
- `eos read <service> --verbose`

## Notes
- Prefer observed state over cached data; include key diagnostics inline.
- Keep output consistent with `list` and `update` for the same service.
