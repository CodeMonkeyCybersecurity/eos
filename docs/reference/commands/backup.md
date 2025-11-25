# backup

Create backups for supported services with role-aware defaults.

## Usage
```bash
eos backup <service> [flags]
```

## Examples
- `eos backup vault` — capture Vault snapshot/keys (ensure secure storage).
- `eos backup consul` — capture Consul snapshot.
- `eos backup ceph` — capture Ceph metadata (fill in details per implementation).

## Notes
- Confirm storage location, encryption, and retention in an ADR before production use.
- Evidence and logs should be preserved with the backup artifact.
- See [common-workflows](../../guides/common-workflows.md) for end-to-end flows.
