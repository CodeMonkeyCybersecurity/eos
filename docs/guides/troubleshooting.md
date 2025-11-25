# Troubleshooting

Use this checklist to diagnose issues quickly and capture evidence for follow-up ADRs.

## Quick checks
- Run `eos --help` to confirm the binary is installed.
- Verify prerequisites: network access, sudo/root permissions, and available disk space.
- Confirm host role and service expectations before running fixes.

## Diagnostics
```bash
eos debug <service>
# Examples
# eos debug vault
# eos debug consul
# eos debug ceph
```
- Review captured evidence under `~/.eos/debug/`.
- Re-run with `--verbose` flags where supported to gather more context.

## Common issues
- **Authentication failures**: Reissue short-lived credentials or check SSH hardening profile for the host role.
- **Drift detected**: Use `eos update <service> --fix` and review logs for items that could not be corrected automatically.
- **Missing dependencies**: Re-run `./install.sh` to rebuild the CLI and re-apply baseline packages.

## When to open an ADR
- Repeated incidents on the same host role.
- New hardening exceptions or operational runbooks needed.
- Material UX or workflow changes affecting the "solve once, systematize" philosophy.
