# Security Best Practices

Foundational practices for Eos deployments and contributions.

## Identity and access
- Use role-based access mapped to the infrastructure outline (bastion, control plane, storage, workload).
- Enforce MFA on bastions; prefer short-lived credentials for automation and operators.
- Keep SSH hardening aligned with [ADR-0002](../adr/ADR-0002-ssh-hardening-by-host-role.md).

## Secrets
- Store secrets in Vault; never commit credentials.
- Rotate tokens/keys regularly; automate via Eos where supported.
- Limit secret scope; avoid reusing credentials across roles or environments.

## Platform hygiene
- Patch regularly; pin critical packages only when documented.
- Minimize exposed services; restrict inbound network ranges per host role.
- Enable logging and forwarding to Wazuh/SIEM; collect evidence for incidents in `~/.eos/debug/`.

## Development and releases
- Default to idempotent operations with clear rollback paths.
- Document decisions and exceptions with ADRs and keep docs up to date.
- Verify changes against the Human Technology principles: human-centric, evidence-based, sustainable innovation.
