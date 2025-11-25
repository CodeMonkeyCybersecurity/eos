# Configuration

Configuration should be explicit, discoverable, and aligned with host roles. Use this page to document the canonical format and defaults.

## Locations
- Primary config directory: `/etc/eos/` (created by the installer).
- Override via CLI flags (e.g., `--config`) where supported.
- Store secrets in Vault; avoid embedding credentials in config files.

## Structure (to be refined)
- **Global**: logging level, telemetry endpoints, runtime context toggles.
- **Control plane**: Vault, Consul, Nomad endpoints and auth strategies.
- **Platform & compute**: Kubernetes (K3s) settings, KVM defaults, networking overlays.
- **Data**: Ceph/ZFS pools, replication factors, snapshot policies.
- **Security**: SSH hardening profile selection, MFA/Bastion requirements.
- **AI/automation**: BionicGPT/OpenWebUI, LiteLLM, n8n endpoints and resource limits.

## Example (fill in with canonical keys)
```yaml
# placeholder example
logging:
  level: info
telemetry:
  endpoint: http://localhost:4317
control_plane:
  vault:
    addr: https://vault.service.consul:8200
    auth_method: approle
```

## Contributor notes
- Keep this file in sync with the actual config structs in code.
- Document defaults, allowed values, and the precedence between flags, env vars, and files.
- Add migration notes when keys change; reference ADRs for breaking changes.
