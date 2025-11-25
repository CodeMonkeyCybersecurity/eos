# Service Management

Services in Eos are grouped by role (control plane, data plane, security, AI/automation) and managed with consistent lifecycles.

## Lifecycle
- **Create**: Provision service dependencies, secrets, and configs using SDK-first operations. Ask for consent before changes.
- **Update**: Apply configuration changes or drift correction (`--fix`) idempotently.
- **Read/List**: Surface observed state from APIs and the host, not cached state.
- **Backup/Restore**: Capture artifacts and configs with role-aware defaults (e.g., Vault unseal data, Consul snapshots, Ceph metadata).
- **Debug**: Collect evidence (`~/.eos/debug`) with structured logs and root-cause hints.

## Service roles (aligned to preferred infrastructure)
- **Control plane**: Vault, Consul, Nomad.
- **Platform & compute**: K3s for Kubernetes workloads; KVM for virtualization.
- **Data**: Ceph/ZFS for storage and snapshots.
- **Security**: Wazuh, Boundary, SSH hardening by host role, Fail2Ban.
- **AI & automation**: BionicGPT, OpenWebUI, LiteLLM gateway, n8n.
- **Web/services**: Reverse proxy (Hecate), Mattermost, Umami, and other app services.

## Contributor guidance
- Map every change to a lifecycle verb and a service role; avoid bespoke flows.
- Keep service-specific constants centralized (e.g., under `pkg/<service>/constants.go`).
- Prefer reusable helpers for secrets, files, and system operations to avoid drift between services.
- When introducing a new service, document its role, dependencies, and safety checks here and in [reference/commands](../reference/commands/).
