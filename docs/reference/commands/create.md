# create

Provision a service or component following the preferred infrastructure outline.

## Usage
```bash
eos create <service> [flags]
```

## Examples
- `eos create vault` — install and configure Vault.
- `eos create consul` — install Consul for service discovery.
- `eos create nomad` — set up Nomad for scheduling.
- `eos create ceph` — provision Ceph storage (when enabled in code).

## Notes
- Keep `cmd/` orchestration minimal; business logic lives in `pkg/<service>/`.
- Request consent before impactful changes; surface dependencies to the user.
- Document new services and defaults in [service-management](../../architecture/service-management.md) and add ADRs for major decisions.
