# ADR-0002 SSH Hardening by Host Role

## Context
- SSH access must be consistent across the preferred Eos infrastructure stack: HashiCorp control plane (Vault, Consul, Nomad), storage (Ceph/ZFS), Kubernetes (K3s), virtualization (KVM), and supporting services (Wazuh, Boundary, BionicGPT/OpenWebUI).
- Current guidance is scattered; role-specific drift increases risk and slows recovery when automation needs to intervene.
- We want a human-centric, evidence-based baseline that balances strong security with operational usability for administrators and automated tasks.

## Decision
- Define role-based SSH hardening profiles: bastion/gateway, control-plane nodes, workload/service nodes, storage nodes, and admin workstations.
- Standardize authentication per role (e.g., bastions require MFA-capable flows; control-plane nodes prefer short-lived machine credentials; service nodes favor key-based auth with restricted principals).
- Standardize protocol settings across roles (KEX/ciphers/MACs, disable password authentication where automation allows, mandate strong host keys, consistent idle/failed-attempt controls).
- Encode profiles into Eos docs and automation so `eos` commands apply the right profile per host role while preserving the "solve once, systematize" philosophy.
- Document operator touchpoints (approved users/groups per role, break-glass flow, logging targets) in the security docs.

## Consequences
- **Positive**: Reduced attack surface, faster audits, and predictable behavior when running Eos updates or fixes across heterogeneous hosts.
- **Trade-offs**: Operators must map every host to a role; some legacy hosts may need exceptions; MFA/short-lived credentials introduce additional setup overhead.
- **Follow-up**: Flesh out per-role settings in `security/hardening-profiles.md` and `security/ssh-configuration.md`; wire automation hooks as the implementation matures.

## Status
Proposed

## Date
2025-11-25
