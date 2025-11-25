# Architecture Overview

Eos is built to "solve once, systematize": encode operational knowledge so humans do not repeat fixes. The architecture keeps orchestration thin, business logic focused, and state observable.

## Philosophy
- Motto: **Human Technology** — human-centric, evidence-based, sustainable innovation.
- Command layer triggers predictable flows; packages implement the Assess → Intervene → Evaluate pattern.
- Documentation and automation stay in sync so contributors can extend safely.

## System Map (aligned to preferred infrastructure)
- **Control plane**: HashiCorp stack (Vault, Consul, Nomad) for secrets, service discovery, and scheduling.
- **Platform**: Kubernetes (K3s) for containerized workloads; virtualization via KVM where bare-metal isolation is required.
- **Data & storage**: Ceph and ZFS for distributed storage and snapshots.
- **Security & access**: SSH hardening by host role, Boundary/Wazuh/Fail2Ban where applicable.
- **AI/automation services**: BionicGPT/OpenWebUI, LiteLLM, n8n for orchestration and automation.
- **CLI boundaries**: `cmd/` defines verbs and flags; `pkg/` performs all real work with SDKs and system APIs.

## Architectural Boundaries
- **Commands**: Verb-first CLI (`create`, `read`, `update`, `delete`, `list`, `backup`, `restore`, `debug`, `service`).
- **Packages**: Service-specific logic with strong typing, constants, and SecretManager usage; no business logic in `cmd/`.
- **State and safety**: Prefer observed state over stored state; detect drift, ask for consent, apply idempotent changes.
- **Observability**: Structured logging (`otelzap`), evidence capture (e.g., `~/.eos/debug`), and follow-up verification.

## For Contributors
- Start with [command structure](command-structure.md) and [state management](state-management.md) to understand responsibilities.
- When adding a feature, define the desired role in the system map, choose the right verb, and codify decisions in an ADR.
- Keep user experience human-centric: explain changes, request consent, and default to safe operations.
