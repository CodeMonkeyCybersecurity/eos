# Command Structure

Eos uses a verb-first CLI so users think in actions, not flags. Commands stay thin; they validate input, gather context, and delegate to `pkg/`.

## Top-level verbs
- `create` — provision or enable a service/component.
- `read` — inspect current state or configuration.
- `update` — change configuration or remediate drift (including `--fix`).
- `delete` — remove resources with guardrails.
- `list` — enumerate resources (services, environments, containers, etc.).
- `backup` / `restore` — capture and recover stateful data.
- `debug` — diagnostics with evidence capture.
- `service` — lifecycle helpers for managed services.
- `self` (where present) — manage the Eos CLI itself.

## Patterns for contributors
- Keep `cmd/` files orchestration-only: flag parsing, consent prompts, handoff to `pkg/`.
- Follow Assess → Intervene → Evaluate in `pkg/` implementations; return structured results for logging.
- Use explicit verbs: avoid feature-specific top-level commands when a verb + noun fits (`eos create vault`, `eos update consul --fix`).
- Prefer SDKs/Go clients over shelling out to system binaries; wire telemetry via `otelzap`.
- Document new commands in [reference/commands](../reference/commands/) and capture decisions in ADRs when behavior changes.

## Navigation
- High-level overview: [architecture/overview.md](overview.md)
- Service boundaries: [service-management.md](service-management.md)
- State handling and drift detection: [state-management.md](state-management.md)
