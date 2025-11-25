# State Management

Eos prioritizes observed state over stored state: inspect the system, plan a change, apply it idempotently, and verify.

## Principles
- **Assess → Intervene → Evaluate**: every operation measures current state, applies changes if approved, then validates results.
- **Minimal persistence**: prefer live facts from APIs (Vault/Consul/Nomad), the host, and config files over local databases.
- **Human Technology**: keep state handling transparent—explain what will change, collect evidence, and make it easy to reverse.

## Sources of truth
- **Configuration**: runtime flags and config files (commonly under `/etc/eos`; override via CLI flags). See [reference/configuration.md](../reference/configuration.md).
- **Runtime context**: environment discovery, host metadata, and secrets pulled through the SecretManager.
- **Diagnostics**: evidence captured to `~/.eos/debug/` to aid root-cause analysis and regression tracking.

## Drift handling
- Detect configuration drift by comparing observed state to expected templates/profiles per service.
- Use `update --fix` paths to apply idempotent corrections and re-verify.
- Log and surface residual drift so operators can decide whether to accept or escalate.

## Contributor checklist
- Make state reads explicit and centralized; avoid duplicating detection logic across services.
- Keep state mutations confined to `pkg/` and guard them with consent and validations.
- When adding new persistent data, document the location, schema, and retention expectations in this file and the reference docs.
