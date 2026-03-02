# CI Scripts

*Last Updated: 2026-03-01*

Script-based CI entrypoints for Gitea Actions (self-hosted, DinD runners).

## Architecture

```text
scripts/ci/
  debug.sh           # Local/CI parity lane used by mage ci:debug + pre-commit
  lib/lane-runtime.sh # Shared lane logging/reporting/error-handling helpers
  verify-parity.sh   # Enforces parity contract across hook, mage target, and CI workflows
  preflight.sh       # Runner health verification + Go cache setup
  coverage-delta.sh  # PR coverage regression gate vs base branch
  lint.sh            # Lint lane: golangci-lint, gofmt, go vet, emoji check
  test.sh            # Policy-driven test lanes: unit/integration/e2e-smoke/e2e-full/fuzz
  summary.sh         # Structured JSONL parser -> report.json + Step Summary markdown
  security-checks.sh # Custom security checks + gosec allowlist validation

test/ci/tool/
  main.go            # Policy validator, JSONL summarizer, gosec allowlist checker

test/ci/
  test-verify-parity.sh # CI parity contract regression checks
```

## Usage

Workflows call these scripts directly. Local parity via Make:

```bash
make ci-preflight     # Runner health check
make ci-lint          # Full lint
make ci-unit          # Unit tests + coverage enforcement (>= 70%)
make ci-integration   # Integration tests (Vault + PostgreSQL containers)
make ci-e2e-smoke     # E2E smoke tests
make ci-fuzz          # Bounded fuzz tests
make ci-coverage-delta
make ci-debug         # Parity lane (what pre-commit and CI debug both execute)
make ci-verify-parity # Verify parity contract wiring
```

## Design decisions

- **Bootstrap repair in setup action**: `.github/actions/setup-go-env/action.yml` repairs `/dev/null` before apt installs.
- **Policy-as-code**: `test.sh` reads lane gating and coverage thresholds from `test/ci/suites.yaml` via `test/ci/tool`.
- **Policy guardrail**: every lane runs `policy-validate` before execution (enforces 70/20/10 and required PR lanes).
- **Port collision avoidance**: integration lane uses ephemeral host ports (`127.0.0.1::PORT`) and isolated docker network names.
- **Fail-fast**: scripts use `set -euo pipefail` (or `set -Eeuo pipefail` where `ERR` trap propagation matters) and explicit exit codes.
- **Structured observability**: lane-scoped outputs at `outputs/ci/<lane>/` with machine-readable report + metrics + JSONL events.
- **Hook-safe Git handling**: shared `scripts/lib/git-env.sh` clears hook-exported Git-local env vars before foreign-repo Git commands.
- **Parity contract**: `scripts/ci/verify-parity.sh` prevents drift between hook command, Mage target, and both `.gitea`/`.github` CI debug workflows.

## Debug Lane Artifacts

`scripts/ci/debug.sh` emits:

- `outputs/ci/debug/report.json`
- `outputs/ci/debug/metrics.prom`
- `outputs/ci/debug/events.jsonl`

The lane takes an exclusive lock (`outputs/ci/debug/.lock`) when `flock` is available and truncates `events.jsonl` on each run for idempotent artifacts.

Key metrics:

- `ci_debug_status{status="pass|fail"}`
- `ci_debug_duration_seconds`
- `ci_debug_stage_failures_total{stage=...}`
- `ci_debug_last_run_timestamp_seconds`

## Git/Gitea Automation (MCP-equivalent CLI path)

- Local parity run: `./scripts/install-git-hooks.sh && ./magew ci:debug`
- Verify parity wiring: `make ci-verify-parity`
- Inspect and operate on PRs with Tea CLI (v0.11.x compatible):
  - `tea pr ls`
  - `tea pr <pr-number>`
  - `tea open prs`

## Related

- Issue: #24
- Workflow: `.github/workflows/ci.yml`
- Suite definitions: `test/ci/suites.yaml` (machine-consumed)
- Security allowlist: `test/ci/security-allowlist.yaml`
