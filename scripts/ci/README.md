# CI Scripts

*Last Updated: 2026-02-22*

Script-based CI entrypoints for Gitea Actions (self-hosted, DinD runners).

## Architecture

```
scripts/ci/
  debug.sh           # Local/CI parity lane used by mage ci:debug + pre-commit
  preflight.sh       # Runner health verification + Go cache setup
  coverage-delta.sh  # PR coverage regression gate vs base branch
  lint.sh            # Lint lane: golangci-lint, gofmt, go vet, emoji check
  test.sh            # Policy-driven test lanes: unit/integration/e2e-smoke/e2e-full/fuzz
  summary.sh         # Structured JSONL parser -> report.json + Step Summary markdown
  security-checks.sh # Custom security checks + gosec allowlist validation

test/ci/tool/
  main.go            # Policy validator, JSONL summarizer, gosec allowlist checker
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
```

## Design decisions

- **Bootstrap repair in setup action**: `.github/actions/setup-go-env/action.yml` repairs `/dev/null` before apt installs.
- **Policy-as-code**: `test.sh` reads lane gating and coverage thresholds from `test/ci/suites.yaml` via `test/ci/tool`.
- **Policy guardrail**: every lane runs `policy-validate` before execution (enforces 70/20/10 and required PR lanes).
- **Port collision avoidance**: integration lane uses ephemeral host ports (`127.0.0.1::PORT`) and isolated docker network names.
- **Fail-fast**: Scripts use `set -euo pipefail` and explicit exit codes.
- **Structured observability**: lane-scoped outputs at `outputs/ci/<lane>/` with machine-readable report + concise markdown.

## Related

- Issue: #24
- Workflow: `.github/workflows/ci.yml`
- Suite definitions: `test/ci/suites.yaml` (machine-consumed)
- Security allowlist: `test/ci/security-allowlist.yaml`
