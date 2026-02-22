# CI Scripts

*Last Updated: 2026-02-22*

Script-based CI entrypoints for Gitea Actions (self-hosted, DinD runners).

## Architecture

```
scripts/ci/
  preflight.sh       # Runner health: /dev/null repair, Go cache setup
  lint.sh            # Lint lane: golangci-lint, gofmt, go vet, emoji check
  test.sh            # Test lanes: unit, integration, e2e-smoke, e2e-full, fuzz
  summary.sh         # Aggregates test JSONL output into GitHub Step Summary
  security-checks.sh # Custom security pattern checks (TLS bypass, token exposure)
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
```

## Design decisions

- **DinD /dev/null repair**: `preflight.sh` repairs broken character devices (common in act_runner DinD containers where apt-get replaces them with regular files).
- **grep over rg**: `security-checks.sh` uses POSIX `grep` for portability across runner images.
- **Fail-fast**: Scripts use `set -euo pipefail` and explicit exit codes. No `|| true` on critical paths.
- **JSONL output**: Test lanes pipe `go test -json` to JSONL files for structured summary.

## Related

- Issue: #24
- Workflow: `.github/workflows/ci.yml`
- Suite definitions: `test/ci/suites.yaml` (policy documentation, not yet machine-consumed - see #32)
