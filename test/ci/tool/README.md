# test/ci/tool

*Last Updated: 2026-02-22*

CI policy parser and reporting tool. Consumed by `scripts/ci/test.sh` and `scripts/ci/summary.sh`.

## Commands

| Command | Purpose |
|---------|---------|
| `policy-validate` | Enforce CI policy invariants (70/20/10, required lanes, required-on-PR gates) |
| `policy-threshold` | Read coverage threshold from `suites.yaml` for a lane |
| `policy-should-run` | Determine if a lane should run based on event + changed files |
| `summary` | Parse JSONL test output into structured report JSON + markdown |
| `gosec-check` | Validate gosec findings against `security-allowlist.yaml` |

## Usage

```bash
go run ./test/ci/tool policy-validate test/ci/suites.yaml
go run ./test/ci/tool policy-threshold test/ci/suites.yaml unit 70
go run ./test/ci/tool policy-should-run test/ci/suites.yaml integration pull_request changed.txt default-true
go run ./test/ci/tool summary unit success outputs/ci/unit outputs/ci/unit/coverage.out outputs/ci/unit/report.json outputs/ci/unit/summary.md
go run ./test/ci/tool gosec-check outputs/ci/security-audit/gosec.json test/ci/security-allowlist.yaml
```

## Related

- Issue: #24
- Policy file: `test/ci/suites.yaml`
- Security allowlist: `test/ci/security-allowlist.yaml`
- CI workflow: `.github/workflows/ci.yml`
