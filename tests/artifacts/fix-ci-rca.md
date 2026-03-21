# CI Fix RCA — fix/chatbackup-lint-ci (lint failures on main)

## Prioritised CI Problem List

| Priority | Symptom | Scope | Evidence |
|---|---|---|---|
| P0 | golangci-lint: 10 issues in pkg/chatbackup/ (errcheck x3, gosec G204 x4, goconst x1, nilerr x2) | main (bfbda3fb) | `golangci-lint run ./pkg/chatbackup/...` locally |
| P1 | PR #299 blocked: inherits main chatbackup lint failures + 3 own nolintlint issues in pkg/npm/ | branch feat/297-create-npm-command | CI run 45895 job 128662 log |
| P2 | CI sanity: no gate job, no notify-failure job, conditional ci-e2e-full | infra | `check-ci-sanity.sh` output |

## Root Cause (5-whys)

### P0: pkg/chatbackup lint violations introduced by PR #300

1. Why did CI fail on PR #299? `lint_changed` found 5 issues in chatbackup + 3 in npm.
2. Why did chatbackup have lint issues? PR #300 merged chatbackup hardening with unchecked errors, untagged exec.Command calls, and repeated "root" string literal.
3. Why was it not caught before merge? Main CI push runs `lint_changed` against previous commit — new issues flagged as "new" relative to prior chatbackup code were insufficient to fail the diff-based check.
4. Why was it not detected earlier? No full-package lint gate on main push (only diff-based).
5. Why is this the right durable fix? Fix each violation at source: check errors where meaningful, add constants for repeated strings, add targeted `//nolint` with security rationale for safe exec.Command usage.

## Fix Plan

- **Smallest change**: Fix 10 lint issues in `pkg/chatbackup/` (constants.go, backup.go, setup.go)
  - Add `RootUsername` constant for repeated "root" string (goconst)
  - Check error returns on filepath.Rel, json.Unmarshal (errcheck)
  - Add `//nolint:errcheck` with rationale for intentional WalkDir discard
  - Add `//nolint:gosec` G204 with rationale for safe exec.Command usages
  - Add `//nolint:nilerr` with rationale for intentional WalkDir error-skip
- **Idempotency**: `golangci-lint run ./pkg/chatbackup/...` must return 0 issues
- **Risk + rollback**: Low risk — no logic changes, only lint compliance. Rollback: revert commit.

