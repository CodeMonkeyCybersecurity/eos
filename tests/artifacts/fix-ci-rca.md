# CI Fix RCA — fix/247-add-propagate-prompts-npm-script

## Prioritised CI Problem List

| Priority | Symptom | Scope | Evidence |
|---|---|---|---|
| P0 | `governance-workflow-yaml-valid` fails: `ModuleNotFoundError: No module named 'yaml'` | main + branch | job#112850 log: `FAIL: governance-workflow-yaml-valid - expected exit 0, got 1 / output: ModuleNotFoundError: No module named 'yaml'` |
| P0 | `repo-root-from-script-path` fails: `cd: /opt/eos/scripts/..: No such file or directory` | main + branch | job#113262 log: `FAIL: repo-root-from-script-path - expected exit 0, got 1 / output: common.sh: line 28: cd: /opt/eos/scripts/..: No such file or directory` |
| P1 | `lint_changed` fails in ci-debug-parity: `fatal error: rados/librados.h: No such file or directory` | main + branch | job#112193 log: golangci-lint fails to compile pkg/ceph/diagnostics_sdk.go (imports go-ceph which requires librados-dev C headers not in catthehacker/ubuntu:act-latest) |

## Root Cause (5-whys)

### P0-A: pyyaml not in CI Docker image
1. Why did CI fail? `governance-workflow-yaml-valid` exits 1
2. Why? `import yaml` throws `ModuleNotFoundError`
3. Why? `pyyaml` is not pre-installed in `catthehacker/ubuntu:act-latest`
4. Why was it not detected earlier? Tests pass locally (`/opt/eos` has pyyaml installed system-wide)
5. Durable fix: ensure pyyaml before test — install it in the e2e test script via pip if absent

### P0-B: Hardcoded /opt/eos path
1. Why did CI fail? `repo-root-from-script-path` exits 1
2. Why? `cd /opt/eos/scripts/..` fails — directory doesn't exist in CI container
3. Why? Test hardcodes `/opt/eos/scripts/check-governance.sh` as input to `ps_repo_root()`
4. Why was it not detected earlier? Dev machine always runs at `/opt/eos`
5. Durable fix: use a temp dir in the test instead of the dev-machine absolute path

### P1: pkg/ceph requires librados-dev (CGo)
1. Why did CI fail? `golangci-lint run` exits 1
2. Why? Compilation of `pkg/ceph/diagnostics_sdk.go` fails — imports `go-ceph/rados` (CGo)
3. Why? `librados-dev` (Ceph C headers) not installed in CI container
4. Why was it not detected earlier? Package added without CI matrix update for CGo deps
5. Durable fix: exclude `pkg/ceph/` from golangci-lint paths (CGo with optional external deps)

## Fix Plan

- **Smallest change**: 3 targeted edits — e2e test script, unit test, golangci.yml exclusion
- **Idempotency**: all fixes are re-entrant; `pip install` is idempotent, path exclusion is additive
- **Risk + rollback**: low risk; test changes make tests more portable; lint exclusion can be reverted if librados-dev is later installed in CI

