# CI Fix RCA — fix/247-add-propagate-prompts-npm-script

## Prioritised CI Problem List

| Priority | Symptom | Scope | Evidence |
|---|---|---|---|
| P0 | `governance-workflow-yaml-valid` fails: `ModuleNotFoundError: No module named 'yaml'` | main + branch | job#112850 log: `FAIL: governance-workflow-yaml-valid - expected exit 0, got 1 / output: ModuleNotFoundError: No module named 'yaml'` |
| P0 | `repo-root-from-script-path` fails: `cd: /opt/eos/scripts/..: No such file or directory` | main + branch | job#113262 log: `FAIL: repo-root-from-script-path - expected exit 0, got 1 / output: common.sh: line 28: cd: /opt/eos/scripts/..: No such file or directory` |
| P1 | `lint_changed` fails in ci-debug-parity: `fatal error: rados/librados.h: No such file or directory` | main + branch | job#112193 log: golangci-lint fails to compile pkg/ceph/diagnostics_sdk.go (imports go-ceph which requires librados-dev C headers not in catthehacker/ubuntu:act-latest) |
| P1 | `lint_changed` times out: `Package 'libvirt', required by 'virtual:world', not found` | branch | job#113964 log: golangci-lint fails to compile pkg/kvm (imports libvirt.org/go/libvirt CGo) + pkg/cephfs (imports go-ceph/cephfs/admin CGo); lint times out after 8m fighting CGo errors |
| P1 | `propagation_pyramid` fails: `FAIL: propagate-script-exists - expected exit 0, got 1` | branch | job#114240 log: `test -f prompts/scripts/propagate.sh` fails because prompts submodule not initialized in ci-debug-parity workflow (fresh CI checkout does not init submodules) |

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

### P1-A: pkg/ceph requires librados-dev (CGo) — fixed with noceph build tag
1. Why did CI fail? `golangci-lint run` exits 1
2. Why? Compilation of `pkg/ceph/diagnostics_sdk.go` fails — imports `go-ceph/rados` (CGo)
3. Why? `librados-dev` (Ceph C headers) not installed in CI container
4. Why was it not detected earlier? Package added without CI matrix update for CGo deps
5. Durable fix: `noceph` build tag in `.golangci.yml` routes to pure-Go stub (no CGo needed)

### P1-B: pkg/kvm and pkg/cephfs require CGo C libraries — fixed by installing in CI
1. Why did CI fail? `golangci-lint run` times out at 8 minutes
2. Why? pkg/kvm imports `libvirt.org/go/libvirt` (CGo, requires `libvirt-dev`); pkg/cephfs imports `go-ceph/cephfs/admin` (CGo, requires `librados-dev`). No build tags exclude them from Linux.
3. Why? These use `linux`/`!darwin` build tags (not `!noceph`), so the `noceph` workaround doesn't apply
4. Why was it not detected earlier? CGo failures in golangci-lint caused timeouts not clear errors
5. Durable fix: install `libvirt-dev` and `librados-dev` in CI workflow before golangci-lint runs; increase golangci-lint timeout from 8m to 20m

### P1-C: prompts submodule not initialized in ci-debug-parity workflow
1. Why did CI fail? `propagation_pyramid` stage exits 1
2. Why? `test -f prompts/scripts/propagate.sh` fails — file not found
3. Why? `git checkout` in CI does NOT initialize submodules by default; `prompts` is a submodule
4. Why was it not detected earlier? Local dev always has the submodule initialized (`/opt/eos/prompts/scripts/propagate.sh` exists)
5. Durable fix: add "Init prompts submodule (HTTPS with token)" step to `ci-debug-parity.yml` that:
   - Detects the reachable IP URL from the checkout action's local extraheader config
   - Sets auth in GLOBAL git config (local config is NOT inherited by git-clone subprocesses)
   - Overrides the submodule URL in local config to use the IP URL
   - Runs `GIT_TERMINAL_PROMPT=0 git submodule update prompts`

   **Root sub-cause**: `actions/checkout` configures auth via `http.<ip-url>.extraheader` in LOCAL git config only. When `git submodule update` spawns `git clone` as a subprocess, that subprocess reads GLOBAL/SYSTEM configs but NOT the parent repo's local config. Result: clone gets HTTP 401, git tries interactive credential prompt, fails with `No such device or address` (no TTY in container).

## Fix Plan

- **Smallest change**: 5 targeted edits — 2 e2e test scripts, golangci.yml (noceph tag + timeout), CI workflow (apt-get install + submodule init with global auth), lint.sh (remove hardcoded --timeout=8m)
- **Idempotency**: all fixes are re-entrant; `pip install` is idempotent, `apt-get install` is idempotent, global git config is overwritten (not appended), build tags are additive
- **Risk + rollback**: low risk; test changes make tests more portable; CGo lib install adds ~30s to CI; global git config change is scoped to the CI container lifecycle only

