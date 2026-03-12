#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
ENTRY_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
# shellcheck source=../../scripts/lib/git-env.sh
source "${GIT_ENV_SCRIPT}"
export GIT_ALLOW_PROTOCOL="file:https:http:ssh"

# Simulate hook environment contamination. All foreign-repo Git commands below
# must run via ge_run_clean_git to remain deterministic.
export GIT_DIR="${REPO_ROOT}/.git"
export GIT_WORK_TREE="${REPO_ROOT}"
export GIT_INDEX_FILE="${REPO_ROOT}/.git/index"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

remote_bare="${tmpdir}/prompts-remote.git"
remote_work="${tmpdir}/prompts-work"
repo="${tmpdir}/eos-test"

ge_run_clean_git git init --bare "${remote_bare}" >/dev/null 2>&1
ge_run_clean_git git clone "${remote_bare}" "${remote_work}" >/dev/null 2>&1
ge_run_clean_git git -C "${remote_work}" config user.email "ci@example.com"
ge_run_clean_git git -C "${remote_work}" config user.name "CI"
echo "v1" > "${remote_work}/README.md"
ge_run_clean_git git -C "${remote_work}" add README.md
ge_run_clean_git git -C "${remote_work}" commit -m "v1" >/dev/null
ge_run_clean_git git -C "${remote_work}" push origin HEAD:main >/dev/null 2>&1
ge_run_clean_git git -C "${remote_bare}" symbolic-ref HEAD refs/heads/main >/dev/null 2>&1
v1_sha="$(ge_run_clean_git git -C "${remote_work}" rev-parse HEAD)"
echo "v2" > "${remote_work}/README.md"
ge_run_clean_git git -C "${remote_work}" add README.md
ge_run_clean_git git -C "${remote_work}" commit -m "v2" >/dev/null
ge_run_clean_git git -C "${remote_work}" push origin HEAD:main >/dev/null 2>&1
v2_sha="$(ge_run_clean_git git -C "${remote_work}" rev-parse HEAD)"

ge_run_clean_git git init "${repo}" >/dev/null 2>&1
ge_run_clean_git git -C "${repo}" config user.email "ci@example.com"
ge_run_clean_git git -C "${repo}" config user.name "CI"
ge_run_clean_git git -C "${repo}" -c protocol.file.allow=always submodule add "${remote_bare}" prompts
ge_run_clean_git git -C "${repo}/prompts" checkout --detach "${v1_sha}" >/dev/null 2>&1
ge_run_clean_git git -C "${repo}" add .gitmodules prompts
ge_run_clean_git git -C "${repo}" commit -m "add stale prompts submodule" >/dev/null
mkdir -p "${repo}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${repo}/scripts/prompts-submodule-freshness.sh"
cp "${ENTRY_SCRIPT}" "${repo}/scripts/prompts-submodule.sh"
cp "${HELPER_SCRIPT}" "${repo}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${repo}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${repo}/scripts/lib/git-env.sh"
mkdir -p "${repo}/scripts/lib/prompts-submodule"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/common.sh" "${repo}/scripts/lib/prompts-submodule/common.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/context.sh" "${repo}/scripts/lib/prompts-submodule/context.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/git.sh" "${repo}/scripts/lib/prompts-submodule/git.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/artifacts.sh" "${repo}/scripts/lib/prompts-submodule/artifacts.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/actions.sh" "${repo}/scripts/lib/prompts-submodule/actions.sh"
chmod +x "${repo}/scripts/prompts-submodule-freshness.sh" "${repo}/scripts/prompts-submodule.sh"

th_assert_run "stale-fail-without-auto-update" 1 '"outcome":"fail_stale"' \
  ge_run_clean_git env STRICT_REMOTE=false AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${repo}/report-stale.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-stale" "${repo}/report-stale.json" "outcome" "fail_stale"

echo "local-only-change" > "${repo}/prompts/LOCAL_ONLY.txt"
th_assert_run "auto-update-refuses-dirty-submodule" 1 '"outcome":"fail_dirty_worktree"' \
  ge_run_clean_git env STRICT_REMOTE=false AUTO_UPDATE=true SUBMODULE_REPORT_JSON="${repo}/report-dirty.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-dirty" "${repo}/report-dirty.json" "outcome" "fail_dirty_worktree"
rm -f "${repo}/prompts/LOCAL_ONLY.txt"

th_assert_run "auto-update-converges" 0 '"outcome":"pass_auto_updated"' \
  ge_run_clean_git env STRICT_REMOTE=false AUTO_UPDATE=true SUBMODULE_REPORT_JSON="${repo}/report-update.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-updated" "${repo}/report-update.json" "outcome" "pass_auto_updated"
th_assert_json_field "report-remote-sha" "${repo}/report-update.json" "remote_sha" "${v2_sha}"
th_assert_json_field "report-schema-updated" "${repo}/report-update.json" "schema_version" "2"

ge_run_clean_git git -C "${repo}/prompts" remote set-url origin "${tmpdir}/does-not-exist.git"
th_assert_run "strict-remote-failure" 2 '"outcome":"fail_remote_unreachable"' \
  ge_run_clean_git env STRICT_REMOTE=true AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${repo}/report-strict.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-strict-failure" "${repo}/report-strict.json" "outcome" "fail_remote_unreachable"

th_summary "integration"
