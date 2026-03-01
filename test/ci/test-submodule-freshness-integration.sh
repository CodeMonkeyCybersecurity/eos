#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
export GIT_ALLOW_PROTOCOL="file:https:http:ssh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

remote_bare="${tmpdir}/prompts-remote.git"
remote_work="${tmpdir}/prompts-work"
repo="${tmpdir}/eos-test"

git init --bare "${remote_bare}" >/dev/null 2>&1
git clone "${remote_bare}" "${remote_work}" >/dev/null 2>&1
git -C "${remote_work}" config user.email "ci@example.com"
git -C "${remote_work}" config user.name "CI"
echo "v1" > "${remote_work}/README.md"
git -C "${remote_work}" add README.md
git -C "${remote_work}" commit -m "v1" >/dev/null
git -C "${remote_work}" push origin HEAD:main >/dev/null 2>&1
git -C "${remote_bare}" symbolic-ref HEAD refs/heads/main >/dev/null 2>&1
v1_sha="$(git -C "${remote_work}" rev-parse HEAD)"
echo "v2" > "${remote_work}/README.md"
git -C "${remote_work}" add README.md
git -C "${remote_work}" commit -m "v2" >/dev/null
git -C "${remote_work}" push origin HEAD:main >/dev/null 2>&1
v2_sha="$(git -C "${remote_work}" rev-parse HEAD)"

git init "${repo}" >/dev/null 2>&1
git -C "${repo}" config user.email "ci@example.com"
git -C "${repo}" config user.name "CI"
git -C "${repo}" -c protocol.file.allow=always submodule add "${remote_bare}" prompts
git -C "${repo}/prompts" checkout --detach "${v1_sha}" >/dev/null 2>&1
git -C "${repo}" add .gitmodules prompts
git -C "${repo}" commit -m "add stale prompts submodule" >/dev/null
mkdir -p "${repo}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${repo}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${repo}/scripts/lib/prompts-submodule.sh"
chmod +x "${repo}/scripts/prompts-submodule-freshness.sh"

th_assert_run "stale-fail-without-auto-update" 1 '"outcome":"fail_stale"' \
  env STRICT_REMOTE=false AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${repo}/report-stale.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-stale" "${repo}/report-stale.json" "outcome" "fail_stale"

th_assert_run "auto-update-converges" 0 '"outcome":"pass_auto_updated"' \
  env STRICT_REMOTE=false AUTO_UPDATE=true SUBMODULE_REPORT_JSON="${repo}/report-update.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-updated" "${repo}/report-update.json" "outcome" "pass_auto_updated"
th_assert_json_field "report-remote-sha" "${repo}/report-update.json" "remote_sha" "${v2_sha}"

git -C "${repo}/prompts" remote set-url origin "${tmpdir}/does-not-exist.git"
th_assert_run "strict-remote-failure" 2 '"outcome":"fail_remote_unreachable"' \
  env STRICT_REMOTE=true AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${repo}/report-strict.json" bash "${repo}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-strict-failure" "${repo}/report-strict.json" "outcome" "fail_remote_unreachable"

th_summary "integration"
