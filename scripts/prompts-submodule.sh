#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/ci-common.sh
source "${script_dir}/lib/ci-common.sh"
# shellcheck source=./lib/git-env.sh
source "${script_dir}/lib/git-env.sh"
# shellcheck source=./lib/prompts-submodule.sh
source "${script_dir}/lib/prompts-submodule.sh"

repo_root="$(ps_repo_root "${BASH_SOURCE[0]}")"
command="${1:-}"
if [[ -z "${command}" ]]; then
  echo "usage: $0 <freshness|governance|install-hook|pre-commit>" >&2
  exit 2
fi
shift || true

case "${command}" in
  freshness)
    ps_run_freshness "${repo_root}" "$@"
    ;;
  governance)
    ps_run_governance "${repo_root}" "$@"
    ;;
  install-hook)
    ps_install_hook "${repo_root}" "$@"
    ;;
  pre-commit)
    export PS_CTX_KIND="hook"
    export PS_CTX_ACTION="pre-commit"
    export PS_CTX_REPORT_PATH="${PRE_COMMIT_REPORT_JSON:-${repo_root}/outputs/ci/pre-commit/report.json}"
    export PS_CTX_REPO_ROOT="${repo_root}"
    ps_ctx_init
    ps_run_pre_commit "${repo_root}" "$@"
    ;;
  *)
    echo "usage: $0 <freshness|governance|install-hook|pre-commit>" >&2
    exit 2
    ;;
esac

