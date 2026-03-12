#!/usr/bin/env bash
set -Eeuo pipefail

_ps_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci-common.sh
source "${_ps_lib_dir}/ci-common.sh"
# shellcheck source=git-env.sh
source "${_ps_lib_dir}/git-env.sh"
# shellcheck source=prompts-submodule/common.sh
source "${_ps_lib_dir}/prompts-submodule/common.sh"
# shellcheck source=prompts-submodule/context.sh
source "${_ps_lib_dir}/prompts-submodule/context.sh"
# shellcheck source=prompts-submodule/git.sh
source "${_ps_lib_dir}/prompts-submodule/git.sh"
# shellcheck source=prompts-submodule/artifacts.sh
source "${_ps_lib_dir}/prompts-submodule/artifacts.sh"
# shellcheck source=prompts-submodule/actions.sh
source "${_ps_lib_dir}/prompts-submodule/actions.sh"

