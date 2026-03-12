#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"
exec bash "${repo_root}/scripts/prompts-submodule.sh" pre-commit "$@"
