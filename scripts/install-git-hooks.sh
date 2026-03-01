#!/usr/bin/env bash
set -euo pipefail

# Install Git hooks used by local CI parity checks.

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${repo_root}" ]]; then
  echo "Error: not in a git repository"
  exit 1
fi

cd "${repo_root}"
mkdir -p .git/hooks

install_hook() {
  local src="${1:?source required}"
  local dst="${2:?destination required}"
  install -m 0755 "${src}" "${dst}"
}

hook_source="scripts/hooks/pre-commit-ci-debug.sh"
hook_dest=".git/hooks/pre-commit"
install_hook "${hook_source}" "${hook_dest}"

hook_path="${repo_root}/${hook_dest}"
source_path="${repo_root}/${hook_source}"
hook_mode="$(stat -c '%a' "${hook_path}" 2>/dev/null || stat -f '%OLp' "${hook_path}")"
hook_sha="$(sha256sum "${hook_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${hook_path}" | awk '{print $1}')"
source_sha="$(sha256sum "${source_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${source_path}" | awk '{print $1}')"

echo "Installed pre-commit hook: ${hook_path}"
echo "Hook source: ${source_path}"
echo "Hook mode: ${hook_mode}"
echo "Hook sha256: ${hook_sha}"
echo "Hook source sha256: ${source_sha}"
if [[ -x "${hook_path}" ]]; then
  echo "Hook executable: true"
else
  echo "Hook executable: false"
  exit 1
fi

if [[ "${hook_sha}" != "${source_sha}" ]]; then
  echo "Hook matches source: false"
  exit 1
fi

echo "Hook matches source: true"
echo "Hook command: mage ci:debug"
