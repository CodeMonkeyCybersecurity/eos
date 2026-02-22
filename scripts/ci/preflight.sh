#!/usr/bin/env bash
set -euo pipefail

runner_temp="${RUNNER_TEMP:-/tmp}"
go_tmp="${runner_temp}/go-tmp"
go_cache="${runner_temp}/go-cache"
go_mod_cache="${runner_temp}/go-mod"

mkdir -p "${go_tmp}" "${go_cache}" "${go_mod_cache}"

export GOTMPDIR="${go_tmp}"
export GOCACHE="${go_cache}"
export GOMODCACHE="${go_mod_cache}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "GOTMPDIR=${GOTMPDIR}"
    echo "GOCACHE=${GOCACHE}"
    echo "GOMODCACHE=${GOMODCACHE}"
  } >> "${GITHUB_ENV}"
fi

# Repair /dev/null and /dev/zero if broken (common in DinD / act_runner).
# apt-get can replace character devices with regular files; Go toolchain
# requires real character devices.
ensure_char_device() {
  local path="$1" major="$2" minor="$3"
  if [[ -c "${path}" ]] && echo "check" > "${path}" 2>/dev/null; then
    return 0
  fi
  echo "Repairing ${path} (was: $(ls -la "${path}" 2>&1 || echo 'missing'))"
  sudo rm -f "${path}" 2>/dev/null || true
  sudo mknod -m 666 "${path}" c "${major}" "${minor}"
  if [[ ! -c "${path}" ]]; then
    echo "::error::Failed to repair ${path}"
    return 1
  fi
}

ensure_char_device /dev/null 1 3 || exit 10
ensure_char_device /dev/zero 1 5 || exit 11

if ! (echo "preflight" > /dev/null); then
  echo "::error::Cannot write to /dev/null after repair"
  exit 12
fi

if [[ ! -w /tmp ]]; then
  echo "::error::/tmp is not writable"
  exit 13
fi

echo "CI preflight diagnostics"
echo "  kernel: $(uname -srmo)"
echo "  go: $(go version 2>/dev/null || echo 'go not found yet')"
echo "  disk(/tmp): $(df -h /tmp | tail -1)"
echo "  /tmp perms: $(stat -c '%a %U:%G' /tmp 2>/dev/null || stat -f '%Sp %Su:%Sg' /tmp 2>/dev/null || echo unknown)"
echo "  /dev/null: $(ls -la /dev/null)"
echo "  /dev/zero: $(ls -la /dev/zero)"
echo "  GOTMPDIR=${GOTMPDIR}"
echo "  GOCACHE=${GOCACHE}"
echo "  GOMODCACHE=${GOMODCACHE}"
