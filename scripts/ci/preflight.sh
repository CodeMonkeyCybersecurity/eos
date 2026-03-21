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

if [[ ! -c /dev/null ]] || ! echo "preflight" > /dev/null 2>/dev/null; then
  echo "::error::/dev/null is not a healthy character device"
  exit 10
fi

if [[ ! -c /dev/zero ]]; then
  echo "::error::/dev/zero is not a character device"
  exit 11
fi

if [[ ! -w /tmp ]]; then
  echo "::error::/tmp is not writable"
  exit 12
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

bash scripts/ci/check-test-tags.sh
