#!/usr/bin/env bash
set -euo pipefail

version="${GOLANGCI_LINT_VERSION:-v2.11.3}"
bin_dir="${1:-$(go env GOPATH)/bin}"

mkdir -p "${bin_dir}"

if command -v curl >/dev/null 2>&1; then
  curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "${bin_dir}" "${version}"
  exit 0
fi

if command -v wget >/dev/null 2>&1; then
  wget -O- -nv https://golangci-lint.run/install.sh | sh -s -- -b "${bin_dir}" "${version}"
  exit 0
fi

echo "ERROR: curl or wget is required to install golangci-lint ${version}" >&2
exit 1
