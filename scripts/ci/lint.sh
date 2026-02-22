#!/usr/bin/env bash
set -euo pipefail

scope="${1:-}"
ci_event="${CI_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
base_ref="${CI_BASE_REF:-${GITHUB_BASE_REF:-}}"

if [[ -z "${scope}" ]]; then
  if [[ "${ci_event}" == "pull_request" ]]; then
    scope="changed"
  else
    scope="all"
  fi
fi

resolve_base_rev() {
  if [[ -z "${base_ref}" ]]; then
    return 1
  fi
  git fetch origin "${base_ref}" --depth=1 >/dev/null 2>&1 || true
  git rev-parse "origin/${base_ref}" 2>/dev/null || return 1
}

run_emoji_check() {
  if [[ -x .github/hooks/remove-emojis.sh ]]; then
    ./.github/hooks/remove-emojis.sh --dry-run > /tmp/emoji-check.log 2>&1 || true
    if grep -Eq "Files with emojis found: [1-9]" /tmp/emoji-check.log; then
      echo "::error::Emojis found in non-test files"
      cat /tmp/emoji-check.log
      exit 1
    fi
  fi
}

run_all() {
  echo "Running full lint checks"
  golangci-lint run --timeout=8m --config=.golangci.yml

  unformatted="$(gofmt -s -l . | grep -v '^vendor/' || true)"
  if [[ -n "${unformatted}" ]]; then
    echo "::error::Unformatted files found:"
    echo "${unformatted}"
    exit 1
  fi

  go vet ./...
  run_emoji_check
}

run_changed() {
  local base_rev
  if ! base_rev="$(resolve_base_rev)"; then
    echo "Base ref unavailable; falling back to full lint"
    run_all
    return
  fi

  echo "Running changed-file lint checks against ${base_ref} (${base_rev})"
  golangci-lint run --timeout=8m --config=.golangci.yml --new-from-rev="${base_rev}"

  changed_go="$(git diff --name-only "${base_rev}"...HEAD -- '*.go' | grep -v '^vendor/' || true)"
  if [[ -n "${changed_go}" ]]; then
    unformatted="$(echo "${changed_go}" | xargs -r gofmt -s -l)"
    if [[ -n "${unformatted}" ]]; then
      echo "::error::Unformatted changed files found:"
      echo "${unformatted}"
      exit 1
    fi

    changed_pkgs="$(echo "${changed_go}" | xargs -n1 dirname | sort -u | sed 's|^|./|')"
    if [[ -n "${changed_pkgs}" ]]; then
      echo "Vetting changed packages"
      echo "${changed_pkgs}" | xargs go vet
    fi
  else
    echo "No changed Go files detected"
  fi

  run_emoji_check
}

case "${scope}" in
  all)
    run_all
    ;;
  changed)
    run_changed
    ;;
  *)
    echo "Usage: $0 [all|changed]"
    exit 2
    ;;
esac
