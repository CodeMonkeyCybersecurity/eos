#!/usr/bin/env bash
# submodule-bootstrap.sh — Idempotent prompts submodule initialisation.
#
# Ensures the prompts submodule is initialised, synced, and up-to-date.
# Handles the chicken-and-egg problem: scripts inside the submodule
# can't run until the submodule is cloned.
#
# Usage:
#   bash scripts/submodule-bootstrap.sh          # init + update to pinned SHA
#   bash scripts/submodule-bootstrap.sh --remote  # init + update to latest main
#   bash scripts/submodule-bootstrap.sh --status   # check status only (no changes)
#
# Sensible defaults:
#   - Uses HTTPS URL matching the main repo's remote (gitea.cybermonkey.sh)
#   - Updates to pinned SHA by default (--remote for latest)
#   - Idempotent: safe to run multiple times
#   - Non-destructive: never force-resets local changes
#
# Exit codes:
#   0 — success (submodule initialised or already up-to-date)
#   1 — failure (network, permissions, corrupt state)
#   2 — usage error

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SUBMODULE_PATH="prompts"
SYMLINK_PATH="third_party/prompts"
EXPECTED_URL="https://gitea.cybermonkey.sh/cybermonkey/prompts.git"

# Defaults
UPDATE_REMOTE=false
STATUS_ONLY=false

# --- Logging ----------------------------------------------------------------

log_info()  { echo "[INFO]  $*" >&2; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# --- Argument parsing -------------------------------------------------------

for arg in "$@"; do
  case "${arg}" in
    --remote) UPDATE_REMOTE=true ;;
    --status) STATUS_ONLY=true ;;
    -h|--help)
      echo "Usage: $0 [--remote] [--status]"
      echo "  --remote  Update submodule to latest upstream main"
      echo "  --status  Check status only (no changes)"
      exit 0
      ;;
    *)
      log_error "Unknown argument: ${arg}"
      echo "Usage: $0 [--remote] [--status]" >&2
      exit 2
      ;;
  esac
done

# --- Functions --------------------------------------------------------------

check_gitmodules() {
  local gitmodules="${REPO_ROOT}/.gitmodules"
  if [[ ! -f "${gitmodules}" ]]; then
    log_error ".gitmodules not found at ${gitmodules}"
    return 1
  fi

  if ! grep -q "\[submodule \"${SUBMODULE_PATH}\"\]" "${gitmodules}"; then
    log_error "Submodule '${SUBMODULE_PATH}' not registered in .gitmodules"
    return 1
  fi
  return 0
}

check_url_matches() {
  local current_url
  current_url="$(git config --file "${REPO_ROOT}/.gitmodules" "submodule.${SUBMODULE_PATH}.url" 2>/dev/null || true)"

  if [[ -z "${current_url}" ]]; then
    log_error "No URL configured for submodule '${SUBMODULE_PATH}'"
    return 1
  fi

  if [[ "${current_url}" != "${EXPECTED_URL}" ]]; then
    log_warn "Submodule URL mismatch"
    log_warn "  current:  ${current_url}"
    log_warn "  expected: ${EXPECTED_URL}"
    log_info "Run 'git submodule sync' to propagate .gitmodules URL to local config"
    return 1
  fi
  return 0
}

is_initialized() {
  local submodule_dir="${REPO_ROOT}/${SUBMODULE_PATH}"
  # A submodule is initialized if its directory exists and contains files
  [[ -d "${submodule_dir}/.git" ]] || [[ -f "${submodule_dir}/.git" ]]
}

check_symlink() {
  local symlink="${REPO_ROOT}/${SYMLINK_PATH}"
  if [[ -L "${symlink}" ]]; then
    local target
    target="$(readlink "${symlink}")"
    if [[ "${target}" == "../${SUBMODULE_PATH}" ]]; then
      return 0
    else
      log_warn "Symlink ${SYMLINK_PATH} points to '${target}', expected '../${SUBMODULE_PATH}'"
      return 1
    fi
  elif [[ -e "${symlink}" ]]; then
    log_warn "${SYMLINK_PATH} exists but is not a symlink"
    return 1
  else
    log_warn "Symlink ${SYMLINK_PATH} does not exist"
    return 1
  fi
}

print_status() {
  log_info "=== Prompts Submodule Status ==="

  if check_gitmodules; then
    log_info ".gitmodules: OK (submodule registered)"
  fi

  if check_url_matches; then
    log_info "URL: OK (${EXPECTED_URL})"
  fi

  if is_initialized; then
    local sha
    sha="$(cd "${REPO_ROOT}/${SUBMODULE_PATH}" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
    log_info "Initialized: YES (HEAD: ${sha})"

    # Check if up-to-date with remote
    local remote_sha
    remote_sha="$(cd "${REPO_ROOT}/${SUBMODULE_PATH}" && git ls-remote origin HEAD 2>/dev/null | cut -f1 | head -c7 || echo "unknown")"
    if [[ "${sha}" == "${remote_sha}" ]]; then
      log_info "Freshness: UP-TO-DATE"
    else
      log_info "Freshness: STALE (local: ${sha}, remote: ${remote_sha})"
    fi
  else
    log_warn "Initialized: NO"
  fi

  if check_symlink; then
    log_info "Symlink: OK (${SYMLINK_PATH} -> ../${SUBMODULE_PATH})"
  fi
}

init_submodule() {
  log_info "Syncing submodule URL from .gitmodules..."
  cd "${REPO_ROOT}"
  git submodule sync "${SUBMODULE_PATH}" 2>&1

  log_info "Initializing and updating submodule '${SUBMODULE_PATH}'..."
  if ! git submodule update --init --recursive "${SUBMODULE_PATH}" 2>&1; then
    log_error "Failed to initialize submodule. Check network connectivity to ${EXPECTED_URL}"
    return 1
  fi

  local sha
  sha="$(cd "${REPO_ROOT}/${SUBMODULE_PATH}" && git rev-parse --short HEAD)"
  log_info "Submodule initialized at ${sha}"
}

update_to_remote() {
  log_info "Updating submodule to latest remote main..."
  cd "${REPO_ROOT}"

  if ! git submodule update --remote "${SUBMODULE_PATH}" 2>&1; then
    log_error "Failed to update submodule to latest remote"
    return 1
  fi

  local sha
  sha="$(cd "${REPO_ROOT}/${SUBMODULE_PATH}" && git rev-parse --short HEAD)"
  log_info "Submodule updated to ${sha}"
}

# --- Main -------------------------------------------------------------------

cd "${REPO_ROOT}"

# Step 1: Verify .gitmodules
if ! check_gitmodules; then
  exit 1
fi

# Step 2: Status-only mode
if [[ "${STATUS_ONLY}" == true ]]; then
  print_status
  exit 0
fi

# Step 3: Check and fix URL if needed
if ! check_url_matches; then
  log_info "URL mismatch detected — syncing..."
  git submodule sync "${SUBMODULE_PATH}" 2>&1
fi

# Step 4: Initialize if needed
if ! is_initialized; then
  init_submodule
else
  log_info "Submodule already initialized"
  # Still sync in case URL changed
  git submodule sync "${SUBMODULE_PATH}" 2>&1
  git submodule update --init --recursive "${SUBMODULE_PATH}" 2>&1
fi

# Step 5: Update to remote if requested
if [[ "${UPDATE_REMOTE}" == true ]]; then
  update_to_remote
fi

# Step 6: Verify symlink
if ! check_symlink; then
  log_warn "Symlink ${SYMLINK_PATH} needs attention (not auto-fixing — may require git add)"
fi

# Step 7: Final status
print_status
log_info "Submodule bootstrap complete"
