#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ -z "${mode}" ]]; then
  echo "Usage: $0 <unit|integration|e2e-smoke|e2e-full|fuzz>"
  exit 2
fi

SUITE_FILE="${CI_SUITE_FILE:-test/ci/suites.yaml}"
lane_dir="outputs/ci/${mode}"
mkdir -p "${lane_dir}"

run_with_timeout() {
  local limit="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=15s "${limit}" "$@"
  else
    "$@"
  fi
}

changed_files_path="${lane_dir}/changed-files.txt"
write_changed_files() {
  : > "${changed_files_path}"
  local ci_event="${CI_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
  local base_ref="${CI_BASE_REF:-${GITHUB_BASE_REF:-}}"

  if [[ "${ci_event}" != "pull_request" || -z "${base_ref}" ]]; then
    return 0
  fi

  git fetch origin "${base_ref}" --depth=1 >/dev/null 2>&1 || true
  local base_rev
  base_rev="$(git rev-parse "origin/${base_ref}" 2>/dev/null || true)"
  if [[ -z "${base_rev}" ]]; then
    return 0
  fi

  git diff --name-only "${base_rev}"...HEAD > "${changed_files_path}" || true
}

run_unit() {
  echo "Running unit lane"
  local unit_jsonl race_jsonl coverage_file
  unit_jsonl="${lane_dir}/unit-test.jsonl"
  race_jsonl="${lane_dir}/unit-race.jsonl"
  coverage_file="${lane_dir}/coverage.out"

  run_with_timeout 8m go build -o /tmp/eos-build ./cmd/

  run_with_timeout 20m bash -c \
    "set -euo pipefail; go test -json -short -count=1 -vet=off -coverprofile='${coverage_file}' -covermode=atomic -p 4 ./pkg/... | tee '${unit_jsonl}'; test \${PIPESTATUS[0]} -eq 0"

  run_with_timeout 15m bash -c \
    "set -euo pipefail; go test -json -short -count=1 -race -vet=off ./pkg/crypto/... ./pkg/interaction/... ./pkg/parse/... ./pkg/verify/... | tee '${race_jsonl}'; test \${PIPESTATUS[0]} -eq 0"

  local coverage threshold
  coverage="$(go tool cover -func="${coverage_file}" | awk '/^total:/ {gsub("%","",$3); print $3}')"
  threshold="$(go run ./test/ci/tool policy-threshold "${SUITE_FILE}" unit 70)"
  if [[ -z "${coverage}" ]]; then
    echo "::error::Unable to parse coverage from ${coverage_file}"
    exit 1
  fi

  echo "Unit coverage: ${coverage}% (threshold: ${threshold}%)"
  awk -v cov="${coverage}" -v min="${threshold}" 'BEGIN { if (cov < min) exit 1 }' || {
    echo "::error::Coverage ${coverage}% is below ${threshold}%"
    exit 1
  }

  scripts/ci/coverage-delta.sh "${coverage_file}"
}

run_integration() {
  echo "Running integration lane"

  write_changed_files

  local ci_event should_run
  ci_event="${CI_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
  should_run="$(go run ./test/ci/tool policy-should-run "${SUITE_FILE}" integration "${ci_event}" "${changed_files_path}" default-true)"
  if [[ "${should_run}" != "true" ]]; then
    echo "Integration lane skipped by policy with reason: optional for this change set"
    echo "skipped:optional_by_policy" > "${lane_dir}/integration.status"
    return 0
  fi

  local run_id network_name vault_container pg_container
  run_id="${GITHUB_RUN_ID:-local}-$$"
  network_name="eos-ci-net-${run_id}"
  vault_container="vault-ci-${run_id}"
  pg_container="postgres-ci-${run_id}"

  cleanup() {
    docker rm -f "${vault_container}" "${pg_container}" >/dev/null 2>&1 || true
    docker network rm "${network_name}" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  # Remove any leftover containers from a previous aborted run with the same run_id.
  cleanup
  docker network create "${network_name}" >/dev/null

  docker run -d --name "${vault_container}" \
    --network "${network_name}" \
    -p 127.0.0.1::8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=test-token \
    -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    --cap-add=IPC_LOCK \
    hashicorp/vault:1.16@sha256:c5e04689611cb864b8b6247a6a845e0bdc059998f39b5c8a659562287379525c >/dev/null

  docker run -d --name "${pg_container}" \
    --network "${network_name}" \
    -p 127.0.0.1::5432 \
    -e POSTGRES_PASSWORD=testpass \
    -e POSTGRES_DB=testdb \
    postgres:15@sha256:dafc4d8e8369da730a5ee9a320a0f0b3c6aa516f41244689c4493a27dc84472d >/dev/null

  local vault_port pg_port vault_addr
  vault_port="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "8200/tcp") 0).HostPort}}' "${vault_container}")" || true
  pg_port="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "${pg_container}")" || true

  if [[ -z "${vault_port}" || ! "${vault_port}" =~ ^[0-9]+$ ]]; then
    echo "::error::Failed to extract valid Vault port (got '${vault_port}')"
    docker logs "${vault_container}" 2>&1 || true
    exit 1
  fi
  if [[ -z "${pg_port}" || ! "${pg_port}" =~ ^[0-9]+$ ]]; then
    echo "::error::Failed to extract valid PostgreSQL port (got '${pg_port}')"
    docker logs "${pg_container}" 2>&1 || true
    exit 1
  fi

  vault_addr=""
  for _ in $(seq 1 30); do
    if curl -sf --connect-timeout 3 "http://127.0.0.1:${vault_port}/v1/sys/health" >/dev/null 2>&1; then
      vault_addr="http://127.0.0.1:${vault_port}"
      break
    fi
    sleep 2
  done

  if [[ -z "${vault_addr}" ]]; then
    echo "::error::Vault failed to become reachable"
    docker logs "${vault_container}" || true
    exit 1
  fi

  for _ in $(seq 1 30); do
    if docker exec "${pg_container}" pg_isready -U postgres >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  docker exec "${pg_container}" pg_isready -U postgres >/dev/null 2>&1 || {
    echo "::error::PostgreSQL failed to become ready"
    docker logs "${pg_container}" || true
    exit 1
  }

  export VAULT_ADDR="${vault_addr}"
  export VAULT_TOKEN="test-token"
  export POSTGRES_URL="postgres://postgres:testpass@127.0.0.1:${pg_port}/testdb?sslmode=disable"

  run_with_timeout 20m bash -c \
    "set -euo pipefail; go test -json -v -timeout=15m ./test/integration_test.go ./test/integration_scenarios_test.go | tee '${lane_dir}/integration-suite.jsonl'; test \${PIPESTATUS[0]} -eq 0"
  run_with_timeout 20m bash -c \
    "set -euo pipefail; go test -json -v -timeout=15m -run Integration ./pkg/backup/... | tee '${lane_dir}/integration-backup.jsonl'; test \${PIPESTATUS[0]} -eq 0"
  run_with_timeout 20m bash -c \
    "set -euo pipefail; go test -json -v -timeout=15m -tags=integration ./pkg/vault/... | tee '${lane_dir}/integration-vault.jsonl'; test \${PIPESTATUS[0]} -eq 0"
}

run_e2e_smoke() {
  echo "Running e2e smoke lane"
  run_with_timeout 15m bash -c \
    "set -euo pipefail; go test -json -v -tags=e2e_smoke -timeout=10m ./test/e2e/smoke/... | tee '${lane_dir}/e2e-smoke.jsonl'; test \${PIPESTATUS[0]} -eq 0"
}

run_e2e_full() {
  echo "Running e2e full lane"
  export EOS_E2E_FULL_APPROVED="true"
  run_with_timeout 75m bash -c \
    "set -euo pipefail; go test -json -v -tags=e2e_full -timeout=60m ./test/e2e/full/... | tee '${lane_dir}/e2e-full.jsonl'; test \${PIPESTATUS[0]} -eq 0"
}

run_fuzz() {
  echo "Running bounded fuzz lane"

  for func_name in FuzzValidateStrongPassword FuzzHashString FuzzHashStrings FuzzAllUnique FuzzAllHashesPresent FuzzRedact FuzzInjectSecretsFromPlaceholders FuzzSecureZero; do
    run_with_timeout 3m bash -c "set -euo pipefail; go test -json -run=^${func_name}$ -fuzz=^${func_name}$ -fuzztime=5s ./pkg/crypto | tee -a '${lane_dir}/fuzz-crypto.jsonl'; test \${PIPESTATUS[0]} -eq 0"
  done

  for func_name in FuzzValidateNonEmpty FuzzValidateUsername FuzzValidateEmail FuzzValidateURL FuzzValidateIP FuzzValidateNoShellMeta; do
    run_with_timeout 3m bash -c "set -euo pipefail; go test -json -run=^${func_name}$ -fuzz=^${func_name}$ -fuzztime=5s ./pkg/interaction | tee -a '${lane_dir}/fuzz-interaction.jsonl'; test \${PIPESTATUS[0]} -eq 0"
  done

  run_with_timeout 3m bash -c \
    "set -euo pipefail; go test -json -run=^FuzzSplitAndTrim$ -fuzz=^FuzzSplitAndTrim$ -fuzztime=5s ./pkg/parse | tee '${lane_dir}/fuzz-parse.jsonl'; test \${PIPESTATUS[0]} -eq 0"
}

case "${mode}" in
  unit)
    run_unit
    ;;
  integration)
    run_integration
    ;;
  e2e-smoke)
    run_e2e_smoke
    ;;
  e2e-full)
    run_e2e_full
    ;;
  fuzz)
    run_fuzz
    ;;
  *)
    echo "Unsupported mode: ${mode}"
    exit 2
    ;;
esac
