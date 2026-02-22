#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ -z "${mode}" ]]; then
  echo "Usage: $0 <unit|integration|e2e-smoke|e2e-full|fuzz>"
  exit 2
fi

mkdir -p outputs/ci

run_with_timeout() {
  local limit="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=15s "${limit}" "$@"
  else
    "$@"
  fi
}

is_integration_relevant_pr() {
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

  local changed
  changed="$(git diff --name-only "${base_rev}"...HEAD || true)"

  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    case "${path}" in
      test/integration*|pkg/vault/*|pkg/backup/*|scripts/ci/*|.github/workflows/ci.yml)
        return 0
        ;;
    esac
  done <<< "${changed}"

  return 1
}

run_unit() {
  echo "Running unit lane"
  run_with_timeout 8m go build -o /tmp/eos-build ./cmd/

  run_with_timeout 20m bash -c \
    'set -euo pipefail; go test -json -short -count=1 -vet=off -coverprofile=coverage.out -covermode=atomic -p 4 ./pkg/... | tee outputs/ci/unit-test.jsonl; test ${PIPESTATUS[0]} -eq 0'

  run_with_timeout 15m bash -c \
    'set -euo pipefail; go test -json -short -count=1 -race -vet=off ./pkg/crypto/... ./pkg/interaction/... ./pkg/parse/... ./pkg/verify/... | tee outputs/ci/unit-race.jsonl; test ${PIPESTATUS[0]} -eq 0'

  local coverage
  coverage="$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
  if [[ -z "${coverage}" ]]; then
    echo "::error::Unable to parse coverage from coverage.out"
    exit 1
  fi
  echo "Unit coverage: ${coverage}%"
  awk -v cov="${coverage}" 'BEGIN { if (cov < 70.0) exit 1 }' || {
    echo "::error::Coverage ${coverage}% is below 70%"
    exit 1
  }
}

run_integration() {
  echo "Running integration lane"
  if ! is_integration_relevant_pr; then
    echo "Integration lane skipped: no integration-owned file changes on PR"
    echo "skipped" > outputs/ci/integration.status
    return 0
  fi

  cleanup() {
    docker rm -f vault-ci postgres-ci >/dev/null 2>&1 || true
    docker network rm eos-ci-net >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  cleanup

  docker run -d --name vault-ci \
    -p 18200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=test-token \
    -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    --cap-add=IPC_LOCK \
    hashicorp/vault:1.16 >/dev/null

  docker run -d --name postgres-ci \
    -p 15432:5432 \
    -e POSTGRES_PASSWORD=testpass \
    -e POSTGRES_DB=testdb \
    postgres:15 >/dev/null

  local vault_cip pg_cip gw_ip vault_addr pg_addr vault_host
  vault_cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vault-ci)"
  pg_cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' postgres-ci)"
  gw_ip="$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo 172.17.0.1)"

  vault_addr=""
  for addr in "${vault_cip}:8200" "${gw_ip}:18200" "127.0.0.1:18200" "localhost:18200"; do
    if curl -sf --connect-timeout 3 "http://${addr}/v1/sys/health" >/dev/null 2>&1; then
      vault_addr="http://${addr}"
      break
    fi
  done

  if [[ -z "${vault_addr}" ]]; then
    for _ in $(seq 1 30); do
      for addr in "${vault_cip}:8200" "${gw_ip}:18200" "127.0.0.1:18200"; do
        if curl -sf --connect-timeout 3 "http://${addr}/v1/sys/health" >/dev/null 2>&1; then
          vault_addr="http://${addr}"
          break 2
        fi
      done
      sleep 2
    done
  fi

  if [[ -z "${vault_addr}" ]]; then
    echo "::error::Vault failed to become reachable"
    docker logs vault-ci || true
    exit 1
  fi

  for _ in $(seq 1 30); do
    if docker exec postgres-ci pg_isready -U postgres >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  docker exec postgres-ci pg_isready -U postgres >/dev/null 2>&1 || {
    echo "::error::PostgreSQL failed to become ready"
    docker logs postgres-ci || true
    exit 1
  }

  vault_host="$(echo "${vault_addr}" | sed 's|http://||' | cut -d: -f1)"
  if [[ "${vault_host}" == "${vault_cip}" ]]; then
    pg_addr="${pg_cip}:5432"
  elif [[ "${vault_host}" == "${gw_ip}" ]]; then
    pg_addr="${gw_ip}:15432"
  else
    pg_addr="127.0.0.1:15432"
  fi

  export VAULT_ADDR="${vault_addr}"
  export VAULT_TOKEN="test-token"
  export POSTGRES_URL="postgres://postgres:testpass@${pg_addr}/testdb?sslmode=disable"

  run_with_timeout 20m bash -c \
    'set -euo pipefail; go test -json -v -timeout=15m ./test/integration_test.go ./test/integration_scenarios_test.go | tee outputs/ci/integration-suite.jsonl; test ${PIPESTATUS[0]} -eq 0'
  run_with_timeout 20m bash -c \
    'set -euo pipefail; go test -json -v -timeout=15m -run Integration ./pkg/backup/... | tee outputs/ci/integration-backup.jsonl; test ${PIPESTATUS[0]} -eq 0'
  run_with_timeout 20m bash -c \
    'set -euo pipefail; go test -json -v -timeout=15m -tags=integration ./pkg/vault/... | tee outputs/ci/integration-vault.jsonl; test ${PIPESTATUS[0]} -eq 0'
}

run_e2e_smoke() {
  echo "Running e2e smoke lane"
  run_with_timeout 15m bash -c \
    'set -euo pipefail; go test -json -v -tags=e2e_smoke -timeout=10m ./test/e2e/smoke/... | tee outputs/ci/e2e-smoke.jsonl; test ${PIPESTATUS[0]} -eq 0'
}

run_e2e_full() {
  echo "Running e2e full lane"
  export EOS_E2E_FULL_APPROVED="true"
  run_with_timeout 75m bash -c \
    'set -euo pipefail; go test -json -v -tags=e2e_full -timeout=60m ./test/e2e/full/... | tee outputs/ci/e2e-full.jsonl; test ${PIPESTATUS[0]} -eq 0'
}

run_fuzz() {
  echo "Running bounded fuzz lane"

  for func_name in FuzzValidateStrongPassword FuzzHashString FuzzHashStrings FuzzAllUnique FuzzAllHashesPresent FuzzRedact FuzzInjectSecretsFromPlaceholders FuzzSecureZero; do
    run_with_timeout 3m bash -c "set -euo pipefail; go test -json -run=^${func_name}$ -fuzz=^${func_name}$ -fuzztime=5s ./pkg/crypto | tee -a outputs/ci/fuzz-crypto.jsonl; test \\${PIPESTATUS[0]} -eq 0"
  done

  for func_name in FuzzValidateNonEmpty FuzzValidateUsername FuzzValidateEmail FuzzValidateURL FuzzValidateIP FuzzValidateNoShellMeta; do
    run_with_timeout 3m bash -c "set -euo pipefail; go test -json -run=^${func_name}$ -fuzz=^${func_name}$ -fuzztime=5s ./pkg/interaction | tee -a outputs/ci/fuzz-interaction.jsonl; test \\${PIPESTATUS[0]} -eq 0"
  done

  run_with_timeout 3m bash -c \
    'set -euo pipefail; go test -json -run=^FuzzSplitAndTrim$ -fuzz=^FuzzSplitAndTrim$ -fuzztime=5s ./pkg/parse | tee outputs/ci/fuzz-parse.jsonl; test ${PIPESTATUS[0]} -eq 0'
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
