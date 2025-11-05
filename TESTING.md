# Eos Testing Guide

**Last Updated**: 2025-11-05

Comprehensive guide for running unit tests, integration tests, and security validation for the Eos project.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Test Categories](#test-categories)
3. [Prerequisites](#prerequisites)
4. [Unit Tests](#unit-tests)
5. [Integration Tests](#integration-tests)
6. [Pre-Commit Hook Tests](#pre-commit-hook-tests)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Environment Setup](#environment-setup)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Run all unit tests
go test -v ./pkg/...

# Run specific package tests
go test -v ./pkg/vault

# Run integration tests (requires setup)
go test -v -tags=integration ./pkg/vault

# Run pre-commit hook tests
./test_precommit_hook.sh

# Verify security checks
.git/hooks/pre-commit
```

---

## Test Categories

### 1. Unit Tests (`*_test.go` without build tags)

**Purpose**: Fast, isolated tests of individual functions
**Duration**: <5 seconds total
**Requirements**: Go 1.25.3+, no external dependencies

**Example**:
```bash
go test -v ./pkg/vault/cluster_token_security_test.go
```

**Coverage**: ~85% (target: 90%)

### 2. Integration Tests (`*_integration_test.go` with `// +build integration`)

**Purpose**: End-to-end tests with real Vault cluster
**Duration**: ~30-60 seconds total
**Requirements**: Go 1.25.3+, Vault cluster running, test token

**Example**:
```bash
# Set environment variables
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN_TEST="hvs.your_test_token_here"
export EOS_TEST_ENVIRONMENT="true"

# Run integration tests
go test -v -tags=integration ./pkg/vault
```

**Coverage**: Critical security paths (P0-1, P0-2, P0-3)

### 3. Pre-Commit Hook Tests (`test_precommit_hook.sh`)

**Purpose**: Validate security checks in pre-commit hook
**Duration**: ~10 seconds
**Requirements**: Git repository, bash, pre-commit hook installed

**Example**:
```bash
./test_precommit_hook.sh
```

**Coverage**: All 6 security checks + edge cases

### 4. Security Validation (Manual)

**Purpose**: Verify security fixes are working
**Duration**: ~5 minutes
**Requirements**: Running Vault cluster

**Steps**:
1. Verify token not in `ps auxe` output
2. Verify TLS validation enabled
3. Verify pre-commit hook blocks vulnerable code

---

## Prerequisites

### Required Software

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25.3+ | Compile and run tests |
| Vault | 1.12.0+ | Integration tests |
| Git | 2.0+ | Pre-commit hook tests |
| Bash | 4.0+ | Test scripts |

**Installation**:
```bash
# Check versions
go version          # Should be go1.25.3 or later
vault version       # Should be v1.12.0 or later
git --version       # Should be 2.0 or later
bash --version      # Should be 4.0 or later

# Install missing tools (Ubuntu/Debian)
sudo apt update
sudo apt install golang-1.25 vault git bash
```

### Environment Variables

```bash
# Required for integration tests
export VAULT_ADDR="https://localhost:8200"           # Vault server address
export VAULT_TOKEN_TEST="hvs.your_token_here"        # Test token (NOT root token)
export EOS_TEST_ENVIRONMENT="true"                   # Safety flag for destructive tests

# Optional for development
export VAULT_CACERT="/etc/vault/tls/ca.crt"          # CA certificate path
export VAULT_SKIP_VERIFY="1"                         # ONLY in dev (INSECURE)
export Eos_ALLOW_INSECURE_VAULT="true"               # Bypass TLS validation
```

**Security Note**: Never use root token for tests. Create a test token:
```bash
# Create test token with limited permissions
vault token create -ttl=1h -display-name="integration-tests" \
    -policy=eos-admin-policy

# Copy token to environment
export VAULT_TOKEN_TEST="hvs.CAESIJwZ..."
```

---

## Unit Tests

### Running Unit Tests

```bash
# Run all unit tests
go test -v ./pkg/...

# Run specific package
go test -v ./pkg/vault

# Run with coverage
go test -v -cover ./pkg/...

# Generate coverage report
go test -v -coverprofile=coverage.out ./pkg/...
go tool cover -html=coverage.out -o coverage.html
```

### P0-1 Unit Tests (Token Security)

**File**: `pkg/vault/cluster_token_security_test.go`

**Tests** (6 total):
1. `TestCreateTemporaryTokenFile` - Basic file creation
2. `TestTokenFileCleanup` - Defer cleanup verification
3. `TestTokenFileUnpredictableName` - Random filename generation
4. `TestTokenFileNotInEnvironment` - Environment variable isolation
5. `TestSanitizeTokenForLogging` - Token sanitization
6. `TestTokenFilePermissionsAfterWrite` - Race condition prevention

**Run**:
```bash
go test -v -run TestCreateTemporaryTokenFile ./pkg/vault
```

**Expected Output**:
```
=== RUN   TestCreateTemporaryTokenFile
✓ Token file created successfully
✓ Permissions correct: 0400
✓ Content matches token
--- PASS: TestCreateTemporaryTokenFile (0.01s)
PASS
```

---

## Integration Tests

### Environment Setup for Integration Tests

**1. Start Vault Cluster** (if not running):
```bash
# Start Vault in dev mode (for testing only)
vault server -dev -dev-root-token-id="root" &

# Or use existing cluster
export VAULT_ADDR="https://your-vault-cluster:8200"
```

**2. Create Test Token**:
```bash
# Login with root token (or your admin token)
vault login root

# Create test token
vault token create -ttl=1h -display-name="integration-tests" \
    -policy=eos-admin-policy

# Copy token to environment
export VAULT_TOKEN_TEST="hvs.CAESIJwZ..."
```

**3. Set Safety Flags**:
```bash
# Mark as test environment (prevents running destructive tests in production)
export EOS_TEST_ENVIRONMENT="true"
```

### Running Integration Tests

```bash
# Run all integration tests
go test -v -tags=integration ./pkg/vault

# Run specific integration test
go test -v -tags=integration -run TestTokenFileIntegration_RealFileCreation ./pkg/vault

# Run with timeout (some tests take longer)
go test -v -tags=integration -timeout=5m ./pkg/vault
```

### P0-1 Integration Tests (Token Security)

**File**: `pkg/vault/cluster_token_security_integration_test.go`

**Tests** (15 total):

| Test | Purpose | Duration |
|------|---------|----------|
| `TestTokenFileIntegration_RealFileCreation` | Real filesystem permissions | ~10ms |
| `TestTokenFileIntegration_UnpredictableNames` | Random file naming | ~50ms |
| `TestTokenFileIntegration_CleanupOnSuccess` | Cleanup verification | ~10ms |
| `TestTokenFileIntegration_CleanupOnError` | Error path cleanup | ~10ms |
| `TestTokenFileIntegration_PermissionsDenyOtherUsers` | Access control | ~10ms |
| `TestTokenFileIntegration_NoTokenInProcessEnvironment` | Environment isolation | ~20ms |
| `TestTokenFileIntegration_RaceConditionPrevention` | Race condition check | ~10ms |
| `TestTokenFileIntegration_WithRealVaultCommand` | Real Vault CLI test | ~500ms |
| `TestTokenFileIntegration_FileDescriptorLeak` | FD leak detection | ~100ms |
| `TestTokenFileIntegration_SELinuxCompatibility` | SELinux support | ~10ms |
| `TestTokenFileIntegration_TempDirFullHandling` | Error handling | ~10ms |
| `TestTokenFileIntegration_ConcurrentAccess` | Thread safety | ~100ms |
| `TestTokenFileIntegration_UmaskRespect` | Umask handling | ~10ms |

**Run**:
```bash
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN_TEST="hvs.your_token"
export EOS_TEST_ENVIRONMENT="true"

go test -v -tags=integration -run TestTokenFileIntegration ./pkg/vault
```

### P0-2 Integration Tests (TLS Validation)

**File**: `pkg/vault/phase2_env_setup_integration_test.go`

**Tests** (13 total):

| Test | Purpose | Duration |
|------|---------|----------|
| `TestCACertificateDiscovery_RealFilesystem` | CA cert discovery | ~10ms |
| `TestValidateCACertificate_RealPEMFiles` | PEM validation | ~50ms |
| `TestTLSConnection_WithValidCA` | TLS with CA cert | ~200ms |
| `TestTLSConnection_WithoutCA_ShouldFail` | Secure by default | ~200ms |
| `TestTLSConnection_InsecureSkipVerify_ShouldSucceed` | Insecure fallback | ~200ms |
| `TestEnsureVaultEnv_WithCA_ShouldNotSetSkipVerify` | P0-2 fix validation | ~10ms |
| `TestIsInteractiveTerminal` | TTY detection | ~1ms |
| `TestCanConnectTLS_WithTimeout` | Connection timeout | ~2s |
| `TestLocateVaultCACertificate_StandardPaths` | CA path discovery | ~10ms |
| `TestHandleTLSValidationFailure_NonInteractive` | Non-TTY behavior | ~1ms |
| `TestEnvironmentVariablePrecedence` | Env var priority | ~1ms |
| `TestCACertificateChainValidation` | Cert chain validation | ~10ms |
| `TestMITMAttackPrevention` | MITM protection | ~200ms |

**Run**:
```bash
export VAULT_ADDR="https://localhost:8200"
export VAULT_CACERT="/etc/vault/tls/ca.crt"

go test -v -tags=integration -run TestTLSConnection ./pkg/vault
```

### Cluster Operations Integration Tests

**File**: `pkg/vault/cluster_operations_integration_test.go`

**Tests** (11 total):

| Test | Purpose | Duration |
|------|---------|----------|
| `TestRaftAutopilot_Integration_WithTokenFile` | Full autopilot workflow | ~500ms |
| `TestGetAutopilotState_Integration_WithTokenFile` | State retrieval | ~200ms |
| `TestTakeRaftSnapshot_Integration_WithTokenFile` | Snapshot creation | ~2s |
| `TestRestoreRaftSnapshot_Integration_WithTokenFile` | Snapshot restore | ~3s |
| `TestTokenExposurePrevention_ProcessList` | P0-1: ps check | ~1s |
| `TestTokenExposurePrevention_ProcEnviron` | P0-1: /proc check | ~500ms |
| `TestTokenFileLeak_MultipleOperations` | Resource leak detection | ~2s |
| `TestClusterOperations_WithExpiredToken` | Error handling | ~200ms |
| `TestClusterOperations_ConcurrentSafety` | Concurrency test | ~1s |
| `TestRaftPeerRemoval_Integration` | Peer removal (destructive) | ~500ms |
| `TestVaultOperatorCommands_ShellInjectionPrevention` | Security test | ~500ms |

**Run**:
```bash
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN_TEST="hvs.your_token"
export EOS_TEST_ENVIRONMENT="true"

go test -v -tags=integration -run TestRaftAutopilot ./pkg/vault
```

**⚠️ WARNING**: Some tests are DESTRUCTIVE (`TestRestoreRaftSnapshot`, `TestRaftPeerRemoval`). Only run on test clusters with `EOS_TEST_ENVIRONMENT=true`.

---

## Pre-Commit Hook Tests

### Running Pre-Commit Hook Tests

```bash
# Run test suite
./test_precommit_hook.sh

# Expected output:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pre-Commit Hook Test Suite
# Testing all 6 security checks + edge cases
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# ... (test output) ...
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ✓ ALL TESTS PASSED
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Test Coverage

**10 Test Suites**:

1. **Hardcoded Secrets Detection** (3 tests)
   - Detects hardcoded passwords, API keys
   - Allows SecretManager usage

2. **VAULT_SKIP_VERIFY Detection** (3 tests)
   - Detects unconditional bypass
   - Allows P0-2 exceptions (handleTLSValidationFailure, Eos_ALLOW_INSECURE_VAULT)

3. **InsecureSkipVerify Detection** (2 tests)
   - Detects in production code
   - Allows in `*_test.go` files

4. **VAULT_TOKEN Environment Variables** (3 tests)
   - Detects VAULT_TOKEN in env
   - Allows VAULT_TOKEN_FILE (P0-1 fix)
   - Allows P0-1 comment exceptions

5. **Hardcoded File Permissions** (3 tests)
   - Detects `0755`, `0644`, etc.
   - Allows permission constants

6. **Security TODOs** (3 tests)
   - Detects `TODO(security)`, `FIXME(security)`
   - Allows regular TODOs

7. **No Go Files** (1 test)
   - Handles no Go files staged

8. **Multiple Violations** (1 test)
   - Detects multiple issues in single file

9. **Hook Bypass Prevention** (1 test)
   - Documents `--no-verify` bypass

10. **Performance Check** (1 test)
    - Verifies hook runs in <5 seconds

**Total Tests**: 21
**Expected Pass Rate**: 100%

### Manual Pre-Commit Hook Testing

```bash
# Test Check 1: Hardcoded secrets
echo 'const PASSWORD = "secret123"' > test_vuln.go
git add test_vuln.go
.git/hooks/pre-commit
# Expected: FAIL (hardcoded secret detected)

# Test Check 2: VAULT_SKIP_VERIFY
echo 'os.Setenv("VAULT_SKIP_VERIFY", "1")' > test_vuln.go
git add test_vuln.go
.git/hooks/pre-commit
# Expected: FAIL (unconditional VAULT_SKIP_VERIFY)

# Test Check 4: VAULT_TOKEN
echo 'cmd.Env = append(cmd.Env, fmt.Sprintf("VAULT_TOKEN=%s", token))' > test_vuln.go
git add test_vuln.go
.git/hooks/pre-commit
# Expected: FAIL (VAULT_TOKEN in environment)

# Test secure pattern (should pass)
echo 'cmd.Env = append(cmd.Env, fmt.Sprintf("VAULT_TOKEN_FILE=%s", file))' > test_secure.go
git add test_secure.go
.git/hooks/pre-commit
# Expected: PASS (VAULT_TOKEN_FILE is secure)

# Cleanup
git reset HEAD -- test_vuln.go test_secure.go
rm -f test_vuln.go test_secure.go
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

**File**: `.github/workflows/security.yml`

**Triggers**:
- Pull requests to `main` or `develop`
- Push to `main`
- Weekly schedule (Sundays at 2 AM UTC)

**Jobs**:

#### Job 1: Security Audit

**Steps**:
1. Checkout code
2. Setup Go 1.25.3
3. Run `gosec` (Go security scanner)
4. Run `govulncheck` (CVE scanner)
5. Run custom security checks (same as pre-commit hook)
6. Upload SARIF results to GitHub Security tab

**Duration**: ~2-3 minutes

**Example**:
```yaml
- name: Run gosec
  run: |
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    gosec -fmt=sarif -out=gosec-results.sarif -severity=medium ./...

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: gosec-results.sarif
```

#### Job 2: Secret Scanning

**Steps**:
1. Checkout code with full history
2. Run TruffleHog secret scanner
3. Upload results to GitHub Security tab

**Duration**: ~1-2 minutes

**Example**:
```yaml
- name: TruffleHog Secret Scan
  uses: trufflesecurity/trufflehog@main
  with:
    path: ./
    base: ${{ github.event.repository.default_branch }}
    head: HEAD
```

### Viewing CI/CD Results

```bash
# View workflow runs (requires gh CLI)
gh workflow list
gh workflow view "Security Validation"
gh run list --workflow=security.yml

# View latest run
gh run view --log

# View security alerts (web UI)
# Navigate to: https://github.com/<user>/<repo>/security/code-scanning
```

---

## Environment Setup

### Development Environment

**1. Clone Repository**:
```bash
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
```

**2. Install Dependencies**:
```bash
# Go dependencies
go mod download

# Vault (if not installed)
wget https://releases.hashicorp.com/vault/1.12.0/vault_1.12.0_linux_amd64.zip
unzip vault_1.12.0_linux_amd64.zip
sudo mv vault /usr/local/bin/
```

**3. Install Pre-Commit Hook**:
```bash
# Hook is already in .git/hooks/pre-commit
# Make sure it's executable
chmod +x .git/hooks/pre-commit

# Test hook
.git/hooks/pre-commit
```

**4. Setup Vault for Testing**:
```bash
# Start Vault in dev mode
vault server -dev -dev-root-token-id="root" &

# Configure environment
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN_TEST="root"
export EOS_TEST_ENVIRONMENT="true"

# Verify connection
vault status
```

### CI/CD Environment

**Required Secrets** (GitHub):
```
VAULT_ADDR            # Vault test cluster address
VAULT_TOKEN_TEST      # Test token (NOT root token)
```

**Set via**:
```bash
gh secret set VAULT_ADDR -b "https://vault-test.example.com:8200"
gh secret set VAULT_TOKEN_TEST -b "hvs.CAESIJwZ..."
```

---

## Troubleshooting

### Go Version Mismatch

**Problem**: `go.mod` requires Go 1.25.3, but system has 1.24.7

**Error**:
```
go: go.mod requires go >= 1.25.3; switching to go 1.24.7
```

**Solution**:
```bash
# Install Go 1.25.3
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-1.25

# Verify version
go version  # Should show go1.25.3
```

### Vault Not Running

**Problem**: Integration tests skip with "Vault server not responding"

**Error**:
```
--- SKIP: TestRaftAutopilot_Integration_WithTokenFile
    Vault server not responding: connection refused
```

**Solution**:
```bash
# Start Vault in dev mode
vault server -dev -dev-root-token-id="root" &

# Or check existing Vault status
vault status

# Verify VAULT_ADDR
echo $VAULT_ADDR
# Should be: http://127.0.0.1:8200 (dev) or https://your-vault:8200 (prod)
```

### Token Not Set

**Problem**: Integration tests skip with "VAULT_TOKEN_TEST not set"

**Error**:
```
--- SKIP: TestGetAutopilotState_Integration_WithTokenFile
    VAULT_TOKEN_TEST not set, skipping test requiring authentication
```

**Solution**:
```bash
# Create test token
vault token create -ttl=1h -display-name="tests"

# Set environment variable
export VAULT_TOKEN_TEST="hvs.CAESIJwZ..."

# Verify
echo $VAULT_TOKEN_TEST
```

### Pre-Commit Hook Not Running

**Problem**: Pre-commit hook doesn't execute on `git commit`

**Diagnosis**:
```bash
# Check if hook exists
ls -la .git/hooks/pre-commit

# Check if executable
test -x .git/hooks/pre-commit && echo "Executable" || echo "Not executable"
```

**Solution**:
```bash
# Make executable
chmod +x .git/hooks/pre-commit

# Test manually
.git/hooks/pre-commit
```

### Tests Timing Out

**Problem**: Integration tests timeout after 2 minutes

**Error**:
```
panic: test timed out after 2m0s
```

**Solution**:
```bash
# Increase timeout
go test -v -tags=integration -timeout=10m ./pkg/vault
```

### Permission Denied

**Problem**: Cannot write snapshot file

**Error**:
```
failed to create snapshot: permission denied
```

**Solution**:
```bash
# Use writable directory
export VAULT_SNAPSHOT_PATH="/tmp/vault-snapshot.snap"

# Or run with sudo (if required)
sudo -E go test -v -tags=integration ./pkg/vault
```

---

## Appendix: Test Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `VAULT_ADDR` | Yes | `http://127.0.0.1:8200` | Vault server address |
| `VAULT_TOKEN_TEST` | Yes | (none) | Test token for authentication |
| `EOS_TEST_ENVIRONMENT` | Yes | (none) | Safety flag for destructive tests |
| `VAULT_CACERT` | No | (discovered) | CA certificate path |
| `VAULT_SKIP_VERIFY` | No | `0` | Skip TLS verification (DEV ONLY) |
| `Eos_ALLOW_INSECURE_VAULT` | No | `false` | Allow insecure Vault (DEV ONLY) |
| `VAULT_TEST_PEER_ID` | No | (none) | Test peer ID for removal tests |

---

## Appendix: Test File Naming Conventions

| Pattern | Build Tag | Purpose | Example |
|---------|-----------|---------|---------|
| `*_test.go` | (none) | Unit tests | `cluster_token_security_test.go` |
| `*_integration_test.go` | `// +build integration` | Integration tests | `cluster_token_security_integration_test.go` |
| `test_*.sh` | N/A | Test scripts | `test_precommit_hook.sh` |

---

## Appendix: Performance Benchmarks

```bash
# Run benchmarks
go test -v -bench=. ./pkg/vault

# Example results:
# BenchmarkTokenFileCreation-8         10000    105234 ns/op
# BenchmarkTokenFileVsEnvVar-8         5000     234567 ns/op
```

**Expected Performance**:
- Token file creation: <200μs per operation
- Token file vs env var: ~2x slower (acceptable security tradeoff)
- Pre-commit hook: <5s for 1000-line file

---

**For Questions**: See `SECURITY_HARDENING_SESSION_COMPLETE.md` or contact Code Monkey Cybersecurity

*"Cybersecurity. With humans."*
