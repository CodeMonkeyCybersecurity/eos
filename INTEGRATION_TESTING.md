# Integration Testing Guide

*Last Updated: 2025-11-05*

Comprehensive guide for running, writing, and debugging integration tests in Eos.

---

## Table of Contents

- [Overview](#overview)
- [Test Types in Eos](#test-types-in-eos)
- [Running Integration Tests](#running-integration-tests)
- [Test Environment Setup](#test-environment-setup)
- [Writing Integration Tests](#writing-integration-tests)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)
- [Best Practices](#best-practices)

---

## Overview

### What is Integration Testing?

Integration tests verify that multiple components of Eos work together correctly. Unlike unit tests (which test isolated functions), integration tests:

- Test **complete workflows** (e.g., create Vault → configure → verify health)
- Interact with **real or mocked services** (Vault, Consul, Docker, etc.)
- Verify **system behavior** under realistic conditions
- Catch **interface mismatches** between components

### Integration Test Philosophy

Following Eos's human-centric philosophy:

**Assess → Intervene → Evaluate**
- **Assess**: Check preconditions (services available, config valid)
- **Intervene**: Execute the operation (create/update/delete)
- **Evaluate**: Verify postconditions (service running, config applied)

**Fast Feedback**: Integration tests should fail quickly with actionable errors.

**Graceful Degradation**: Tests should work with or without external services (use mocks when services unavailable).

---

## Test Types in Eos

| Type | Purpose | Duration | When to Run |
|------|---------|----------|-------------|
| **Unit Tests** | Test individual functions in isolation | <1s per file | Every commit (pre-commit hook) |
| **Integration Tests** | Test component interactions | 5-60s per test | Before PR, in CI |
| **E2E Tests** | Test complete user workflows | 1-10min per test | Before merge, nightly |
| **Fuzz Tests** | Security-focused randomized testing | 5s-8hrs | Every PR (5s), nightly (8hrs) |
| **Platform Tests** | Verify cross-platform compatibility | <5s per file | Every build |

---

## Running Integration Tests

### Quick Start (Local Development)

```bash
# Run all integration tests
go test -v ./test/...

# Run specific integration test file
go test -v ./test/integration_test.go

# Run specific test function
go test -v -run TestEosIntegration_VaultAuthenticationWorkflow ./test/...

# Run with race detector (recommended)
go test -v -race ./test/...

# Run with timeout (prevents hanging tests)
go test -v -timeout=10m ./test/...
```

### Run with Coverage

```bash
# Generate coverage report
go test -v -coverprofile=coverage.out ./test/...

# View coverage in browser
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out | grep total
```

### Filter by Test Scenario

```bash
# Run only Vault-related tests
go test -v -run Vault ./test/...

# Run only authentication tests
go test -v -run Authentication ./test/...

# Skip slow tests (requires -short flag support)
go test -short -v ./test/...
```

---

## Test Environment Setup

### Minimal Setup (Unit + Integration Tests)

No external services required - integration tests use mocks:

```bash
# 1. Install Go (1.22+)
sudo apt install golang-1.22

# 2. Clone Eos
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

# 3. Run tests
go test -v ./test/...
```

**Status**: ✓ Works on any platform (Linux, macOS, Windows)

### Full Setup (With Real Services)

For testing against real Vault, Consul, etc.:

#### Prerequisites

```bash
# Install Docker + Docker Compose
sudo apt install -y docker.io docker-compose-v2

# Install Vault CLI (for manual testing)
wget -O /tmp/vault.zip https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
sudo unzip /tmp/vault.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/vault

# Install Consul CLI (for manual testing)
wget -O /tmp/consul.zip https://releases.hashicorp.com/consul/1.17.0/consul_1.17.0_linux_amd64.zip
sudo unzip /tmp/consul.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/consul
```

#### Start Test Services

**Option 1: Docker Compose** (Recommended)

```bash
# Create docker-compose.yml for test services
cat <<EOF > /tmp/eos-test-services.yml
version: '3.8'

services:
  vault-test:
    image: hashicorp/vault:1.15
    container_name: eos-test-vault
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: "eos-test-root-token"
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
    cap_add:
      - IPC_LOCK
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 5s
      timeout: 3s
      retries: 5

  consul-test:
    image: hashicorp/consul:1.17
    container_name: eos-test-consul
    ports:
      - "8500:8500"
    command: "agent -dev -client=0.0.0.0"
    healthcheck:
      test: ["CMD", "consul", "info"]
      interval: 5s
      timeout: 3s
      retries: 5

  postgres-test:
    image: postgres:16-alpine
    container_name: eos-test-postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: "eos-test-password"
      POSTGRES_USER: "eos-test"
      POSTGRES_DB: "eos-test-db"
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "eos-test"]
      interval: 5s
      timeout: 3s
      retries: 5
EOF

# Start services
docker compose -f /tmp/eos-test-services.yml up -d

# Wait for health checks
sleep 10

# Verify services are healthy
docker compose -f /tmp/eos-test-services.yml ps
```

**Option 2: Native Services** (Advanced)

```bash
# Install and start Vault in dev mode
vault server -dev -dev-root-token-id="eos-test-root-token" &

# Install and start Consul in dev mode
consul agent -dev &

# Set environment variables
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="eos-test-root-token"
export CONSUL_HTTP_ADDR="localhost:8500"
```

#### Run Tests with Real Services

```bash
# Set environment variables for test services
export EOS_TEST_USE_REAL_SERVICES=true
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="eos-test-root-token"
export CONSUL_HTTP_ADDR="localhost:8500"

# Run integration tests
go test -v -timeout=15m ./test/...

# Cleanup
docker compose -f /tmp/eos-test-services.yml down -v
```

---

## Writing Integration Tests

### Test Structure

Integration tests in Eos follow the `IntegrationTestSuite` pattern:

```go
// test/integration_myfeature_test.go
package test

import (
    "testing"
    "time"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/myfeature"
)

func TestEosIntegration_MyFeature(t *testing.T) {
    // 1. Create test suite
    suite := testutil.NewIntegrationTestSuite(t, "my-feature")

    // 2. Configure mocks (optional)
    suite.WithVaultMock()
    suite.WithDockerMock()

    // 3. Define test scenario
    scenario := testutil.TestScenario{
        Name:        "my_feature_workflow",
        Description: "Test complete workflow for my feature",

        // 4. Setup (optional)
        Setup: func(s *testutil.IntegrationTestSuite) {
            // Create test files, set env vars, etc.
        },

        // 5. Test steps
        Steps: []testutil.TestStep{
            {
                Name:        "step_1_setup",
                Description: "Initialize components",
                Action: func(s *testutil.IntegrationTestSuite) error {
                    rc := s.CreateTestContext("step1")
                    return myfeature.Initialize(rc)
                },
                Timeout: 10 * time.Second,
            },
            {
                Name:        "step_2_operation",
                Description: "Execute main operation",
                Action: func(s *testutil.IntegrationTestSuite) error {
                    rc := s.CreateTestContext("step2")
                    return myfeature.DoSomething(rc, config)
                },
                Validation: func(s *testutil.IntegrationTestSuite) error {
                    // Verify postconditions
                    s.AssertFileExists("path/to/expected/file")
                    return nil
                },
                Timeout: 30 * time.Second,
            },
        },

        // 6. Cleanup (optional)
        Cleanup: func(s *testutil.IntegrationTestSuite) {
            // Remove test files, stop services, etc.
        },
    }

    // 7. Run scenario
    suite.RunScenario(scenario)
}
```

### Test Helpers (`pkg/testutil/`)

**RuntimeContext Creation**:
```go
// Create test context with logging
rc := testutil.TestContext(t)

// Create context with cancellation
rc, cancel := testutil.TestRuntimeContextWithCancel(t)
defer cancel()

// Create context with custom options
rc := testutil.TestContextWithOptions(t, testutil.LoggerOptions{
    Level: zapcore.DebugLevel,
})
```

**File Operations**:
```go
// Create test file
testutil.CreateTestFile(t, dir, "path/to/file", "content", 0644)

// Assert file exists
suite.AssertFileExists("path/to/file")
```

**Command Execution**:
```go
// Execute command with timeout
err := suite.ExecuteCommandWithTimeout(cmd.RootCmd, []string{"--help"}, 5*time.Second)
```

### Example: Complete Integration Test

```go
func TestEosIntegration_ServiceDeployment(t *testing.T) {
    suite := testutil.NewIntegrationTestSuite(t, "service-deployment")
    suite.WithVaultMock()  // Mock Vault for testing

    scenario := testutil.TestScenario{
        Name:        "deploy_service_workflow",
        Description: "Test deploying a service from scratch",

        Setup: func(s *testutil.IntegrationTestSuite) {
            // Create test service directory
            serviceDir := filepath.Join(s.GetTempDir(), "test-service")
            os.MkdirAll(serviceDir, 0755)

            // Create docker-compose.yml
            composeContent := `
version: '3.8'
services:
  test:
    image: nginx:alpine
    ports:
      - "8080:80"
`
            testutil.CreateTestFile(t, s.GetTempDir(), "test-service/docker-compose.yml", composeContent, 0644)
        },

        Steps: []testutil.TestStep{
            {
                Name:        "validate_compose_file",
                Description: "Validate Docker Compose configuration",
                Action: func(s *testutil.IntegrationTestSuite) error {
                    rc := s.CreateTestContext("validate")
                    composeFile := filepath.Join(s.GetTempDir(), "test-service/docker-compose.yml")

                    return docker.ValidateComposeWithShellFallback(rc.Ctx, composeFile, "")
                },
                Timeout: 10 * time.Second,
            },
            {
                Name:        "deploy_service",
                Description: "Deploy service with Docker Compose",
                Action: func(s *testutil.IntegrationTestSuite) error {
                    rc := s.CreateTestContext("deploy")
                    serviceDir := filepath.Join(s.GetTempDir(), "test-service")

                    // Simulate deployment (don't actually start container in test)
                    logger := otelzap.Ctx(rc.Ctx)
                    logger.Info("Would deploy service", zap.String("dir", serviceDir))
                    return nil
                },
                Validation: func(s *testutil.IntegrationTestSuite) error {
                    // Verify service files exist
                    s.AssertFileExists("test-service/docker-compose.yml")
                    return nil
                },
                Timeout: 30 * time.Second,
            },
        },

        Cleanup: func(s *testutil.IntegrationTestSuite) {
            // Cleanup handled automatically by suite
        },
    }

    suite.RunScenario(scenario)
}
```

---

## Troubleshooting

### Common Issues

#### 1. Test Timeout

**Error**:
```
panic: test timed out after 2m0s
```

**Solutions**:
```bash
# Increase timeout
go test -v -timeout=10m ./test/...

# Or set per-test timeout
timeout: 30 * time.Second,  // In TestStep
```

#### 2. Mock Service Unavailable

**Error**:
```
failed to connect to Vault: connection refused
```

**Solutions**:
```bash
# Check if test uses mocks correctly
suite.WithVaultMock()  // Add this to test

# Or start real services
docker compose -f /tmp/eos-test-services.yml up -d
export EOS_TEST_USE_REAL_SERVICES=true
```

#### 3. Race Condition Detected

**Error**:
```
WARNING: DATA RACE
```

**Solutions**:
```bash
# Always run with race detector
go test -v -race ./test/...

# Fix race in code (use mutexes, channels, or atomic)
```

#### 4. Test Leaves Temp Files

**Error**:
```
/tmp/eos-test-12345 still exists after test
```

**Solutions**:
```go
// Use suite temp dir (auto-cleaned)
dir := suite.GetTempDir()

// Or manual cleanup
defer os.RemoveAll(tempDir)
```

#### 5. Integration Test Fails in CI but Passes Locally

**Debugging**:
```bash
# Check CI environment
echo $GITHUB_ACTIONS  # true in GitHub Actions

# Use same environment locally
export CI=true
export GITHUB_ACTIONS=true
go test -v ./test/...
```

---

## CI/CD Integration

### GitHub Actions Workflow

Integration tests run in `.github/workflows/test.yml`:

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest

    services:
      vault:
        image: hashicorp/vault:1.15
        ports:
          - 8200:8200
        env:
          VAULT_DEV_ROOT_TOKEN_ID: test-root-token
        options: >-
          --health-cmd "vault status"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 5

      postgres:
        image: postgres:16-alpine
        ports:
          - 5432:5432
        env:
          POSTGRES_PASSWORD: test-password
          POSTGRES_USER: test-user
          POSTGRES_DB: test-db
        options: >-
          --health-cmd "pg_isready -U test-user"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Run integration tests
        env:
          VAULT_ADDR: http://localhost:8200
          VAULT_TOKEN: test-root-token
          POSTGRES_HOST: localhost
          POSTGRES_PORT: 5432
        run: |
          go test -v -race -timeout=15m ./test/...
```

### Test Reports

Integration test results are uploaded to Codecov:

```yaml
- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.out
    flags: integration-tests
```

---

## Best Practices

### DO ✓

1. **Use TestSuite Framework**: Use `testutil.IntegrationTestSuite` for consistency
2. **Test Real Workflows**: Test complete user workflows, not just API calls
3. **Timeout Every Step**: Always set `Timeout` for test steps
4. **Clean Up Resources**: Use `Cleanup` function or `defer` for cleanup
5. **Log Context**: Use structured logging with context
6. **Mock When Appropriate**: Use mocks for external services in fast tests
7. **Test Error Paths**: Test both success and failure scenarios
8. **Use Descriptive Names**: `TestEosIntegration_VaultAuthenticationWorkflow` not `TestVault`

### DON'T ✗

1. **Don't Leave Processes Running**: Always clean up background processes
2. **Don't Assume Service Availability**: Check service health before testing
3. **Don't Share State Between Tests**: Each test should be independent
4. **Don't Use Production Credentials**: Always use test credentials
5. **Don't Skip Cleanup on Failure**: Use `defer` or suite cleanup
6. **Don't Test Platform-Specific Code Without Tags**: Use build tags for platform tests
7. **Don't Hardcode Paths**: Use `suite.GetTempDir()` or `t.TempDir()`

### Test Independence

**CRITICAL**: Each test must be independent and idempotent.

```go
// BAD: Depends on previous test
func TestCreateUser(t *testing.T) {
    // Assumes database from previous test exists
    db := getExistingDB()
    // ...
}

// GOOD: Self-contained
func TestCreateUser(t *testing.T) {
    // Create test database
    db := setupTestDB(t)
    defer db.Close()
    // ...
}
```

### Error Messages

**CRITICAL**: Integration test errors must be actionable.

```go
// BAD: Vague error
if err != nil {
    t.Fatal("test failed")
}

// GOOD: Actionable error
if err != nil {
    t.Fatalf("failed to connect to Vault at %s: %v\n"+
        "Check: is Vault running? Try: docker compose up vault-test",
        vaultAddr, err)
}
```

---

## Further Reading

- [Unit Testing Guide](/docs/TESTING.md) - Unit test patterns and practices
- [End-to-End Testing](/docs/E2E_TESTING.md) - Complete workflow testing
- [CI/CD Documentation](/.github/workflows/README.md) - CI pipeline details
- [CLAUDE.md](/CLAUDE.md) - Eos coding standards
- [PATTERNS.md](/docs/PATTERNS.md) - Implementation patterns

---

*"Cybersecurity. With humans."*
