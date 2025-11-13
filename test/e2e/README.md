# End-to-End (E2E) Testing

*Last Updated: 2025-11-05*

End-to-end tests for Eos that verify complete user workflows from start to finish.

---

## Overview

E2E tests in this directory test **real user workflows** by executing the actual `eos` binary. Unlike unit tests (which test functions in isolation) or integration tests (which test component interactions), E2E tests verify:

- **Complete workflows**: Full create → update → read → delete cycles
- **Real command execution**: Uses the compiled `eos` binary
- **System state changes**: Verifies actual file system, service status, etc.
- **User experience**: Tests what users actually experience

---

## Test Structure

```
test/e2e/
├── README.md                    # This file
├── framework.go                 # E2E test framework and utilities
├── vault_lifecycle_test.go      # Vault create/update/fix/delete workflow
├── service_deployment_test.go   # Service deployment workflows
└── ...                          # Additional E2E tests
```

---

## Running E2E Tests

### Quick Start

```bash
# Run all E2E tests
go test -v ./test/e2e/...

# Run specific test file
go test -v ./test/e2e/vault_lifecycle_test.go ./test/e2e/framework.go

# Run specific test function
go test -v -run TestE2E_VaultLifecycle ./test/e2e/...

# Run with timeout (E2E tests can be slow)
go test -v -timeout=30m ./test/e2e/...
```

### Skip Slow Tests

E2E tests are slow - use `-short` flag to skip them during development:

```bash
# Skip slow E2E tests
go test -short -v ./test/e2e/...

# Run only fast tests (help commands, etc.)
go test -short -v -run TestE2E_VaultHelp ./test/e2e/...
```

### Run as Root

Many E2E tests require root privileges for service installation:

```bash
# Run with sudo
sudo go test -v ./test/e2e/...

# Or run as root user
su -c "go test -v ./test/e2e/..." root
```

---

## Test Modes

E2E tests support two modes:

### 1. **Non-Destructive Mode** (Default)

Tests **command structure** without modifying the system:
- Tests `--help` flags
- Verifies command exists
- Checks error messages
- Fast and safe

```bash
# Run non-destructive tests (default)
go test -v ./test/e2e/...
```

**Use case**: CI/CD, development, pull requests

### 2. **Full E2E Mode** (Manual Uncommenting)

Tests **actual operations** that modify the system:
- Creates real services
- Modifies system configuration
- Requires cleanup
- Slow and potentially destructive

```bash
# Edit test files and uncomment real operations:
# result := suite.RunCommand("create", "vault")  # Uncomment this
# result.AssertSuccess(t)

# Run full E2E tests
sudo go test -v ./test/e2e/...
```

**Use case**: Test VMs, staging environments, pre-release validation

---

## Writing E2E Tests

### Basic Template

```go
package e2e

import (
    "testing"
)

func TestE2E_MyFeature(t *testing.T) {
    // 1. Create test suite
    suite := NewE2ETestSuite(t, "my-feature")

    // 2. Skip in short mode (optional)
    suite.SkipIfShort("My feature test is slow")

    // 3. Require root if needed (optional)
    suite.RequireRoot("Feature requires root privileges")

    // 4. Run test phases
    t.Run("Phase1_Setup", func(t *testing.T) {
        suite.Logger.Info("Setting up test")

        result := suite.RunCommand("create", "myservice", "--flag", "value")
        result.AssertSuccess(t)
        result.AssertContains(t, "expected output")
    })

    t.Run("Phase2_Verify", func(t *testing.T) {
        suite.Logger.Info("Verifying setup")

        result := suite.RunCommand("read", "myservice", "status")
        result.AssertSuccess(t)
    })

    t.Run("Phase3_Cleanup", func(t *testing.T) {
        suite.Logger.Info("Cleaning up")

        result := suite.RunCommand("delete", "myservice", "--force")
        result.AssertSuccess(t)
    })
}
```

### Framework Utilities

**Suite Creation**:
```go
suite := NewE2ETestSuite(t, "test-name")
```

**Run Commands**:
```go
// Run with default timeout (5 minutes)
result := suite.RunCommand("create", "vault")

// Run with custom timeout
result := suite.RunWithTimeout(10*time.Minute, "create", "vault")
```

**Assertions**:
```go
result.AssertSuccess(t)              // Exit code 0
result.AssertFails(t)                // Exit code != 0
result.AssertContains(t, "text")     // Output contains text
result.AssertNotContains(t, "text")  // Output doesn't contain text
```

**File Operations**:
```go
suite.CreateFile("path/to/file", "content")
exists := suite.FileExists("path/to/file")
content := suite.ReadFile("path/to/file")
```

**Wait for Conditions**:
```go
suite.WaitForCondition(func() bool {
    result := suite.RunCommand("read", "vault", "status")
    return result.ExitCode == 0
}, 2*time.Minute, "Vault becomes healthy")
```

**Cleanup**:
```go
suite.AddCleanup(func() {
    suite.RunCommand("delete", "myservice", "--force")
})

// Cleanup runs automatically at test end via defer
defer suite.RunCleanup()
```

---

## Test Categories

### 1. Lifecycle Tests

Test complete service lifecycle: create → read → update → delete

**Example**: `vault_lifecycle_test.go`

```go
func TestE2E_VaultLifecycle(t *testing.T) {
    // Phase 1: Create Vault
    // Phase 2: Verify status
    // Phase 3: Update/fix configuration
    // Phase 4: Verify health
    // Phase 5: Delete Vault
    // Phase 6: Verify clean removal
}
```

### 2. Deployment Tests

Test deploying services with various configurations

**Example**: `service_deployment_test.go`

```go
func TestE2E_ServiceDeployment_DockerBased(t *testing.T) {
    // Deploy Docker-based service
    // Verify container running
    // Check health
    // Clean up
}
```

### 3. Error Handling Tests

Test error cases and edge conditions

```go
func TestE2E_VaultLifecycle_WithErrors(t *testing.T) {
    // Test creating service twice (should fail)
    // Test deleting non-existent service (should fail)
    // Test fixing non-installed service (should fail)
}
```

### 4. Performance Tests

Test command performance and timing

```go
func TestE2E_VaultPerformance(t *testing.T) {
    // Measure help command speed
    // Measure deployment time
    // Measure status check latency
}
```

---

## Best Practices

### DO ✓

1. **Use Phases**: Break tests into clear phases (Setup, Execute, Verify, Cleanup)
2. **Always Cleanup**: Use `defer suite.RunCleanup()` to clean up resources
3. **Skip in Short Mode**: Use `suite.SkipIfShort()` for slow tests
4. **Log Progress**: Use `suite.Logger.Info()` to track test progress
5. **Test Both Success and Failure**: Test error cases, not just happy paths
6. **Use Timeouts**: Set appropriate timeouts for slow operations
7. **Verify Cleanup**: Check that deletion actually removes resources
8. **Document Prerequisites**: Document root/platform/service requirements

### DON'T ✗

1. **Don't Assume Clean State**: Always set up required preconditions
2. **Don't Leave Resources Running**: Always clean up services/containers/files
3. **Don't Run Destructive Tests in CI**: Use non-destructive mode for CI
4. **Don't Hardcode Paths**: Use `suite.WorkDir` for temporary files
5. **Don't Skip Error Checks**: Always verify command exit codes
6. **Don't Test Too Much at Once**: Keep tests focused on single workflows
7. **Don't Forget Platform Checks**: Skip tests that require specific platforms

---

## Troubleshooting

### Test Hangs/Times Out

```bash
# Increase timeout
go test -v -timeout=60m ./test/e2e/...

# Check which phase is hanging
# (Look for last "Phase X:" log before hang)
```

### Permission Denied Errors

```bash
# Run as root
sudo -E go test -v ./test/e2e/...

# Or check if test requires root
# (Look for suite.RequireRoot() in test)
```

### Binary Not Found

```bash
# Framework auto-builds binary, but you can pre-build:
go build -o /tmp/eos-test ./cmd/

# Or force rebuild:
rm /tmp/eos-test
go test -v ./test/e2e/...
```

### Test Fails to Clean Up

```bash
# Manually clean up resources
sudo docker compose down
sudo systemctl stop vault consul nomad
sudo rm -rf /opt/vault /opt/consul /opt/nomad

# Check for leftover processes
ps aux | grep -E "vault|consul|nomad"
```

### Platform-Specific Failures

```bash
# Some tests only work on Linux
# Check for runtime.GOOS checks in test:
if runtime.GOOS == "darwin" {
    t.Skip("Skipping on macOS")
}
```

---

## CI/CD Integration

E2E tests can run in CI with limitations:

### GitHub Actions

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e-non-destructive:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      # Non-destructive tests only
      - name: Run E2E Tests (Non-Destructive)
        run: |
          go test -v -timeout=30m ./test/e2e/...

  e2e-full:
    runs-on: ubuntu-latest
    # Only run on main branch or manual trigger
    if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5

      # Full E2E tests on dedicated runner
      - name: Run E2E Tests (Full)
        run: |
          # Uncomment real operations in test files
          sed -i 's|// result := suite.RunCommand|result := suite.RunCommand|g' test/e2e/*.go

          # Run with root
          sudo -E go test -v -timeout=60m ./test/e2e/...
```

---

## Future Enhancements

Planned improvements to E2E testing:

1. **Test Environment Provisioning**: Auto-provision test VMs with Terraform
2. **Parallel Execution**: Run independent tests in parallel
3. **Test Data Generation**: Generate realistic test data for services
4. **Snapshot/Restore**: Snapshot VM state between tests for faster runs
5. **Visual Regression**: Capture screenshots for UI-based services
6. **Load Testing**: Add performance/load tests for services
7. **Network Chaos**: Test service resilience under network failures

---

## See Also

- [Integration Testing Guide](/INTEGRATION_TESTING.md)
- [Test Architecture](/docs/TESTING.md)
- [CI/CD Documentation](/.github/workflows/README.md)
- [CLAUDE.md](/CLAUDE.md) - Eos coding standards

---

*"Cybersecurity. With humans."*
