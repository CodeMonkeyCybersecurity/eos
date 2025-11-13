# E2E Testing Strategy: Smoke vs Full

## Overview

E2E tests are split into two categories using Go build tags:

1. **Smoke Tests** (`//go:build e2e_smoke`) - Fast, non-destructive
2. **Full Tests** (`//go:build e2e_full`) - Slow, destructive, requires test environment

## Build Tags Usage

### Run Smoke Tests (Fast - Safe for CI)
```bash
# Run smoke tests only (3-5 seconds)
go test -v -tags=e2e_smoke ./test/e2e/...

# Or using eos self test
eos self test e2e --smoke
```

**What smoke tests verify:**
- ✓ Commands exist and are callable
- ✓ Flags are recognized and parsed correctly
- ✓ Help text is informative
- ✓ Command structure is correct
- ✓ Basic validation works (dry-run mode)

**What smoke tests DON'T do:**
- ✗ Install actual services
- ✗ Modify system state
- ✗ Create files outside /tmp
- ✗ Require root privileges
- ✗ Connect to external services

### Run Full Tests (Slow - Requires Test VM)
```bash
# Run full E2E tests (10-30 minutes)
sudo go test -v -tags=e2e_full ./test/e2e/...

# Or using eos self test
sudo eos self test e2e --full
```

**What full tests verify:**
- ✓ Complete service installation
- ✓ Configuration drift correction
- ✓ Service health monitoring
- ✓ Clean uninstallation
- ✓ Error handling in real scenarios
- ✓ Integration between services

**Full test requirements:**
- ✓ Root privileges (sudo)
- ✓ Isolated test environment (VM or container)
- ✓ Fresh Ubuntu 24.04 LTS installation
- ✓ Network connectivity
- ✓ Sufficient disk space (20GB+)

## Test File Organization

### Smoke Tests
```
test/e2e/smoke/
├── vault_smoke_test.go         //go:build e2e_smoke
├── consul_smoke_test.go         //go:build e2e_smoke
└── service_deployment_smoke_test.go
```

### Full Tests
```
test/e2e/full/
├── vault_lifecycle_full_test.go      //go:build e2e_full
├── consul_lifecycle_full_test.go     //go:build e2e_full
└── service_deployment_full_test.go
```

### Shared Code
```
test/e2e/
├── framework.go              // No build tags - shared utilities
└── README.md                 // This file
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM UTC

jobs:
  smoke-tests:
    name: E2E Smoke Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Run smoke tests
        run: go test -v -tags=e2e_smoke ./test/e2e/...
        timeout-minutes: 5

  full-tests:
    name: E2E Full Tests
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule' || contains(github.event.pull_request.labels.*.name, 'run-e2e-full')
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Run full E2E tests
        run: sudo go test -v -tags=e2e_full ./test/e2e/...
        timeout-minutes: 60
```

## Local Development

### Running Tests Locally

```bash
# Quick smoke test before committing
make test-e2e-smoke

# Full test in VM before release
make test-e2e-full

# Run specific smoke test
go test -v -tags=e2e_smoke -run TestSmoke_VaultCommands ./test/e2e/...

# Run specific full test
sudo go test -v -tags=e2e_full -run TestFull_VaultLifecycle ./test/e2e/...
```

### Test Environment Setup

For full E2E tests, use a fresh VM:

```bash
# Using multipass (recommended)
multipass launch --name eos-e2e-test --memory 4G --disk 20G
multipass shell eos-e2e-test

# Inside VM:
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
make install-deps
sudo make test-e2e-full

# Cleanup
multipass delete eos-e2e-test
multipass purge
```

## Test Naming Conventions

### Smoke Tests
- Prefix: `TestSmoke_`
- Example: `TestSmoke_VaultCommandsExist`
- Example: `TestSmoke_VaultFlagsValidation`

### Full Tests
- Prefix: `TestFull_`
- Example: `TestFull_VaultLifecycle`
- Example: `TestFull_ConsulClusterSetup`

## Writing New E2E Tests

### Smoke Test Template

```go
//go:build e2e_smoke

package e2e

import "testing"

func TestSmoke_ServiceCommands(t *testing.T) {
    suite := NewE2ETestSuite(t, "service-commands-smoke")

    t.Run("CreateCommand_Exists", func(t *testing.T) {
        result := suite.RunCommand("create", "service", "--help")
        result.AssertSuccess(t)
        result.AssertContains(t, "Create and configure")
    })

    t.Run("CreateCommand_FlagsValidation", func(t *testing.T) {
        result := suite.RunCommand("create", "service", "--invalid-flag")
        result.AssertFails(t)
        result.AssertContains(t, "unknown flag")
    })
}
```

### Full Test Template

```go
//go:build e2e_full

package e2e

import (
    "testing"
    "time"
)

func TestFull_ServiceLifecycle(t *testing.T) {
    suite := NewE2ETestSuite(t, "service-lifecycle-full")
    suite.RequireRoot("Service installation requires root")

    defer func() {
        // Always cleanup, even if test fails
        suite.RunCommand("delete", "service", "--force")
        suite.RunCleanup()
    }()

    t.Run("Install", func(t *testing.T) {
        result := suite.RunWithTimeout(5*time.Minute, "create", "service")
        result.AssertSuccess(t)
        result.AssertContains(t, "installed successfully")
    })

    t.Run("Verify", func(t *testing.T) {
        suite.WaitForCondition(func() bool {
            result := suite.RunCommand("read", "service", "status")
            return result.ExitCode == 0
        }, 2*time.Minute, "Service becomes healthy")
    })

    t.Run("Uninstall", func(t *testing.T) {
        result := suite.RunCommand("delete", "service", "--force")
        result.AssertSuccess(t)
    })
}
```

## Debugging Failed E2E Tests

### Smoke Test Failures

Smoke tests should almost never fail. If they do:
1. Command structure changed (update test)
2. Flag name changed (update test)
3. Help text changed (update expected output)

### Full Test Failures

Full tests can fail for many reasons:
1. Check test logs: `$TMPDIR/eos-e2e-*/`
2. Check service logs: `journalctl -u <service>`
3. Check Eos debug output: `eos debug <service>`
4. Verify test environment: `eos read system status`

## Performance Benchmarks

| Test Type | Duration | Resource Usage | When to Run |
|-----------|----------|----------------|-------------|
| Smoke | 3-5 seconds | Minimal (MB) | Every commit |
| Full (single service) | 5-15 minutes | Moderate (GB) | Before merge |
| Full (all services) | 30-60 minutes | Heavy (GB) | Nightly, releases |

## References

- Go Build Tags: https://go.dev/wiki/Build-Tags
- E2E Testing Best Practices: https://martinfowler.com/articles/practical-test-pyramid.html
- Eos Testing Strategy: docs/TESTING_ADVERSARIAL_ANALYSIS.md
