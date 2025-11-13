# Golden File Testing in Eos

## Overview

Golden file testing (also called snapshot testing) is a testing technique where you compare generated output against a "golden" reference file. This is particularly useful for testing:

- **Docker Compose file generation**
- **Systemd unit file templates**
- **Vault/Consul/Nomad configuration files**
- **Complex multi-line output**
- **Generated code or templates**

## Quick Start

### Basic Usage

```go
package mypackage

import (
    "testing"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestGenerateDockerCompose(t *testing.T) {
    config := &ServiceConfig{
        Name:  "myservice",
        Image: "myservice:latest",
        Port:  8080,
    }

    output := GenerateDockerCompose(config)

    // Compare against golden file
    golden := testutil.NewGolden(t)
    golden.Assert(output)
}
```

### Running Tests

```bash
# First run - creates golden file
go test ./pkg/mypackage/...
# Output: PASS (golden file created)

# Subsequent runs - compares against golden file
go test ./pkg/mypackage/...
# Output: PASS (if output matches) or FAIL (if output differs)

# Update golden files when expected output changes
go test ./pkg/mypackage/... -update
# Output: PASS (golden files updated)
```

## When to Use Golden Files

### ✅ Good Use Cases

1. **Configuration File Generation**
   ```go
   // Test Vault configuration generation
   func TestGenerateVaultConfig(t *testing.T) {
       config := &VaultConfig{Port: 8200, Storage: "file"}
       output := GenerateVaultHCL(config)
       testutil.GoldenString(t, output)
   }
   ```

2. **Docker Compose Templates**
   ```go
   // Test Docker Compose file generation
   func TestGenerateComposeFile(t *testing.T) {
       services := []Service{{Name: "web", Image: "nginx"}}
       compose := GenerateComposeFile(services)
       testutil.GoldenBytes(t, compose)
   }
   ```

3. **Systemd Unit Files**
   ```go
   // Test systemd unit generation
   func TestGenerateSystemdUnit(t *testing.T) {
       unit := GenerateUnit("vault.service", "/usr/bin/vault")
       testutil.GoldenString(t, unit)
   }
   ```

4. **Multi-line Text Output**
   ```go
   // Test formatted report generation
   func TestGenerateDebugReport(t *testing.T) {
       report := GenerateDebugReport(diagnostics)
       testutil.GoldenString(t, report)
   }
   ```

### ❌ Avoid Golden Files For

1. **Simple string comparisons** - Use `assert.Equal()` instead
2. **Boolean or numeric values** - Use standard assertions
3. **Dynamic timestamps** - Strip timestamps before comparison
4. **Randomized output** - Mock randomness or use deterministic seeds

## Convenience Functions

### Quick Single-Value Tests

```go
// String comparison
testutil.GoldenString(t, generatedConfig)

// Byte slice comparison
testutil.GoldenBytes(t, composeFile)

// JSON comparison (auto-marshals structs)
testutil.GoldenJSON(t, configStruct)
```

### Multiple Snapshots Per Test

```go
func TestServiceGeneration(t *testing.T) {
    golden := testutil.NewGolden(t)

    // Generate Docker Compose
    compose := GenerateCompose(config)
    golden.AssertWithName("docker-compose", compose)

    // Generate systemd unit
    unit := GenerateSystemdUnit(config)
    golden.AssertWithName("systemd-unit", unit)

    // Generate environment file
    env := GenerateEnvFile(config)
    golden.AssertWithName("env-file", env)
}
```

## File Organization

Golden files are stored in `testdata/golden/`:

```
pkg/vault/
├── config.go
├── config_test.go
└── testdata/
    └── golden/
        ├── TestGenerateVaultConfig.golden
        ├── TestGenerateVaultConfig-docker-compose.golden
        └── TestGenerateVaultConfig-systemd-unit.golden
```

**Naming convention:**
- Single snapshot: `<TestFunctionName>.golden`
- Named snapshots: `<TestFunctionName>-<snapshot-name>.golden`

## Table-Driven Tests

Golden files work great with table-driven tests:

```go
func TestGenerateDockerCompose(t *testing.T) {
    tests := []struct {
        name   string
        config ServiceConfig
    }{
        {
            name: "basic-service",
            config: ServiceConfig{Name: "web", Port: 80},
        },
        {
            name: "database-service",
            config: ServiceConfig{Name: "db", Port: 5432},
        },
    }

    golden := testutil.NewGolden(t)

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            output := GenerateDockerCompose(tt.config)
            golden.AssertWithName(tt.name, output)
        })
    }
}
```

This creates:
- `testdata/golden/TestGenerateDockerCompose-basic-service.golden`
- `testdata/golden/TestGenerateDockerCompose-database-service.golden`

## Updating Golden Files

### When to Update

Update golden files when:
- ✓ You intentionally changed the output format
- ✓ You improved generated configuration
- ✓ You fixed a bug in template rendering
- ✓ You added new fields to generated files

### How to Update

```bash
# Update all golden files
go test ./pkg/... -update

# Update golden files for specific package
go test ./pkg/vault/... -update

# Update golden files for specific test
go test ./pkg/vault/... -update -run TestGenerateVaultConfig
```

### Review Process

**IMPORTANT**: Always review changes before committing:

```bash
# Update golden files
go test ./pkg/vault/... -update

# Review changes
git diff testdata/golden/

# If changes look correct, commit
git add testdata/golden/
git commit -m "Update golden files for improved Vault config generation"
```

## Best Practices

### 1. Normalize Output Before Comparison

```go
func TestGenerateConfig(t *testing.T) {
    config := GenerateConfig()

    // Normalize timestamps, paths, or other dynamic values
    normalized := strings.ReplaceAll(config, "/tmp/random-123", "/tmp/test-dir")

    testutil.GoldenString(t, normalized)
}
```

### 2. Use Deterministic Inputs

```go
// BAD: Randomized input leads to flaky tests
func TestGenerateToken(t *testing.T) {
    token := GenerateToken() // Uses random seed
    testutil.GoldenString(t, token) // ✗ Fails randomly
}

// GOOD: Deterministic input
func TestGenerateToken(t *testing.T) {
    token := GenerateTokenWithSeed(42) // Fixed seed
    testutil.GoldenString(t, token) // ✓ Consistent
}
```

### 3. Split Large Tests

```go
// Split into logical sections with named snapshots
func TestGenerateVaultDeployment(t *testing.T) {
    golden := testutil.NewGolden(t)

    golden.AssertWithName("compose-file", generateCompose())
    golden.AssertWithName("vault-config", generateVaultHCL())
    golden.AssertWithName("systemd-unit", generateSystemdUnit())
    golden.AssertWithName("env-file", generateEnvFile())
}
```

### 4. Include Comments in Golden Files

Golden files can include comments for clarity:

```yaml
# testdata/golden/TestGenerateVaultConfig.golden
# Generated Vault configuration
# Version: 1.15.0
# Cluster mode: single-node

storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 0
}
```

## Integration with CI/CD

### Prevent Accidental Updates

Add this to your CI workflow to ensure golden files aren't accidentally updated:

```yaml
# .github/workflows/tests.yml
- name: Run tests (golden files should not be updated in CI)
  run: |
    go test ./pkg/...
    if git diff --exit-code testdata/golden/; then
      echo "✓ Golden files unchanged"
    else
      echo "✗ Golden files were modified - did you forget to commit them?"
      exit 1
    fi
```

### Require Golden File Review

```yaml
# .github/workflows/golden-files-check.yml
- name: Check for golden file changes
  run: |
    if git diff --name-only HEAD~1 | grep -q "testdata/golden/"; then
      echo "::warning::Golden files were modified - ensure changes are intentional"
    fi
```

## Troubleshooting

### Golden File Mismatches

```
--- FAIL: TestGenerateVaultConfig (0.00s)
    golden.go:45: Golden file assertion failed:
        testdata/golden/TestGenerateVaultConfig.golden
        differs from generated output

        To update golden files, run:
          go test -update
```

**Resolution**:
1. Check if the output change is intentional
2. If yes: `go test -update` and commit
3. If no: Fix the code generating the output

### Missing Golden Files

First test run creates golden files automatically:

```bash
$ go test ./pkg/vault/...
=== RUN   TestGenerateVaultConfig
--- PASS: TestGenerateVaultConfig (0.00s)
    golden.go:38: Created golden file: testdata/golden/TestGenerateVaultConfig.golden
PASS
```

### Golden Files Not Updating

Ensure you're using the `-update` flag:

```bash
# Wrong - won't update
go test ./pkg/...

# Right - updates golden files
go test ./pkg/... -update
```

## Real-World Examples in Eos

### Docker Compose Generation

```go
// pkg/docker/compose_test.go
func TestGenerateComposeFile(t *testing.T) {
    t.Parallel()

    config := &ComposeConfig{
        Version: "3.8",
        Services: []Service{
            {Name: "vault", Image: "hashicorp/vault:1.15.0", Port: 8200},
        },
    }

    output := GenerateComposeFile(config)
    testutil.GoldenString(t, output)
}
```

### Vault Configuration

```go
// pkg/vault/config_test.go
func TestGenerateVaultHCL(t *testing.T) {
    t.Parallel()

    config := &VaultConfig{
        Port:    8200,
        Storage: "file",
        TLS:     true,
    }

    output := GenerateVaultHCL(config)
    testutil.GoldenString(t, output)
}
```

### Systemd Units

```go
// pkg/systemd/unit_test.go
func TestGenerateVaultUnit(t *testing.T) {
    t.Parallel()

    unit := GenerateSystemdUnit("vault", "/usr/local/bin/vault", "server", "-config=/etc/vault.d/vault.hcl")
    testutil.GoldenString(t, unit)
}
```

## References

- **cupaloy library**: https://github.com/bradleyjkemp/cupaloy
- **Go testing best practices**: https://go.dev/wiki/TestComments
- **Snapshot testing concept**: https://jestjs.io/docs/snapshot-testing
- **Eos testing guide**: docs/TESTING_ADVERSARIAL_ANALYSIS.md
