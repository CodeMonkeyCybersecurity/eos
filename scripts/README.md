# EOS Fuzzing Scripts

## Overview

The EOS fuzzing framework provides comprehensive security testing with STACK.md architectural compliance.

## Scripts

### 🆕 New Framework (Recommended)

#### `eos-fuzz.sh` - Main Fuzzing Framework
Architecturally aligned, secure, and operationally sane fuzzing framework.

```bash
# Basic usage
./scripts/eos-fuzz.sh 30s

# Security-focused testing
SECURITY_FOCUS=true ./scripts/eos-fuzz.sh 5m

# Architecture compliance testing  
ARCHITECTURE_TESTING=true ./scripts/eos-fuzz.sh 2m

# Full testing with debug logging
SECURITY_FOCUS=true ARCHITECTURE_TESTING=true VERBOSE=true ./scripts/eos-fuzz.sh 1m
```

**Features:**
- ✅ STACK.md Section 4.1 compliant
- ✅ Dynamic test discovery
- ✅ Resource monitoring and limits
- ✅ Comprehensive error handling
- ✅ Security hardening
- ✅ Structured reporting

#### `eos-fuzz-ci.sh` - CI/CD Optimized
Lightweight version optimized for continuous integration environments.

```bash
# PR validation (fast)
./scripts/eos-fuzz-ci.sh pr-validation

# Security-focused CI testing
./scripts/eos-fuzz-ci.sh security-focused

# Architecture compliance testing
./scripts/eos-fuzz-ci.sh architecture

# Complete CI test suite
./scripts/eos-fuzz-ci.sh full
```

**Features:**
- ✅ GitHub Actions integration
- ✅ CI-specific optimizations
- ✅ Automated reporting
- ✅ Security alerting
- ✅ Performance optimized

### 🔄 Legacy Scripts (Deprecated)

#### `run-fuzz-tests.sh` - Legacy Framework
Original fuzzing script with architectural and security issues.

⚠️ **DEPRECATED**: Use `eos-fuzz.sh` instead.

#### `comprehensive-fuzz-runner.sh` - Legacy Comprehensive
Original comprehensive fuzzing with complexity issues.

⚠️ **DEPRECATED**: Use `eos-fuzz.sh` or `eos-fuzz-ci.sh` instead.

#### `run-fuzz-tests-legacy.sh` - Migration Helper
Backward compatibility wrapper that warns about deprecation.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FUZZTIME` | `30s` | Duration per fuzz test |
| `PARALLEL_JOBS` | `4` | Number of parallel jobs |
| `LOG_DIR` | `~/.cache/eos-fuzz` | Log directory |
| `SECURITY_FOCUS` | `true` | Enable security-critical tests |
| `ARCHITECTURE_TESTING` | `false` | Enable architecture tests |
| `VERBOSE` | `false` | Enable debug logging |

### CI/CD Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_FUZZTIME` | `60s` | CI test duration |
| `CI_PARALLEL_JOBS` | `4` | CI parallel jobs |
| `CI_LOG_DIR` | `./fuzz-results` | CI log directory |

## Test Categories

### Security-Critical Tests
Focus on security vulnerabilities and injection prevention:
- Input sanitization (`pkg/security`)
- Cryptographic functions (`pkg/crypto`) 
- Command execution (`pkg/execute`)
- Template generation (`pkg/saltstack`, `pkg/terraform`)

### Architecture Tests
Validate STACK.md compliance:
- Orchestration workflows (SaltStack → Terraform → Nomad)
- Cross-boundary integration (bare metal ↔ containerized)
- State consistency validation
- Resource contention scenarios

### Component Tests
Standard functionality testing:
- Input validation (`pkg/interaction`)
- Data parsing (`pkg/parse`, `pkg/eos_io`)
- File operations (`pkg/eos_unix`)
- Database operations (`pkg/database_management`)

## GitHub Actions Integration

### Workflow Configuration

```yaml
- name: Run Security Fuzzing
  run: ./scripts/eos-fuzz-ci.sh security-focused

- name: Run PR Validation
  if: github.event_name == 'pull_request'
  run: ./scripts/eos-fuzz-ci.sh pr-validation

- name: Check Security Alerts
  if: steps.fuzzing.outputs.security_alert == 'true'
  run: |
    echo "Security issues detected!"
    exit 1
```

### Available Outputs

| Output | Description |
|--------|-------------|
| `security_alert` | `true` if crashes detected |
| `security_test` | Test name that found crashes |
| `crash_count` | Number of crashes found |
| `tests_total` | Total tests executed |
| `tests_failed` | Number of failed tests |
| `success_rate` | Percentage of passed tests |

## Migration Guide

### From `run-fuzz-tests.sh`

```bash
# Old
./scripts/run-fuzz-tests.sh 30s ./pkg/crypto FuzzHashString

# New (automatic discovery)
SECURITY_FOCUS=true ./scripts/eos-fuzz.sh 30s
```

### From `comprehensive-fuzz-runner.sh`

```bash
# Old
CHAOS_MODE=true ./scripts/comprehensive-fuzz-runner.sh 5m

# New
SECURITY_FOCUS=true ARCHITECTURE_TESTING=true ./scripts/eos-fuzz.sh 5m
```

### CI/CD Migration

```bash
# Old CI usage
./scripts/run-fuzz-tests.sh 60s

# New CI usage
./scripts/eos-fuzz-ci.sh pr-validation
```

## Troubleshooting

### Common Issues

#### "Invalid FUZZTIME format"
```bash
# Wrong
FUZZTIME=30 ./scripts/eos-fuzz.sh

# Correct
FUZZTIME=30s ./scripts/eos-fuzz.sh
```

#### "Insufficient disk space"
```bash
# Check available space
df -h ~/.cache/eos-fuzz

# Use custom location
LOG_DIR=/tmp/fuzz ./scripts/eos-fuzz.sh 30s
```

#### "Low memory warning"
```bash
# Reduce parallel jobs
PARALLEL_JOBS=2 ./scripts/eos-fuzz.sh 30s
```

### Debug Mode

```bash
# Enable verbose logging
VERBOSE=true ./scripts/eos-fuzz.sh 30s

# Check system resources
VERBOSE=true ./scripts/eos-fuzz.sh 30s 2>&1 | grep -E "(memory|disk|resource)"
```

## Security Considerations

### Framework Security Features

1. **Input Validation**: All inputs are validated and sanitized
2. **Resource Limits**: Memory and time limits per test
3. **Secure Paths**: No predictable temporary file paths
4. **Process Control**: Proper cleanup of background processes
5. **Command Injection Prevention**: Safe handling of user inputs

### Security Alerts

The framework automatically detects and reports:
- Potential crashes (security vulnerabilities)
- Memory corruption issues
- Input validation failures
- Template injection attempts

When security issues are detected:
1. Immediate logging with `🚨 SECURITY ALERT`
2. CI/CD pipeline failure
3. Detailed crash information in logs
4. GitHub Actions security outputs

## Performance

### Resource Usage

| Test Category | Memory per Job | Typical Duration |
|---------------|----------------|------------------|
| Security | ~256MB | 30s - 5m |
| Architecture | ~512MB | 1m - 10m |
| Component | ~128MB | 10s - 2m |

### Optimization Tips

1. **Parallel Jobs**: Adjust based on available CPU cores
2. **Test Duration**: Longer duration finds more issues
3. **Log Directory**: Use fast storage (SSD) for logs
4. **CI Mode**: Use `eos-fuzz-ci.sh` for faster CI execution

## Contributing

When adding new fuzz tests:

1. **Location**: Place in appropriate package directory
2. **Naming**: Use `Fuzz*` function naming convention
3. **Categories**: Tests are automatically categorized by location
4. **Documentation**: Update this README if adding new categories

### Example Fuzz Test

```go
// pkg/security/example_fuzz_test.go
func FuzzNewSecurityFeature(f *testing.F) {
    // Seed with known attack vectors
    f.Add("normal_input")
    f.Add("$(malicious_command)")
    f.Add("../../../etc/passwd")
    
    f.Fuzz(func(t *testing.T, input string) {
        // Test your security feature
        result := YourSecurityFunction(input)
        
        // Validate security properties
        if ContainsDangerousContent(result) {
            t.Errorf("Security violation: %s", input)
        }
    })
}
```