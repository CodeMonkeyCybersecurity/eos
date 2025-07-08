# Overnight Fuzzing Guide for Eos Framework

This guide provides comprehensive instructions for setting up and running overnight fuzz testing on the Eos framework to discover security vulnerabilities and edge cases.

## Quick Start

```bash
# Quick validation (essential tests for 3-5 seconds each)
./assets/quick-fuzz-validation.sh 5s

# Run overnight fuzzing with default settings (8h long tests, 2h medium, 30m short)
./assets/overnight-fuzz-simple.sh

# Run with custom durations for testing
FUZZTIME_LONG=30m FUZZTIME_MEDIUM=10m FUZZTIME_SHORT=5m ./assets/overnight-fuzz-simple.sh

# Individual test execution
./scripts/run-fuzz-tests.sh 10s ./pkg/crypto FuzzHashString
```

## Configuration

### Environment Variables

```bash
# Core timing configuration
export FUZZTIME_LONG="8h"        # Duration for critical tests  
export FUZZTIME_MEDIUM="2h"      # Duration for security tests
export FUZZTIME_SHORT="30m"      # Duration for basic tests

# Performance configuration
export PARALLEL_JOBS="4"         # Number of parallel fuzz jobs
export LOG_DIR="/tmp/eos-fuzz-logs"  # Log output directory

# Notification configuration  
export EMAIL_REPORT="true"       # Enable email reports
export EMAIL_ADDRESS="admin@example.com"  # Email for alerts
export SLACK_WEBHOOK="https://hooks.slack.com/..."  # Slack notifications
```

### Test Categories and Priorities

The overnight fuzzing runs tests in 6 phases with different priorities:

#### Phase 1: Critical System Tests (Sequential)
- **FuzzAllEosCommands** - Comprehensive CLI command testing
- **FuzzDelphiServicesCommands** - Service management operations
- Duration: `FUZZTIME_LONG` (default 8h each)

#### Phase 2: Security-Focused Tests (Parallel)
- **FuzzValidateStrongPassword** - Password validation security
- **FuzzHashString** - Cryptographic hashing functions  
- **FuzzRedact** - Sensitive data redaction
- **FuzzInjectSecretsFromPlaceholders** - Secret injection validation
- Duration: `FUZZTIME_MEDIUM` (default 2h each)

#### Phase 3: Command Processing Tests (Parallel)
- **FuzzUpdateCommand** - Service update operations
- **FuzzServiceWorkerPaths** - File path validation
- **FuzzCommandParsing** - CLI parsing logic
- **FuzzEosCommandFlags** - Flag processing
- Duration: `FUZZTIME_SHORT` to `FUZZTIME_MEDIUM`

#### Phase 4: Input Validation Tests (Parallel)
- **FuzzNormalizeYesNoInput** - Boolean input normalization
- **FuzzValidateUsername** - Username validation
- **FuzzValidateEmail** - Email validation  
- **FuzzValidateNoShellMeta** - Shell injection prevention
- Duration: `FUZZTIME_SHORT` (default 30m each)

#### Phase 5: Parsing & I/O Tests (Parallel)
- **FuzzSplitAndTrim** - String parsing utilities
- **FuzzYAMLParsing** - YAML configuration parsing
- **FuzzJSONParsing** - JSON data parsing
- Duration: `FUZZTIME_SHORT` (default 30m each)

#### Phase 6: Filesystem & Database Tests (Parallel)
- **FuzzMkdirP** - Directory creation operations
- **FuzzExecuteCommand** - Command execution security
- **FuzzDatabaseOperations** - Database interaction fuzzing
- Duration: `FUZZTIME_SHORT` (default 30m each)

## Test Execution

### Overnight Fuzzing (Production)

```bash
# Full overnight run with default settings
./assets/overnight-fuzz.sh

# Custom configuration for extended weekend testing
FUZZTIME_LONG=24h FUZZTIME_MEDIUM=6h FUZZTIME_SHORT=2h \
PARALLEL_JOBS=6 ./assets/overnight-fuzz.sh

# Testing mode (quick validation)
FUZZTIME_LONG=5m FUZZTIME_MEDIUM=2m FUZZTIME_SHORT=1m \
./assets/overnight-fuzz.sh
```

### Quick Testing

```bash
# Run all representative tests for 30 seconds each
./scripts/run-fuzz-tests.sh 30s

# Test specific package
./scripts/run-fuzz-tests.sh 2m ./pkg/crypto

# Test specific function
./scripts/run-fuzz-tests.sh 5m ./pkg/crypto FuzzValidateStrongPassword

# Discover available tests
./scripts/run-fuzz-tests.sh 1s | grep "Available fuzz tests"
```

## Monitoring and Reporting

### Real-time Monitoring

```bash
# Monitor active fuzzing session
tail -f /tmp/eos-fuzz-logs/fuzz-report-*.md

# Watch for crashes
watch "ls -la /tmp/eos-fuzz-logs/crashes_*.log 2>/dev/null || echo 'No crashes detected'"

# Monitor system resources
htop
# or
watch "ps aux | grep 'go test.*fuzz' | grep -v grep"
```

### Report Analysis

The overnight fuzzing generates comprehensive reports with:

- **Executive Summary**: Pass/fail counts, success rates, timing
- **Detailed Results**: Per-test logs, execution counts, discovered inputs
- **Performance Metrics**: Total executions, interesting inputs found
- **Crash Analysis**: Detailed crash information with stack traces
- **Next Steps**: Actionable recommendations

#### Report Locations

```bash
# Main report (Markdown format)
/tmp/eos-fuzz-logs/fuzz-report-YYYYMMDD_HHMMSS.md

# Individual test logs
/tmp/eos-fuzz-logs/FuzzTestName_YYYYMMDD_HHMMSS.log

# Crash summary (if any crashes detected)
/tmp/eos-fuzz-logs/crashes_YYYYMMDD_HHMMSS.log
```

### Automated Notifications

#### Email Alerts
```bash
export EMAIL_REPORT="true"
export EMAIL_ADDRESS="security-team@company.com"
./assets/overnight-fuzz.sh
```

#### Slack Integration
```bash
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
./assets/overnight-fuzz.sh
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Overnight Fuzz Testing
on:
  schedule:
    - cron: '0 22 * * 0'  # Every Sunday at 10 PM
  workflow_dispatch:

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    timeout-minutes: 600  # 10 hours max
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y bc
    
    - name: Run overnight fuzzing
      env:
        FUZZTIME_LONG: "3h"      # Reduced for CI
        FUZZTIME_MEDIUM: "1h"
        FUZZTIME_SHORT: "15m"
        PARALLEL_JOBS: "2"
        EMAIL_REPORT: "false"
      run: ./assets/overnight-fuzz.sh
    
    - name: Upload results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: fuzz-results
        path: /tmp/eos-fuzz-logs/
        retention-days: 30
    
    - name: Notify on failure
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### Cron Job Setup

```bash
# Add to crontab for nightly execution
crontab -e

# Run every night at 10 PM
0 22 * * * cd /path/to/eos && /bin/bash assets/overnight-fuzz.sh 2>&1 | logger -t eos-fuzz

# Weekly extended run (Saturday 10 PM)
0 22 * * 6 cd /path/to/eos && FUZZTIME_LONG=12h FUZZTIME_MEDIUM=4h /bin/bash assets/overnight-fuzz.sh 2>&1 | logger -t eos-fuzz-weekly
```

## Crash Analysis and Response

### When Crashes Are Detected

1. **Immediate Response**
   ```bash
   # Review crash summary
   cat /tmp/eos-fuzz-logs/crashes_TIMESTAMP.log
   
   # Examine specific failing test
   cat /tmp/eos-fuzz-logs/FailingTestName_TIMESTAMP.log
   ```

2. **Reproduce Crash**
   ```bash
   # Extract failing input from testdata/fuzz directory
   find testdata/fuzz -name "*" -type f | head -5
   
   # Run specific crash reproduction
   go test -run=TestName/specific-crash-input ./pkg/package
   ```

3. **Fix and Validate**
   ```bash
   # After fixing the code, validate the fix
   go test -run=TestName -fuzz=TestName -fuzztime=5m ./pkg/package
   
   # Re-run full test suite
   ./scripts/run-fuzz-tests.sh 1m
   ```

### Common Crash Patterns

#### Input Validation Failures
- **Panic**: `index out of range`
- **Root Cause**: Missing bounds checking
- **Fix**: Add length validation before array access

#### Memory Safety Issues  
- **Panic**: `runtime error: invalid memory address`
- **Root Cause**: Nil pointer dereference
- **Fix**: Add nil checks and proper initialization

#### Type Conversion Errors
- **Panic**: `invalid syntax` or `value out of range`  
- **Root Cause**: Unsafe type conversions
- **Fix**: Add validation before conversions

## Performance Optimization

### Resource Management

```bash
# Monitor memory usage during fuzzing
watch "free -h && ps aux | grep 'go test.*fuzz' | awk '{sum+=\$6} END {print \"Total RSS:\", sum/1024 \"MB\"}'"

# Adjust parallelism based on system capacity
export PARALLEL_JOBS=$(nproc)  # Use all CPU cores
export PARALLEL_JOBS=$(($(nproc) / 2))  # Use half the cores
```

### Disk Space Management

```bash
# Set up log rotation
find /tmp/eos-fuzz-logs -name "*.log" -mtime +7 -delete

# Compress old reports
find /tmp/eos-fuzz-logs -name "*.md" -mtime +1 -exec gzip {} \;
```

## Security Considerations

### Sensitive Data Protection

The fuzzing framework automatically:
- Skips tests in production environments (checks for production indicators)
- Uses `--dry-run` and `--skip-installation-check` flags for service tests
- Runs tests in isolated temporary directories
- Redacts sensitive information in logs

### Network Isolation

For production fuzzing:
```bash
# Run in network namespace to prevent external calls
sudo ip netns add fuzz-testing
sudo ip netns exec fuzz-testing ./assets/overnight-fuzz.sh
```

### File System Isolation

```bash
# Run in chroot for additional isolation
sudo chroot /path/to/isolated/eos ./assets/overnight-fuzz.sh
```

## Troubleshooting

### Common Issues

#### "No fuzz tests found"
```bash
# Verify test files exist
find . -name "*fuzz*test.go" | head -10

# Check test compilation
go test -c ./pkg/crypto
```

#### "Command not found: bc"
```bash
# Install bc for mathematical calculations
sudo apt-get install bc  # Ubuntu/Debian
brew install bc          # macOS
```

#### Memory exhaustion
```bash
# Reduce parallel jobs
export PARALLEL_JOBS=2

# Reduce test duration
export FUZZTIME_SHORT="5m"
```

#### Timeout issues
```bash
# Tests running too long - the script includes automatic timeouts
# Check for infinite loops in test code
go test -timeout=1m -run=TestName ./pkg/package
```

### Log Analysis

```bash
# Extract performance metrics
grep "executions" /tmp/eos-fuzz-logs/*.log | sort -n

# Find tests with high crash rates
grep -c "panic" /tmp/eos-fuzz-logs/*.log | sort -nr

# Analyze coverage patterns
grep "new interesting input" /tmp/eos-fuzz-logs/*.log | wc -l
```

## Best Practices

### Regular Execution Schedule

1. **Daily Quick Runs** (30 minutes): `./scripts/run-fuzz-tests.sh 30s`
2. **Weekly Medium Runs** (4 hours): Medium duration settings
3. **Monthly Extended Runs** (overnight): Full duration settings
4. **Pre-release Validation**: 24+ hour runs before major releases

### Test Development

1. **Add fuzz tests for new security-critical functions**
2. **Include representative seed inputs based on production data**
3. **Test edge cases and boundary conditions**
4. **Validate input sanitization and error handling**

### Continuous Improvement

1. **Monitor success rates and adjust test priorities**
2. **Add new test categories as the codebase evolves**
3. **Optimize test performance based on coverage analysis**
4. **Update seed corpus with interesting inputs from production**

## Integration with Development Workflow

### Pre-commit Hooks

```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
echo "Running quick fuzz validation..."
./scripts/run-fuzz-tests.sh 5s || {
    echo "❌ Fuzz tests failed - commit blocked"
    exit 1
}
echo "Fuzz tests passed"
```

### Pull Request Validation

```bash
# Run targeted fuzzing for changed packages
git diff --name-only HEAD~1 | grep "\.go$" | \
    xargs -I {} dirname {} | sort -u | \
    xargs -I {} ./scripts/run-fuzz-tests.sh 1m {}
```

## Success Metrics

Track these metrics to measure fuzzing effectiveness:

### Coverage Metrics
- Lines of code covered by fuzzing
- Unique execution paths discovered
- Edge cases and boundary conditions tested

### Quality Metrics  
- Crashes discovered and fixed
- Security vulnerabilities prevented
- Input validation gaps identified

### Performance Metrics
- Test execution speed
- Resource utilization efficiency
- Time to discovery for issues

## Conclusion

The enhanced overnight fuzzing framework provides comprehensive security testing for the Eos framework with:

- **Automated Discovery**: Finds crashes and edge cases automatically
- **Comprehensive Coverage**: Tests all security-critical components
- **Detailed Reporting**: Provides actionable insights and metrics
- **CI/CD Integration**: Seamlessly integrates with development workflows
- **Production Ready**: Includes safety measures and isolation

Regular overnight fuzzing significantly improves the security posture and reliability of the Eos framework by catching issues before they reach production.

For questions or issues, check the logs, review this guide, and ensure all dependencies are properly installed.