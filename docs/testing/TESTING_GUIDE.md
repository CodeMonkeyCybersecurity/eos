# Comprehensive Testing Guide for Eos

*Last Updated: 2025-01-14*

This guide provides a complete strategy for implementing security-first testing, integration testing, and comprehensive fuzzing in the Eos project. It combines unit testing, integration testing, security testing, and advanced fuzzing techniques to ensure robust validation of the entire system.

## Table of Contents

1. [Testing Strategy Overview](#testing-strategy-overview)
2. [Testing Prioritization Framework](#testing-prioritization-framework)
3. [Unit Testing](#unit-testing)
4. [Integration Testing](#integration-testing)
5. [Security Testing & Fuzzing](#security-testing--fuzzing)
6. [Advanced Testing Strategies](#advanced-testing-strategies)
7. [CI/CD Integration](#cicd-integration)
8. [Testing Framework Usage](#testing-framework-usage)
9. [Implementation Roadmap](#implementation-roadmap)

## Testing Strategy Overview

### Executive Summary

The Eos testing strategy implements multiple layers of testing to ensure robust security, reliability, and compliance with the STACK.md architecture requirements. The strategy emphasizes security-first principles with comprehensive fuzzing, integration testing, and property-based testing.

### Current Testing Infrastructure

**Strengths:**
- **105+ test files** across critical packages
- **Strong security focus** with dedicated fuzzing for crypto, security, and vault components
- **Integration testing framework** with scenario-based testing
- **Automated fuzzing infrastructure** with corpus management
- **ClusterFuzz integration** for continuous vulnerability discovery

**Critical Gaps Addressed:**
- **STACK.md Architecture Testing**:  → Terraform → Nomad workflows
- **Cross-Boundary Integration**: Bare metal ↔ containerized service communication
- **State Consistency Validation**: Multi-layer state drift detection
- **Template Injection Prevention**: /Terraform generation security
- **Chaos Engineering**: Infrastructure resilience testing

## Testing Prioritization Framework

### Priority 1: Critical Security & Infrastructure (Target: 95%+ coverage)

**Packages to test first:**
- `pkg/vault/` - HashiCorp Vault operations (secrets management)
- `pkg/crypto/` - Cryptographic functions (password hashing, TLS)
- `pkg/eos_io/` - Runtime context and logging foundation
- `pkg/eos_err/` - Error handling patterns

**Why these are critical:**
- Security vulnerabilities have catastrophic impact
- These packages are used by everything else
- Bugs here can compromise entire system

**Example test for vault package:**
```go
func TestVaultHealthCheck(t *testing.T) {
    rc := testutil.TestRuntimeContext(t)
    cleanup := testutil.WithMockHTTPClient(t, testutil.VaultMockTransport())
    defer cleanup()
    
    healthy, err := vault.HealthCheck(rc)
    testutil.AssertNoError(t, err)
    testutil.AssertEqual(t, true, healthy)
}
```

**Testing Vault Agent Integration:**
```go
func TestVaultAgentConfiguration(t *testing.T) {
    rc := testutil.TestRuntimeContext(t)
    tempDir := testutil.CreateTempDir(t)
    defer testutil.CleanupTempDir(t, tempDir)
    
    // Test agent config generation
    config, err := vault.GenerateAgentConfig(rc, "test-role", tempDir)
    testutil.AssertNoError(t, err)
    testutil.AssertContains(t, config, "auto_auth")
    testutil.AssertContains(t, config, "approle")
    
    // Test systemd integration paths
    testutil.AssertFileExists(t, "/etc/tmpfiles.d/vault-agent.conf")
    testutil.AssertDirectoryPermissions(t, "/run/vault-agent", 0750)
}
```

### Priority 2: External Service Integration (Target: 80%+ coverage)

**Packages to test next:**
- `pkg/wazuh/` - Wazuh/OpenSearch security monitoring
- `pkg/container/` - Docker operations
- `pkg/ldap/` - Directory service operations
- `pkg/hetzner/` - Cloud provider integration

**Why these matter:**
- High failure rate due to network/external dependencies
- Complex error scenarios need proper handling
- Integration bugs are hard to debug in production

### Priority 3: Business Logic (Target: 70%+ coverage)

**Packages to test:**
- `pkg/platform/` - System administration functions
- `pkg/execute/` - Command execution and retries
- `pkg/hecate/` - Reverse proxy management
- `pkg/interaction/` - User input validation

### Priority 4: CLI Commands (Target: 60%+ coverage)

**Commands to test:**
- Core lifecycle: `create`, `read`, `update`, `delete`
- Critical operations: `vault`, `secure`, `backup`

## Unit Testing

### Test Types & When to Use Them

#### 1. Unit Tests
- **What:** Test individual functions in isolation
- **When:** For pure functions, business logic, data transformations
- **Mock:** All external dependencies

```go
func TestHashPassword(t *testing.T) {
    password := "test123"
    hash, err := crypto.HashPassword(password)
    testutil.AssertNoError(t, err)
    testutil.AssertNotEqual(t, password, hash)
}
```

#### 2. Table-Driven Tests
Use for multiple input scenarios:

```go
func TestValidateInput(t *testing.T) {
    tests := []testutil.TableTest[string]{
        {Name: "valid email", Input: "user@domain.com", Expected: true},
        {Name: "invalid email", Input: "invalid", Error: "invalid format"},
        {Name: "empty input", Input: "", Error: "required"},
    }
    
    testutil.RunTableTests(t, tests, func(t *testing.T, input string) (any, error) {
        return ValidateEmail(input), nil
    })
}
```

#### 3. Subtests for Related Scenarios
```go
func TestVaultOperations(t *testing.T) {
    rc := testutil.TestRuntimeContext(t)
    cleanup := testutil.WithMockHTTPClient(t, testutil.VaultMockTransport())
    defer cleanup()
    
    t.Run("write secret", func(t *testing.T) {
        err := vault.WriteSecret(rc, "secret/test", data)
        testutil.AssertNoError(t, err)
    })
    
    t.Run("read secret", func(t *testing.T) {
        result, err := vault.ReadSecret(rc, "secret/test")
        testutil.AssertNoError(t, err)
        testutil.AssertEqual(t, "value", result["key"])
    })
}
```

## Integration Testing

### Integration Testing Framework

The integration testing framework provides end-to-end testing capabilities that connect all well-tested components together, ensuring they work correctly in realistic scenarios.

#### Framework Components

**1. IntegrationTestSuite (`pkg/testutil/integration.go`)**

The core orchestration framework that provides:
- **Environment Setup**: Automated test environment configuration
- **Mock Services**: HTTP transport mocking for external services
- **Resource Management**: Temporary directories, certificates, and cleanup
- **Context Management**: Runtime context creation and lifecycle management
- **Command Execution**: Cobra command testing with timeouts
- **Scenario Orchestration**: Step-by-step test execution with validation

```go
// Create a test suite
suite := testutil.NewIntegrationTestSuite(t, "test-name")

// Add mock services
suite.WithVaultMock()
suite.WithDockerMock()

// Create runtime contexts
rc := suite.CreateTestContext("command-name")

// Execute commands with timeout
err := suite.ExecuteCommandWithTimeout(cmd, args, timeout)
```

**2. Predefined Scenarios (`pkg/testutil/scenarios.go`)**

Ready-to-use test scenarios for common workflows:
- **VaultHealthCheckScenario()**: Vault client and authentication testing
- **FileSecurityScenario()**: File permission and secure operations testing
- **RuntimeContextLifecycleScenario()**: Context creation, attributes, and cleanup
- **ErrorHandlingScenario()**: Panic recovery and security validation

```go
scenario := testutil.VaultHealthCheckScenario()
suite.RunScenario(scenario)
```

#### Available Integration Tests

**Core Integration Tests (`integration_test.go`)**

1. **TestEosIntegration_VaultAuthenticationWorkflow**
   - Vault client setup
   - Authentication orchestration
   - Error handling validation

2. **TestEosIntegration_CommandWrapperFlow**
   - CLI command execution
   - Panic recovery testing
   - Telemetry integration

3. **TestEosIntegration_ConfigurationManagement**
   - Configuration file handling
   - Runtime context attributes
   - File system operations

4. **TestEosIntegration_ErrorHandlingFlow**
   - Error categorization
   - Context cancellation
   - Security validation

5. **TestEosIntegration_TelemetryAndLogging**
   - Telemetry span creation
   - Contextual logging
   - Observability features

6. **TestEosIntegration_MultiComponentWorkflow**
   - Multi-service integration
   - Component interaction
   - Resilience testing

**Running Integration Tests:**
```bash
# Run all integration tests
go test -v ./integration_test.go ./integration_scenarios_test.go

# Run specific test
go test -v ./integration_test.go -run TestEosIntegration_VaultAuthenticationWorkflow

# Run scenario-based tests
go test -v ./integration_scenarios_test.go -run TestIntegrationScenarios_VaultHealthCheck
```

## Security Testing & Fuzzing

### Comprehensive Fuzzing Strategy

#### 1. Security-Critical Component Fuzzing

**High-Priority Targets:**
- ** Template Generation** (`pkg//template_fuzz_test.go`)
  - Jinja2 template injection prevention
  -  data validation and sanitization
  - Configuration file generation security

- **Terraform Configuration Generation** (`pkg/terraform/config_fuzz_test.go`)
  - HCL injection prevention
  - Variable validation and sanitization
  - State file manipulation protection

- **Input Sanitization** (Enhanced `pkg/security/input_sanitizer_fuzz_test.go`)
  - Command injection prevention
  - Path traversal protection
  - Unicode and encoding attack prevention

**Security Properties Tested:**
```go
// Example: Security invariant property
SecurityInvariantProperty() Property {
    Name: "SecurityInvariant"
    Predicate: func(input interface{}) bool {
        // No injection attempts should succeed
        return !containsInjectionAttempts(input)
    }
}
```

#### 2. Architecture-Specific Testing

**STACK.md Compliance Testing:**
- **Orchestration Workflow Consistency**
  -  → Terraform → Nomad state consistency
  - Configuration generation chain validation
  - Error propagation and handling

- **Vault Degradation Scenarios**
  - Graceful fallback to Consul for credentials
  - Security warning validation
  - State recovery procedures

- **Cross-Boundary Communication**
  - Bare metal ↔ containerized service interaction
  - Service discovery validation
  - Network security boundary enforcement

- **Resource Contention Testing**
  - Memory allocation conflicts between deployment types
  - I/O interference detection
  - CPU scheduling validation

**Property-Based Testing Framework:**
```go
// Example: Orchestration consistency property
OrchestrationConsistencyProperty() Property {
    Name: "OrchestrationConsistency"
    Predicate: func(input interface{}) bool {
        // All layers should produce equivalent names
        return Name == terraformName && terraformName == nomadName
    }
}
```

#### 3. Fuzzing Operations

**Multi-Modal Testing:**
```bash
# Security-focused mode
SECURITY_FOCUS=true ./scripts/comprehensive-fuzz-runner.sh 30s

# Architecture compliance mode  
ARCHITECTURE_TESTING=true ./scripts/comprehensive-fuzz-runner.sh 5m

# Chaos engineering mode
CHAOS_MODE=true ./scripts/comprehensive-fuzz-runner.sh 10m

# Continuous fuzzing mode
CONTINUOUS_MODE=true ./scripts/comprehensive-fuzz-runner.sh 1h
```

**Intelligent Test Discovery:**
- **Categorized Test Execution**: Security, Architecture, Component testing
- **Parallel Execution**: Up to 16 concurrent fuzz tests
- **Corpus Management**: Automatic interesting input preservation
- **Performance Regression Detection**: Benchmark comparison

## Advanced Testing Strategies

### Chaos Engineering Implementation

#### Infrastructure Resilience Testing
- **Resource Exhaustion Simulation**
  - Memory pressure testing
  - CPU saturation scenarios
  - Disk I/O flooding

- **Network Disruption Testing**
  - Service discovery failures
  - Inter-service communication interruption
  - DNS resolution issues

- **Component Failure Simulation**
  - Vault unavailability
  - Nomad cluster failures
  - Database connection loss

### Property-Based Testing

Property-based testing validates system invariants and consistency properties across different scenarios:

```go
// Example: System consistency property
SystemConsistencyProperty() Property {
    Name: "SystemConsistency"
    Predicate: func(input interface{}) bool {
        // System state should remain consistent across operations
        return validateSystemConsistency(input)
    }
}
```

## CI/CD Integration

### Multi-Stage Testing Pipeline

**1. Quick Validation (15 minutes)**
- Linting and basic unit tests
- Quick fuzz validation

**2. Security-Focused Fuzzing (60 minutes)**
- Crypto and security component testing
- Input validation fuzzing
- Template injection prevention

**3. Architecture Testing (45 minutes)**
- STACK.md workflow validation
- Cross-boundary integration testing
- State consistency verification

**4. Chaos Engineering (30 minutes, on-demand/nightly)**
- Infrastructure resilience testing
- Failure scenario simulation
- Recovery procedure validation

**5. Property-Based Testing (30 minutes)**
- Invariant validation across components
- Consistency property verification
- Security property enforcement

### Coverage and Quality Metrics

**Coverage Enforcement:**
- **Minimum 80% coverage** for security-critical packages
- **100% coverage** for input validation and sanitization
- **Branch coverage analysis** for complex decision trees

**Security Metrics:**
- **Zero tolerance** for security property violations
- **Automatic security alerts** for potential vulnerabilities
- **Compliance tracking** with security best practices

## Testing Framework Usage

### Quick Start

1. **Create test context:**
```go
rc := testutil.TestRuntimeContext(t)
```

2. **Mock external services:**
```go
cleanup := testutil.WithMockHTTPClient(t, testutil.WazuhMockTransport())
defer cleanup()
```

3. **Use assertion helpers:**
```go
testutil.AssertNoError(t, err)
testutil.AssertEqual(t, expected, actual)
testutil.AssertErrorContains(t, err, "expected message")
```

### Advanced Mocking

#### Custom HTTP Responses
```go
customTransport := &testutil.MockHTTPTransport{
    ResponseMap: map[string]testutil.MockResponse{
        "/api/custom": {
            StatusCode: 200,
            Body: map[string]any{"result": "success"},
            Headers: map[string]string{"X-Custom": "header"},
        },
    },
    DefaultResponse: testutil.MockResponse{
        StatusCode: 404,
        Body: map[string]any{"error": "not found"},
    },
}
```

#### Error Scenarios
```go
func TestErrorHandling(t *testing.T) {
    tests := []struct {
        name string
        setupMock func() *testutil.MockHTTPTransport
        expectedErr string
    }{
        {
            name: "network timeout",
            setupMock: func() *testutil.MockHTTPTransport {
                return &testutil.MockHTTPTransport{
                    ResponseMap: map[string]testutil.MockResponse{
                        "/api/test": {StatusCode: 500},
                    },
                }
            },
            expectedErr: "server error",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cleanup := testutil.WithMockHTTPClient(t, tt.setupMock())
            defer cleanup()
            
            _, err := CallAPI()
            testutil.AssertErrorContains(t, err, tt.expectedErr)
        })
    }
}
```

## Implementation Roadmap

### Phase 1: Security Foundation (Weeks 1-2)
-  template generation fuzzing
- Terraform configuration fuzzing
- Enhanced input sanitization testing
- Security property framework

### Phase 2: Architecture Compliance (Weeks 3-4)
- STACK.md workflow testing
- Cross-boundary integration fuzzing
- Vault degradation scenario testing
- Resource contention validation

### Phase 3: Infrastructure Hardening (Weeks 5-6)
- Chaos engineering implementation
- Property-based testing framework
- Enhanced automation scripts
- CI/CD pipeline integration

### Phase 4: Continuous Improvement (Ongoing)
- Monitor and analyze fuzzing results
- Expand test coverage based on findings
- Refine security properties and invariants
- Enhance chaos engineering scenarios

### Weekly Implementation Schedule

**Week 1: Foundation**
1. Test `pkg/eos_io/` runtime context creation and logging
2. Test `pkg/eos_err/` error classification and wrapping
3. Test `pkg/crypto/` password hashing and validation

**Week 2: Critical Services**
1. Test `pkg/vault/` health checks and basic operations
2. Test `pkg/container/` Docker client operations
3. Expand `pkg/wazuh/` test coverage

**Week 3: Integration Testing**
1. Test vault + crypto integration
2. Test container + vault secret mounting
3. Test wazuh + vault authentication

**Week 4: CLI Testing**
1. Test core CRUD commands
2. Test vault management commands
3. Add end-to-end workflow tests

## Testing Checklist

### Before Writing Tests
- [ ] Is this function testable? (no hidden dependencies)
- [ ] What are the edge cases?
- [ ] What external dependencies need mocking?
- [ ] Should this be unit, integration, or e2e test?

### Test Quality Standards
- [ ] Test has descriptive name explaining what it tests
- [ ] Test is isolated (doesn't depend on other tests)
- [ ] Test cleans up after itself
- [ ] Test covers both success and failure paths
- [ ] Assertions are specific and meaningful
- [ ] Test uses proper helpers and utilities

### Coverage Goals by Package Type
- **Security/Crypto packages:** 95%+ line coverage
- **External integrations:** 80%+ line coverage  
- **Business logic:** 70%+ line coverage
- **CLI commands:** 60%+ line coverage
- **Utilities:** 50%+ line coverage

## 🐛 Debugging Test Failures

### Common Issues
1. **Test pollution:** Tests affecting each other
   - Solution: Ensure proper cleanup, use fresh contexts
   
2. **Mock not matching real behavior:**
   - Solution: Compare mock responses with actual API responses
   
3. **Flaky tests:**
   - Solution: Remove time dependencies, use deterministic data

### Debug Helpers
```go
// Enable debug logging in tests
func TestWithDebugLogging(t *testing.T) {
    logger, _ := zap.NewDevelopment()
    zap.ReplaceGlobals(logger)
    defer zap.ReplaceGlobals(zap.NewNop())
    
    // Your test code here
}
```

## Measuring Success

### Key Metrics
- **Coverage percentage** by package priority
- **Test execution time** (should be under 10 seconds for unit tests)
- **Test reliability** (flaky test rate < 5%)
- **Bug detection rate** (tests should catch bugs before production)

### Security Metrics
- **Zero security property violations** in production releases
- **<1% false positive rate** in security testing
- **100% coverage** of user input vectors
- **Sub-second detection** of security violations

### Reliability Metrics
- **99.9% test stability** across fuzzing runs
- **<5% performance regression** tolerance
- **100% architecture compliance** with STACK.md
- **<10 second** average test execution time

### Tools
```bash
# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test patterns
go test -run "TestVault.*" ./pkg/vault/

# Run tests with race detection
go test -race ./...

# Quick security validation (10 minutes)
./scripts/run-fuzz-tests.sh 10s

# Standard comprehensive testing (30 minutes)
./scripts/comprehensive-fuzz-runner.sh 2m
```

## Conclusion

This comprehensive testing strategy provides multiple layers of security validation while ensuring compliance with the sophisticated STACK.md architecture. The implementation combines traditional testing approaches with modern fuzzing techniques, chaos engineering, and property-based testing to create a robust security foundation.

The strategy emphasizes:
- **Security-first approach** with dedicated fuzzing for all input vectors
- **Architecture compliance** with STACK.md orchestration requirements
- **Comprehensive integration testing** with realistic scenarios
- **Automation and CI/CD integration** for continuous validation
- **Comprehensive coverage** of cross-boundary and state consistency issues
- **Operational readiness** with clear procedures and metrics

This framework provides the foundation for building robust, maintainable tests that will catch bugs early and give you confidence to refactor and extend the Eos codebase safely while maintaining the highest security standards.