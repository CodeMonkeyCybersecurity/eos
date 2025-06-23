# Integration Testing Framework

This document describes the comprehensive integration testing framework built for the Eos project.

## Overview

The integration testing framework provides end-to-end testing capabilities that connect all well-tested components together, ensuring they work correctly in realistic scenarios.

## Framework Components

### 1. IntegrationTestSuite (`pkg/testutil/integration.go`)

The core orchestration framework that provides:

- **Environment Setup**: Automated test environment configuration
- **Mock Services**: HTTP transport mocking for external services
- **Resource Management**: Temporary directories, certificates, and cleanup
- **Context Management**: Runtime context creation and lifecycle management
- **Command Execution**: Cobra command testing with timeouts
- **Scenario Orchestration**: Step-by-step test execution with validation

#### Key Features:

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

### 2. Predefined Scenarios (`pkg/testutil/scenarios.go`)

Ready-to-use test scenarios for common workflows:

- **VaultHealthCheckScenario()**: Vault client and authentication testing
- **FileSecurityScenario()**: File permission and secure operations testing
- **RuntimeContextLifecycleScenario()**: Context creation, attributes, and cleanup
- **ErrorHandlingScenario()**: Panic recovery and security validation

#### Usage:

```go
scenario := testutil.VaultHealthCheckScenario()
suite.RunScenario(scenario)
```

### 3. Test Patterns

Reusable patterns for common testing needs:

- **MockServicePattern**: External service mocking
- **FileSystemPattern**: File operation testing
- **ConcurrencyPattern**: Concurrent operation testing

## Integration Test Structure

### Test Scenarios

Each scenario consists of:

```go
type TestScenario struct {
    Name        string
    Description string
    Setup       func(*IntegrationTestSuite)     // Optional setup
    Steps       []TestStep                      // Execution steps
    Cleanup     func(*IntegrationTestSuite)     // Optional cleanup
}
```

### Test Steps

Individual steps with validation:

```go
type TestStep struct {
    Name        string
    Description string
    Action      func(*IntegrationTestSuite) error
    Validation  func(*IntegrationTestSuite) error  // Optional
    Timeout     time.Duration
}
```

## Available Integration Tests

### Core Integration Tests (`integration_test.go`)

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

### Scenario-Based Tests (`integration_scenarios_test.go`)

1. **TestIntegrationScenarios_VaultHealthCheck**
2. **TestIntegrationScenarios_FileSecurityOperations**
3. **TestIntegrationScenarios_RuntimeContextLifecycle**
4. **TestIntegrationScenarios_ErrorHandling**
5. **TestIntegrationScenarios_CombinedWorkflow**

## Running Integration Tests

### Run all integration tests:
```bash
go test -v ./integration_test.go ./integration_scenarios_test.go
```

### Run specific test:
```bash
go test -v ./integration_test.go -run TestEosIntegration_VaultAuthenticationWorkflow
```

### Run scenario-based tests:
```bash
go test -v ./integration_scenarios_test.go -run TestIntegrationScenarios_VaultHealthCheck
```

## Test Environment

The framework automatically sets up:

- **Temporary directories** for test data
- **Mock TLS certificates** for secure connections
- **Environment variables** for test configuration
- **Mock HTTP transports** for external services
- **Cleanup handlers** for resource management

### Environment Variables Set:

- `EOS_TEST_MODE=true`
- `VAULT_SKIP_VERIFY=true`
- `VAULT_ADDR=http://127.0.0.1:8200`
- `VAULT_CACERT=<temp-cert-path>`
- `EOS_DATA_DIR=<temp-data-dir>`
- `EOS_LOG_LEVEL=debug`

## Mock Services

### Vault Mock Transport
- Health check endpoints
- Authentication endpoints
- Token validation

### Docker Mock Transport
- Container listing
- Image management
- Status checking

### Wazuh Mock Transport
- User management
- Role management
- Policy management

## Best Practices

### 1. Test Isolation
- Each test suite gets its own temporary environment
- Automatic cleanup prevents test interference
- Environment variables are restored after tests

### 2. Timeout Management
- All test steps have configurable timeouts
- Default timeout: 30 seconds
- Context cancellation for long-running operations

### 3. Error Handling
- Comprehensive error validation
- Security-focused error message checking
- Panic recovery testing

### 4. Resource Management
- Automatic cleanup of test resources
- Proper context lifecycle management
- Memory and goroutine leak prevention

## Writing New Integration Tests

### 1. Create a Test Suite
```go
func TestMyIntegration(t *testing.T) {
    suite := testutil.NewIntegrationTestSuite(t, "my-test")
    suite.WithVaultMock() // Optional mock services
    
    // Your test logic here
}
```

### 2. Define a Custom Scenario
```go
scenario := testutil.TestScenario{
    Name: "my_custom_scenario",
    Steps: []testutil.TestStep{
        {
            Name: "step_1",
            Action: func(s *testutil.IntegrationTestSuite) error {
                // Your test logic
                return nil
            },
            Timeout: 10 * time.Second,
        },
    },
}

suite.RunScenario(scenario)
```

### 3. Use Predefined Patterns
```go
pattern := testutil.MockServicePattern("myservice", myMockTransport)
scenario := testutil.TestScenario{
    Setup: func(s *testutil.IntegrationTestSuite) {
        pattern.Setup(s)
    },
    // ... rest of scenario
}
```

## Framework Benefits

1. **Comprehensive Coverage**: Tests end-to-end workflows
2. **Realistic Scenarios**: Uses actual component integration
3. **Isolation**: Each test runs in isolated environment
4. **Reusability**: Predefined scenarios and patterns
5. **Maintainability**: Structured approach with clear separation
6. **Debugging**: Detailed step-by-step execution with timeouts
7. **Security Focus**: Validates security properties in integration
8. **Performance**: Concurrent execution support and timeout management

## Future Enhancements

- Add more predefined scenarios for specific workflows
- Extend mock services for additional external dependencies
- Add performance benchmarking capabilities
- Implement test result reporting and metrics
- Add support for distributed testing scenarios