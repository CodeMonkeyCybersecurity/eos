# Eos Testing Strategy & Best Practices

This guide provides a comprehensive strategy for implementing and prioritizing tests in the Eos project.

##  Testing Prioritization Framework

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
- `pkg/delphi/` - Wazuh/OpenSearch security monitoring
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

##  Testing Architecture

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

#### 2. Integration Tests
- **What:** Test interaction between components
- **When:** For workflows, API integrations, database operations
- **Mock:** External services only, keep internal integration

```go
func TestCreateVaultSecret(t *testing.T) {
    rc := testutil.TestRuntimeContext(t)
    cleanup := testutil.WithMockHTTPClient(t, testutil.VaultMockTransport())
    defer cleanup()
    
    // This tests vault client + HTTP transport + error handling
    err := vault.WriteSecret(rc, "secret/test", map[string]string{"key": "value"})
    testutil.AssertNoError(t, err)
}
```

#### 3. End-to-End Tests
- **What:** Test complete user workflows
- **When:** For critical paths, CLI command flows
- **Mock:** Minimal - use test environments

```go
func TestCreateTenantWorkflow(t *testing.T) {
    // Test the complete flow: vault -> delphi -> container setup
    // This would require a test environment with actual services
}
```

### Test Organization Patterns

#### 1. Table-Driven Tests
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

#### 2. Subtests for Related Scenarios
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

##  Using the Testing Framework

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

##  Testing Checklist

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

##  Implementation Roadmap

### Week 1: Foundation
1. Test `pkg/eos_io/` runtime context creation and logging
2. Test `pkg/eos_err/` error classification and wrapping
3. Test `pkg/crypto/` password hashing and validation

### Week 2: Critical Services
1. Test `pkg/vault/` health checks and basic operations
2. Test `pkg/container/` Docker client operations
3. Expand `pkg/delphi/` test coverage

### Week 3: Integration Testing
1. Test vault + crypto integration
2. Test container + vault secret mounting
3. Test delphi + vault authentication

### Week 4: CLI Testing
1. Test core CRUD commands
2. Test vault management commands
3. Add end-to-end workflow tests

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

##  Measuring Success

### Key Metrics
- **Coverage percentage** by package priority
- **Test execution time** (should be under 10 seconds for unit tests)
- **Test reliability** (flaky test rate < 5%)
- **Bug detection rate** (tests should catch bugs before production)

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
```

This framework provides the foundation for building robust, maintainable tests that will catch bugs early and give you confidence to refactor and extend the Eos codebase safely.