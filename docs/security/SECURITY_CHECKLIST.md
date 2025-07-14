# Security Development Checklist

*Last Updated: 2025-01-14*

## Pre-Development Security Checklist

Before writing any code, developers must verify:

### Input Validation Planning
- [ ] Identified all user inputs (CLI arguments, file inputs, network data)
- [ ] Defined validation rules for each input type
- [ ] Planned rejection strategies for invalid inputs
- [ ] Considered edge cases and boundary conditions

### Error Handling Strategy
- [ ] Planned distinction between user errors and system errors
- [ ] Identified sensitive information that must not be exposed
- [ ] Designed error logging without information leakage
- [ ] Planned audit trail for all error conditions

### Cryptographic Requirements
- [ ] Identified any cryptographic operations needed
- [ ] Selected appropriate algorithms (SHA-256+, AES-256-GCM)
- [ ] Planned secure key management through Vault
- [ ] Avoided deprecated algorithms (MD5, SHA-1)

## Code Implementation Security Checklist

During code development, verify:

### Secure Coding Patterns
- [ ] All functions follow Assess → Intervene → Evaluate pattern
- [ ] RuntimeContext passed to all security-sensitive functions
- [ ] Structured logging used exclusively (no fmt.Printf/Println)
- [ ] Input validation implemented before any processing

### Authentication & Authorization
- [ ] User identity verified before any operations
- [ ] Permissions checked before accessing resources
- [ ] Authentication failures properly logged
- [ ] Session management follows security standards

### Data Protection
- [ ] Sensitive data encrypted at rest and in transit
- [ ] Credentials never logged in plaintext
- [ ] Secure data deletion when no longer needed
- [ ] Access controls applied to all sensitive operations

### Network Security
- [ ] All network communications use TLS
- [ ] Certificate validation implemented
- [ ] Timeout and retry logic prevents DoS
- [ ] Input validation on all network data

## Code Review Security Checklist

Code reviewers must verify:

### Input Validation Review
- [ ] All user inputs validated with appropriate patterns
- [ ] Path traversal prevention implemented (no ".." in paths)
- [ ] SQL injection prevention (parameterized queries)
- [ ] Command injection prevention (no shell execution with user input)
- [ ] Cross-site scripting prevention (proper output encoding)

### Error Handling Review
- [ ] No sensitive information leaked in error messages
- [ ] All errors properly wrapped with context
- [ ] Security errors use security error framework
- [ ] Audit logs generated for all security events

### Cryptographic Review
- [ ] Only approved algorithms used (SHA-256+, AES-256-GCM)
- [ ] Secure random number generation (crypto/rand)
- [ ] Proper key management (through Vault)
- [ ] No hardcoded secrets or keys

### Logging Review
- [ ] All security operations logged with structured logging
- [ ] No credentials or sensitive data in logs
- [ ] Proper log levels used (Debug, Info, Warn, Error)
- [ ] Audit trail includes user context and timestamps

## Testing Security Checklist

Security testing must include:

### Unit Test Security Coverage
- [ ] Valid input handling tests
- [ ] Invalid input rejection tests
- [ ] Boundary condition tests
- [ ] Error condition tests
- [ ] Security error handling tests

### Integration Test Security Coverage
- [ ] Complete authentication workflow tests
- [ ] Authorization boundary tests
- [ ] Data protection workflow tests
- [ ] Audit logging verification tests
- [ ] Security configuration tests

### Security-Specific Test Cases
```go
// Template for security test cases
func TestFunction_SecurityBoundaries(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        wantErr  bool
        errType  string
    }{
        {"sql injection attempt", "'; DROP TABLE users; --", true, "invalid characters"},
        {"command injection attempt", "$(rm -rf /)", true, "invalid characters"},
        {"path traversal attempt", "../../../etc/passwd", true, "invalid characters"},
        {"buffer overflow attempt", strings.Repeat("A", 10000), true, "exceeds maximum length"},
        {"null byte injection", "file\x00.txt", true, "invalid characters"},
        {"valid input", "validinput123", false, ""},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := functionUnderTest(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.errType)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

## Deployment Security Checklist

Before deploying code:

### Build Security Verification
- [ ] Code compiles without errors: `go build -o /tmp/eos-build ./cmd/`
- [ ] Security linting passes: `golangci-lint run --enable=gosec`
- [ ] All tests pass: `go test -v ./pkg/...`
- [ ] Dependency vulnerability scan clean: `go mod audit`

### Configuration Security Review
- [ ] No hardcoded secrets in configuration
- [ ] Proper file permissions on configuration files (600/644)
- [ ] TLS certificates valid and properly configured
- [ ] Database connections use encrypted connections
- [ ] Vault integration properly configured

### Runtime Security Verification
- [ ] Service runs with minimal required privileges
- [ ] Security monitoring enabled and configured
- [ ] Audit logging functional and tested
- [ ] Error handling working correctly in production environment
- [ ] Security alerts configured and tested

## Security Pattern Templates

### Input Validation Template
```go
func validateInput(input string, maxLength int, pattern *regexp.Regexp) error {
    // Length validation
    if len(input) > maxLength {
        return fmt.Errorf("input exceeds maximum length %d", maxLength)
    }
    
    // Pattern validation
    if !pattern.MatchString(input) {
        return fmt.Errorf("input contains invalid characters")
    }
    
    // Additional security checks
    if strings.Contains(input, "\x00") {
        return fmt.Errorf("null byte detected in input")
    }
    
    return nil
}
```

### Secure Operation Template
```go
func SecureOperation(rc *eos_io.RuntimeContext, input *InputData) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Validate all inputs
    if err := validateInputData(input); err != nil {
        shared.LogSecurityEvent(rc.Ctx, "validation_failure", "operation", 
            input.Resource, map[string]interface{}{"error": err.Error()})
        return shared.NewSecurityError(rc.Ctx, "VAL_001", err.Error(),
            shared.SeverityMedium, shared.CategoryDataProtection)
    }
    
    // ASSESS - Check permissions
    if !hasPermission(rc, input.Resource, "write") {
        shared.LogSecurityEvent(rc.Ctx, "authorization_failure", "operation",
            input.Resource, map[string]interface{}{"user": getCurrentUser(rc)})
        return shared.NewAuthorizationError(rc.Ctx, "insufficient permissions")
    }
    
    // INTERVENE - Perform operation
    result, err := performOperation(rc, input)
    if err != nil {
        shared.LogSecurityEvent(rc.Ctx, "operation_failure", "operation",
            input.Resource, map[string]interface{}{"error": err.Error()})
        return fmt.Errorf("operation failed: %w", err)
    }
    
    // EVALUATE - Verify results
    if err := verifyOperation(rc, result); err != nil {
        logger.Warn("Operation verification failed", zap.Error(err))
        // Continue - verification failure is non-critical
    }
    
    // Log success
    shared.LogSecuritySuccess(rc.Ctx, "operation", input.Resource,
        map[string]interface{}{
            "user": getCurrentUser(rc),
            "result_id": result.ID,
        })
    
    return nil
}
```

### Security Error Handling Template
```go
func SecurityErrorHandler(rc *eos_io.RuntimeContext, err error, operation string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Classify error type
    switch {
    case isUserError(err):
        // User errors are safe to return
        logger.Info("User error in security operation",
            zap.String("operation", operation),
            zap.Error(err))
        return err
        
    case isAuthenticationError(err):
        // Authentication errors need special handling
        shared.LogSecurityEvent(rc.Ctx, "authentication_failure", operation,
            "", map[string]interface{}{"error": "authentication failed"})
        return shared.NewAuthenticationError(rc.Ctx, "authentication failed")
        
    case isAuthorizationError(err):
        // Authorization errors need audit logging
        shared.LogSecurityEvent(rc.Ctx, "authorization_failure", operation,
            "", map[string]interface{}{"user": getCurrentUser(rc)})
        return shared.NewAuthorizationError(rc.Ctx, "access denied")
        
    default:
        // System errors - log details but return generic error
        logger.Error("System error in security operation",
            zap.String("operation", operation),
            zap.Error(err))
        shared.LogSecurityEvent(rc.Ctx, "system_error", operation,
            "", map[string]interface{}{"error": "system error"})
        return fmt.Errorf("internal system error")
    }
}
```

## Common Security Mistakes to Avoid

### 1. Information Disclosure
```go
// ❌ DON'T - Exposes internal details
return fmt.Errorf("failed to connect to database at %s: %v", dbURL, err)

// ✅ DO - Generic message for users
logger.Error("Database connection failed", zap.Error(err))
return fmt.Errorf("database connection error")
```

### 2. Insecure Logging
```go
// ❌ DON'T - Logs sensitive data
fmt.Printf("User %s logged in with password %s", user, password)

// ✅ DO - Structured logging without secrets
logger.Info("User authentication successful",
    zap.String("user_id", user),
    zap.String("method", "password"))
```

### 3. Weak Input Validation
```go
// ❌ DON'T - Weak validation
if len(username) > 0 {
    // Process username
}

// ✅ DO - Comprehensive validation
if !isValidUsername(username) {
    return fmt.Errorf("invalid username format")
}
```

### 4. Command Injection
```go
// ❌ DON'T - Shell execution with user input
exec.Command("sh", "-c", "grep "+userInput+" /etc/passwd").Run()

// ✅ DO - Proper argument passing
exec.Command("grep", userInput, "/etc/passwd").Run()
```

### 5. Weak Cryptography
```go
// ❌ DON'T - Weak hashing
hash := md5.Sum(data)

// ✅ DO - Strong hashing
hash := sha256.Sum256(data)
```

## Security Review Sign-off

Before marking any security-related work as complete:

- [ ] **Developer**: All security checklist items verified
- [ ] **Peer Reviewer**: Security code review completed
- [ ] **Security Lead**: Security design review approved
- [ ] **Tests**: All security tests passing
- [ ] **Documentation**: Security changes documented

## Emergency Security Response

If a security vulnerability is discovered:

1. **Immediate Response** (within 1 hour):
   - [ ] Stop affected deployments
   - [ ] Assess scope and impact
   - [ ] Notify security team

2. **Short-term Response** (within 24 hours):
   - [ ] Implement temporary mitigation
   - [ ] Conduct impact assessment
   - [ ] Prepare security patch

3. **Long-term Response** (within 1 week):
   - [ ] Deploy permanent fix
   - [ ] Update security documentation
   - [ ] Conduct lessons learned review

---

**Remember**: Security is everyone's responsibility. When in doubt, escalate to the security team rather than proceeding with uncertain security implications.