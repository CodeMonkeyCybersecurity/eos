# Redundant Code Patterns Analysis

## Executive Summary

This analysis identifies major redundant code patterns across the Eos codebase and provides recommendations for centralization. The analysis found significant duplication in error handling, file operations, validation, HTTP clients, and service management patterns.

## Key Findings

### 1. Direct exec.Command Usage vs Execute Package

**Current State:**
- 86 files use direct `exec.Command()` calls
- 116 files use the `execute` package
- Mixed usage creates inconsistency

**Impact:**
- Inconsistent error handling
- No centralized timeout management
- Duplicate command execution patterns
- Security concerns with command injection

**Examples of Direct Usage:**
```go
// pkg/system_config/manager.go
cmd := exec.Command("systemctl", "status", serviceName)

// pkg/nginx/nginx.go
cmd := exec.Command("nginx", "-t")

// pkg/vault/phase3_tls_cert.go
cmd := exec.Command("openssl", "req", "-new", "-key", keyPath)
```

**Recommendation:**
Migrate all direct `exec.Command` usage to the `execute` package for:
- Consistent timeout handling
- Structured logging of command execution
- Security validation of commands
- Unified error handling

### 2. Direct fmt.Printf/Println Usage

**Current State:**
- 182 files still use `fmt.Printf/Println/Print`
- Violates the structured logging requirement

**High Priority Files:**
- `pkg/ragequit/emergency/actions.go`
- `pkg/pipeline/system_prompts.go`
- `pkg/nginx/nginx.go`
- `pkg/eos_io/secure_input.go`
- Command files in `cmd/` directory

**Impact:**
- No structured logging metadata
- Inconsistent output formatting
- Difficult log aggregation
- Missing context information

**Recommendation:**
Replace all `fmt` output with structured logging:
```go
// Instead of:
fmt.Printf("Installing package: %s\n", pkgName)

// Use:
logger.Info("Installing package", zap.String("package", pkgName))
```

### 3. Manual Error Wrapping Patterns

**Current State:**
- 164+ occurrences of `errors.New()` and `fmt.Errorf()`
- Inconsistent error message formats
- No standardized error categorization

**Common Patterns Found:**
```go
// Installation errors
fmt.Errorf("failed to install %s: %w", tool, err)
fmt.Errorf("vault install via apt failed: %w", err)

// Configuration errors
fmt.Errorf("failed to configure %s: %w", component, err)

// File operation errors
fmt.Errorf("failed to read file %s: %w", path, err)
fmt.Errorf("failed to create directory: %w", err)

// Validation errors
fmt.Errorf("%s cannot be empty", fieldName)
fmt.Errorf("invalid %s: %s", field, value)
```

**Recommendation:**
The new `pkg/shared/error_handling.go` provides standardized error wrappers that should be used consistently.

### 4. Service/Systemctl Management Duplications

**Current State:**
- 32 files contain systemctl command patterns
- Duplicate service lifecycle management
- Inconsistent service status checking

**Common Duplicated Patterns:**
```go
// Starting services
exec.Command("systemctl", "start", serviceName)

// Checking service status
exec.Command("systemctl", "is-active", serviceName)

// Enabling services
exec.Command("systemctl", "enable", serviceName)

// Reloading daemon
exec.Command("systemctl", "daemon-reload")
```

**Existing Solutions:**
- `pkg/shared/service_management.go` - Enhanced service management
- `pkg/shared/service_lifecycle.go` - Service lifecycle operations
- `pkg/eos_unix/systemctl.go` - Basic systemctl wrapper

**Recommendation:**
Consolidate all service management through the shared packages.

### 5. File Operation Duplications

**Current State:**
- 6 packages implement their own file operations
- Common operations reimplemented multiple times

**Duplicated Patterns:**
```go
// File existence checks (repeated across packages)
if _, err := os.Stat(path); err != nil {
    if os.IsNotExist(err) {
        // handle
    }
}

// Directory creation (repeated pattern)
if err := os.MkdirAll(dir, 0755); err != nil {
    return fmt.Errorf("failed to create directory: %w", err)
}

// File reading (multiple implementations)
content, err := os.ReadFile(path)
if err != nil {
    return fmt.Errorf("failed to read %s: %w", path, err)
}
```

**Existing Solution:**
`pkg/shared/file_operations.go` provides comprehensive file operations.

### 6. Validation Pattern Duplications

**Current State:**
- 770+ duplicate string validation checks
- Repeated email, URL, path validations
- Inconsistent validation error messages

**Common Patterns:**
```go
// Empty string checks (repeated everywhere)
if config.Username == "" {
    return errors.New("username cannot be empty")
}

// Path validation (multiple implementations)
if _, err := os.Stat(path); os.IsNotExist(err) {
    return fmt.Errorf("path does not exist: %s", path)
}

// Port validation (inconsistent)
if port < 1 || port > 65535 {
    return errors.New("invalid port")
}
```

**Existing Solution:**
`pkg/shared/validation.go` provides comprehensive validation utilities.

### 7. Context Creation Patterns

**Current State:**
- 20 files create contexts with timeout/cancel
- Inconsistent timeout values
- Duplicate context management code

**Patterns Found:**
```go
// Various timeout patterns
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
ctx, cancel := context.WithCancel(context.Background())
```

**Recommendation:**
Standardize through `eos_io.RuntimeContext` for consistent timeout management.

### 8. Flag Handling Boilerplate

**Current State:**
- Repetitive flag parsing code
- Inconsistent flag validation
- Duplicate prompt-if-missing patterns

**Common Pattern:**
```go
cmd.Flags().String("username", "", "Username for service")
cmd.Flags().String("password", "", "Password for service")

// Then in command:
username := cmd.Flag("username").Value.String()
if username == "" {
    // prompt for username
}
```

**Recommendation:**
Create a shared flag handling utility for common patterns.

## Priority Recommendations

### Phase 1: Critical Security & Consistency (Immediate)
1. **Replace all `fmt.Printf/Println` with structured logging**
   - Security risk: Unstructured output can leak sensitive information
   - Affects 182 files
   
2. **Migrate direct `exec.Command` to execute package**
   - Security risk: Command injection vulnerabilities
   - Affects 86 files

3. **Standardize error handling with shared utilities**
   - Consistency issue: Makes debugging difficult
   - Affects all packages

### Phase 2: Code Quality & Maintainability (1-2 weeks)
1. **Consolidate file operations**
   - Use `pkg/shared/file_operations.go`
   - Remove duplicate implementations
   
2. **Standardize validation**
   - Use `pkg/shared/validation.go`
   - Create domain-specific validators

3. **Unify service management**
   - Use `pkg/shared/service_management.go`
   - Remove direct systemctl calls

### Phase 3: Long-term Improvements (1 month)
1. **Create shared installation framework**
   - Standardize "Assess → Intervene → Evaluate" pattern
   - Reduce duplicate installation logic

2. **Implement shared configuration framework**
   - Standardize config loading and validation
   - Create config migration utilities

3. **Build comprehensive testing utilities**
   - Shared test contexts and mocks
   - Standardized test patterns

## Estimated Impact

### Code Reduction
- Error handling: ~6,000 lines
- File operations: ~2,000 lines  
- Validation: ~1,500 lines
- Service management: ~1,000 lines
- **Total potential reduction: ~10,500 lines**

### Quality Improvements
- Consistent error messages across the codebase
- Standardized logging with proper context
- Unified security validations
- Centralized maintenance points

### Security Benefits
- Prevented command injection through execute package
- Consistent input validation
- Proper error handling prevents information disclosure
- Standardized file permission handling

## Migration Strategy

### Automated Migration Tools
Consider creating scripts to:
1. Replace `fmt.Printf` with logger calls
2. Convert `exec.Command` to execute package
3. Replace common error patterns with shared utilities

### Manual Review Required For:
1. Complex error handling logic
2. Service-specific validations
3. Custom file operations with special requirements

### Testing Strategy
1. Unit tests for all shared utilities
2. Integration tests for migrated code
3. Regression testing for critical paths
4. Security testing for command execution

## Conclusion

The codebase contains significant redundancy that can be addressed through the new shared utilities. Priority should be given to security-critical migrations (logging and command execution) followed by consistency improvements. The estimated code reduction of ~10,500 lines will significantly improve maintainability and reduce the surface area for bugs and security vulnerabilities.