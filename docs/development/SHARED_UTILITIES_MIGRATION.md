# Shared Utilities Migration Guide

*Last Updated: 2025-01-14*

This guide documents the migration to consolidated shared utilities in the Eos codebase.

## Overview

The Eos codebase has grown organically, resulting in duplicate implementations of common functions across multiple packages. This migration consolidates these into shared utilities in `pkg/shared/`.

## Migration Mappings

### File Operations

All file operations should now use `pkg/shared/file_operations.go`:

```go
// OLD - Multiple implementations
pkg/eos_unix.FileExists()
pkg/system_config.CheckFileExists()
pkg/cmd_helpers.FileExists()

// NEW - Single implementation
import "your-repo/pkg/shared/file_operations"
file_operations.FileExists(path)
```

#### Complete Migration Map:

| Old Function | Package | New Function | Notes |
|-------------|---------|--------------|-------|
| `FileExists()` | `pkg/eos_unix` | `file_operations.FileExists()` | |
| `CheckFileExists()` | `pkg/system_config` | `file_operations.FileExists()` | |
| `WriteFile()` | `pkg/eos_unix` | `file_operations.WriteFileContents()` | Add owner param if needed |
| `WriteFileString()` | `pkg/system_config` | `file_operations.WriteFileContents()` | Convert string to []byte |
| `AppendToFile()` | `pkg/system_config` | `file_operations.AppendToFile()` | |
| `ReadFile()` | Multiple | `file_operations.ReadFileContents()` | |
| `EnsureDirectory()` | Multiple | `file_operations.EnsureDirectoryExists()` | |

### Validation Functions

All validation should use `pkg/shared/validation.go`:

```go
// OLD
pkg/interaction.ValidateUsername()
pkg/domain/stringutils.ValidateUsername()

// NEW
import "your-repo/pkg/shared/validation"
err := validation.ValidateUsername(username)
```

#### Validation Migration Map:

| Old Function | Package | New Function | Notes |
|-------------|---------|--------------|-------|
| `ValidateUsername()` | `pkg/interaction` | `validation.ValidateUsername()` | |
| `ValidatePassword()` | Multiple | `validation.ValidatePassword()` | Security-focused validation separate |
| `ValidateEmail()` | Multiple | `validation.ValidateEmail()` | |
| `ValidateHostname()` | Multiple | `validation.ValidateHostname()` | |
| `ValidateDomain()` | Multiple | `validation.ValidateDomain()` | |

### Error Handling

Use the consolidated error handling utilities:

```go
// OLD - Manual error wrapping
return fmt.Errorf("failed to do X: %w", err)

// NEW - Structured errors
import "your-repo/pkg/shared/error_handling"
return error_handling.WrapError(err, "failed to do X")
```

For user vs system errors:
```go
// User errors (exit code 0)
import "your-repo/pkg/eos_err"
return eos_err.NewUserError("please provide a valid username")

// System errors (exit code 1)
return eos_err.NewSystemError("database connection failed")
```

### Command Execution

Replace direct `exec.Command` usage:

```go
// OLD - Direct execution
cmd := exec.Command("apt-get", "install", pkg)
output, err := cmd.CombinedOutput()

// NEW - Using execute package
import "your-repo/pkg/execute"
output, err := execute.RunCommand(rc.Ctx, "apt-get", "install", pkg)
```

## Migration Steps

### Step 1: Update Imports

```go
// Add new imports
import (
    "your-repo/pkg/shared/file_operations"
    "your-repo/pkg/shared/validation"
    "your-repo/pkg/shared/error_handling"
)

// Remove old imports if no longer needed
```

### Step 2: Replace Function Calls

Use your IDE's find-and-replace with these patterns:

1. **File Operations**:
   - Find: `eos_unix\.FileExists\(`
   - Replace: `file_operations.FileExists(`

2. **Validation**:
   - Find: `interaction\.Validate(\w+)\(`
   - Replace: `validation.Validate$1(`

### Step 3: Update Tests

Ensure tests import and use the new shared functions:

```go
func TestMyFeature(t *testing.T) {
    // Use shared validation
    err := validation.ValidateUsername("testuser")
    assert.NoError(t, err)
    
    // Use shared file operations
    exists := file_operations.FileExists("/tmp/test")
    assert.False(t, exists)
}
```

### Step 4: Remove Old Implementations

Once all references are updated, remove the duplicate implementations:

1. Delete duplicate functions from individual packages
2. Update package documentation
3. Run tests to ensure nothing breaks

## Testing the Migration

### Pre-Migration Tests
```bash
# Run all tests and save baseline
go test -v ./... > pre-migration-tests.log 2>&1
```

### Post-Migration Verification
```bash
# Ensure compilation succeeds
go build -o /tmp/eos-build ./cmd/

# Run linting
golangci-lint run

# Run all tests
go test -v ./...

# Compare test results
diff pre-migration-tests.log post-migration-tests.log
```

## Common Pitfalls

### 1. Parameter Differences
Some duplicate functions have slightly different parameters:
```go
// Old - with owner parameter
eos_unix.WriteFile(path, content, owner)

// New - without owner parameter
file_operations.WriteFileContents(path, content)
// Then set owner separately if needed
```

### 2. Return Value Differences
Check if return values differ:
```go
// Old - returns bool
exists := FileExists(path)

// New - returns bool (same)
exists := file_operations.FileExists(path)
```

### 3. Error Message Changes
Consolidated functions may have different error messages. Update tests that check specific error strings.

## Rollback Plan

If issues arise during migration:

1. **Git Revert**: Use git to revert the migration commits
2. **Feature Flags**: Consider using build tags to toggle between old/new implementations
3. **Gradual Migration**: Migrate one package at a time rather than all at once

## Success Criteria

The migration is complete when:

1. ✅ No duplicate function implementations remain
2. ✅ All tests pass with the same results as before
3. ✅ Code compiles without errors
4. ✅ Linting passes without violations
5. ✅ No performance degradation observed

## Support

For questions or issues during migration:
- Check the shared package documentation
- Review test files for usage examples
- Consult CLAUDE.md for coding standards