# Secure Output Migration Guide

This guide helps developers migrate from direct output functions (`fmt.Printf`, `fmt.Println`) to the secure output system that prevents terminal manipulation vulnerabilities.

## Overview

The `pkg/security` package provides secure output functions that:
- **Sanitize all output** to remove dangerous control sequences (CSI, ANSI escape codes)
- **Integrate with structured logging** using the existing `otelzap.Ctx()` pattern
- **Maintain security compliance** with the CLAUDE.md requirements
- **Provide rich metadata** for monitoring and debugging

## Critical Security Issues Addressed

1. **Terminal Control Sequence Injection**: Prevents 0x9b (CSI) character attacks
2. **ANSI Escape Sequence Injection**: Removes malicious terminal formatting
3. **Log Injection**: Prevents control characters in log entries
4. **UTF-8 Validation**: Handles malformed Unicode sequences safely

## Migration Patterns

### 1. Simple Messages

**Before:**
```go
fmt.Println("Operation completed successfully")
fmt.Printf("Found %d items\n", count)
```

**After:**
```go
secureOutput := security.NewSecureOutput(rc.Ctx)
secureOutput.Success("Operation completed successfully")
secureOutput.Info("Found items", zap.Int("count", count))
```

### 2. Error Messages

**Before:**
```go
fmt.Printf("Error: %v\n", err)
fmt.Fprintf(os.Stderr, "Failed to process: %s\n", filename)
```

**After:**
```go
secureOutput := security.NewSecureOutput(rc.Ctx)
secureOutput.Error("Processing failed", err, zap.String("filename", filename))
```

### 3. Lists and Tables

**Before:**
```go
fmt.Printf("Available commands:\n")
for _, cmd := range commands {
    fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
}
```

**After:**
```go
secureOutput := security.NewSecureOutput(rc.Ctx)
commandNames := make([]string, len(commands))
for i, cmd := range commands {
    commandNames[i] = cmd.Name
}
secureOutput.List("Available commands", commandNames)

// Or for more detailed output:
headers := []string{"Name", "Description"}
rows := make([][]string, len(commands))
for i, cmd := range commands {
    rows[i] = []string{cmd.Name, cmd.Description}
}
secureOutput.Table("Available Commands", headers, rows)
```

### 4. Progress Updates

**Before:**
```go
fmt.Printf("Processing file %d of %d: %s\n", current, total, filename)
```

**After:**
```go
secureOutput := security.NewSecureOutput(rc.Ctx)
secureOutput.Progress("Processing file", current, total, 
    zap.String("filename", filename))
```

### 5. Command Results

**Before:**
```go
fmt.Printf("Backup created: %s\n", backupPath)
fmt.Printf("Size: %d bytes\n", size)
```

**After:**
```go
secureOutput := security.NewSecureOutput(rc.Ctx)
secureOutput.Result("backup_created", map[string]interface{}{
    "path": backupPath,
    "size_bytes": size,
})
```

## Complete Migration Example

Here's the complete migration of `cmd/list/commands.go`:

**Before:**
```go
func runListCommands(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // ... setup code ...
    
    if len(commands) == 0 {
        fmt.Println("No custom commands found.")
        return nil
    }
    
    fmt.Printf("Found %d custom commands:\n\n", len(commands))
    
    for _, cmd := range commands {
        fmt.Printf("Name: %s\n", cmd.Name)
        fmt.Printf("Path: %s\n", cmd.Path)
        fmt.Printf("Created: %s\n", cmd.CreatedAt.Format("2006-01-02 15:04:05"))
        fmt.Println()
    }
    return nil
}
```

**After:**
```go
func runListCommands(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    secureOutput := security.NewSecureOutput(rc.Ctx)
    
    // ... setup code ...
    
    if len(commands) == 0 {
        secureOutput.Info("No custom commands found")
        return nil
    }
    
    // Prepare data for secure output
    headers := []string{"Name", "Path", "Created"}
    rows := make([][]string, len(commands))
    
    for i, cmd := range commands {
        rows[i] = []string{
            cmd.Name,
            cmd.Path,
            cmd.CreatedAt.Format("2006-01-02 15:04:05"),
        }
    }
    
    secureOutput.Table("Custom Commands", headers, rows,
        zap.Int("total_commands", len(commands)))
    
    return nil
}
```

## Package-Level Convenience Functions

For simple cases, use package-level functions:

```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/security"

// Simple info message
security.LogInfo(rc.Ctx, "Operation started")

// Success with metadata
security.LogSuccess(rc.Ctx, "Deployment completed", 
    zap.String("environment", "production"))

// Error with context
security.LogError(rc.Ctx, "Database connection failed", err,
    zap.String("host", dbHost))

// Results with structured data
security.LogResult(rc.Ctx, "file_scan", map[string]interface{}{
    "files_scanned": 150,
    "threats_found": 0,
    "scan_duration": "2.3s",
})
```

## Benefits of Migration

### Security Benefits
- **Zero terminal manipulation vulnerabilities** from output
- **Automatic sanitization** of all user-provided data in output
- **Consistent security posture** across all commands

### Operational Benefits
- **Structured logging** for better monitoring and alerting
- **Rich metadata** for debugging and analytics
- **Consistent output format** across all commands
- **Better integration** with log aggregation systems

### Developer Benefits
- **Type-safe APIs** with compile-time validation
- **Consistent patterns** across the codebase
- **Built-in performance** through structured logging
- **Future-proof** against new terminal vulnerabilities

## Migration Strategy

### Phase 1: Critical Commands
Migrate security-sensitive commands first:
- Authentication/authorization commands
- System configuration commands
- User management commands
- File operations commands

### Phase 2: High-Traffic Commands
Migrate frequently used commands:
- List commands
- Status commands
- Info commands

### Phase 3: Remaining Commands
Complete migration of all remaining commands.

### Phase 4: Enforcement
Add linting rules to prevent future use of direct output functions.

## Testing Migrated Commands

Test migrated commands with dangerous input:

```bash
# Test with CSI character injection
eos list commands --filter "test$(echo -e '\x9b')[31m"

# Test with ANSI escape sequences
eos list commands --filter "test\e[31mred\e[0m"

# Test with null bytes
eos list commands --filter "test$(echo -e '\x00')null"
```

The secure output system should automatically sanitize these inputs in the log output.

## Performance Considerations

- **Minimal overhead**: Sanitization is lightweight regex operations
- **Lazy evaluation**: Only sanitizes when output is actually logged
- **Efficient batching**: Multiple fields sanitized in single operation
- **Memory efficient**: Reuses sanitizer instances where possible

## Compliance Notes

This migration ensures compliance with:
- **CLAUDE.md requirement**: "ALL user-facing output MUST go through structured logging"
- **Security requirement**: No use of `fmt.Printf`, `fmt.Println`, etc.
- **Debugging requirement**: "prioritize debugging information over pretty output formatting"

## Common Pitfalls

1. **Don't bypass the system**: Never use `fmt` functions for user-facing output
2. **Sanitize user data**: All user-provided content is automatically sanitized
3. **Use appropriate log levels**: Info for normal output, Warn for issues, Error for failures
4. **Include context**: Add relevant zap fields for debugging and monitoring

## Support

For questions about secure output migration:
- Review existing migrated commands in `cmd/` directory
- Check the comprehensive tests in `pkg/security/output_test.go`
- Follow the patterns established in the codebase