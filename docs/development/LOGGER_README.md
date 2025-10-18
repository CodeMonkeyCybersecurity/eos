# Logger Package

*Last Updated: 2025-01-14*

The `logger` package provides centralized logging functionality for the Eos CLI application with dual-output capabilities (console + file), structured logging, and OpenTelemetry integration.

## Overview

This package implements a comprehensive logging system that:
- Outputs structured logs to both console and log files simultaneously
- Integrates with OpenTelemetry for distributed tracing
- Provides secure file handling with appropriate permissions
- Supports multiple log levels and environment-based configuration
- Handles platform-specific log file locations
- Includes fallback mechanisms for reliability

## Architecture

### Core Components

#### Dual Output Logging (`fallback.go`)
The primary initialization function that configures logging to output to both console and file:

```go
func InitFallback()
```

**Features:**
- **Console Output**: Color-coded, human-readable format with simplified fields
- **File Output**: JSON format with full structured data
- **Automatic Fallback**: Falls back to console-only if file writing fails
- **OpenTelemetry Integration**: Configures global otelzap logger for distributed tracing

**Log Format Examples:**
```bash
# Console output (human-readable)
INFO  Checking Wazuh services status
WARN Service unit file not found {"service": "wazuh-listener"}

# File output (JSON structured)
{"level":"INFO","ts":"2024-06-23T10:30:00.000Z","msg":" Checking Wazuh services status"}
{"level":"WARN","ts":"2024-06-23T10:30:01.000Z","msg":"Service unit file not found","service":"wazuh-listener"}
```

#### Configuration Management (`config.go`)
Provides production-ready Zap configurations:

```go
func DefaultConfig(rc *eos_io.RuntimeContext) zap.Config
func ParseLogLevel(level string) zapcore.Level
```

**Supported Log Levels:**
- `TRACE`/`DEBUG` → Debug level
- `INFO` → Info level (default)
- `WARN` → Warning level
- `ERROR` → Error level
- `FATAL` → Fatal level
- `DPANIC` → Development panic level

#### Platform-Specific Paths (`paths.go`)
Manages log file locations across different operating systems:

```go
func PlatformLogPaths() []string
```

**Platform Priorities:**

**macOS (Darwin):**
1. `~/.local/state/eos/eos.log` (XDG State)
2. `/tmp/eos/eos.log`
3. `./eos.log` (current directory)

**Linux:**
1. `/var/log/eos/eos.log` (system-wide)
2. `/run/eos/eos.log` (runtime directory)
3. `~/.local/state/eos/eos.log` (XDG State)
4. `/tmp/eos/eos.log`
5. `./eos.log` (current directory)

**Windows:**
1. `%ProgramData%\eos\eos.log`
2. `%LOCALAPPDATA%\eos\eos.log`
3. `.\eos.log` (current directory)

#### File Operations (`writer.go`)
Handles secure file creation and writing:

```go
func GetLogFileWriter(path string) (zapcore.WriteSyncer, error)
func FindWritableLogPath() (string, error)
func GetFallbackLogWriter() zapcore.WriteSyncer
```

**Security Features:**
- Creates directories with `0700` permissions (owner-only access)
- Creates log files with `0600` permissions (owner read/write only)
- Validates write permissions before use
- Graceful fallback to stdout if file operations fail

#### Permission Management (`check.go`)
Ensures secure file and directory permissions:

```go
func EnsureLogPermissions(path string) error
```

**Security Implementation:**
- Directory permissions: `0700` (rwx------)
- File permissions: `0600` (rw-------)
- Creates missing directories and files as needed
- Validates permissions after creation

#### Handler Functions (`handler.go`)
Provides initialization and management utilities:

```go
func Init(rc *eos_io.RuntimeContext, cfg zap.Config)
func Sync(rc *eos_io.RuntimeContext, strict ...bool) error
func LogErrAndWrap(rc *eos_io.RuntimeContext, msg string, err error) error
```

## Usage

### Basic Initialization

The logger is automatically initialized in all Eos commands through the `eos_cli.Wrap()` function:

```go
// In command files
var MyCmd = &cobra.Command{
    Use: "example",
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        // Logger is already initialized and available via otelzap.Ctx(rc.Ctx)
        logger := otelzap.Ctx(rc.Ctx)
        logger.Info("Command started")
        return nil
    }),
}
```

### Structured Logging Patterns

**CRITICAL**: All logging must use structured logging patterns as defined in CLAUDE.md:

```go
logger := otelzap.Ctx(rc.Ctx)

// Function entry with context
logger.Info(" Starting operation", 
    zap.String("user", os.Getenv("USER")),
    zap.String("function", "functionName"))

// File operations
logger.Info(" Output file determined",
    zap.String("file_path", outputPath),
    zap.Bool("exists", fileExists))

// Command execution
logger.Info(" Executing command",
    zap.String("command", cmdName),
    zap.Strings("args", args))

// Error handling
logger.Error(" Operation failed",
    zap.Error(err),
    zap.String("phase", currentPhase))
```

### Environment Configuration

Configure logging behavior with environment variables:

```bash
# Set log level
export LOG_LEVEL=DEBUG

# Enable development mode
export ENV=development
```

### Manual Initialization (Advanced)

For custom initialization outside the standard command wrapper:

```go
import (
    "github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func customInit() {
    // Use fallback initialization (recommended)
    logger.InitFallback()
    
    // Or use custom configuration
    rc := eos_io.NewContext(context.Background(), "custom")
    cfg := logger.DefaultConfig(rc)
    logger.Init(rc, cfg)
}
```

## Integration with Eos Architecture

### RuntimeContext Integration

The logger integrates seamlessly with `eos_io.RuntimeContext`:

```go
type RuntimeContext struct {
    Ctx    context.Context
    Log    *zap.Logger        // Contextual logger
    // ... other fields
}
```

### OpenTelemetry Integration

All logging is instrumented with OpenTelemetry tracing:

- Trace IDs are automatically included in log entries
- Spans are correlated with log messages
- Distributed tracing context is preserved across service boundaries

### Command Wrapper Integration

The logger is automatically initialized in `pkg/eos_cli/wrap.go`:

```go
func Wrap(fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) {
    return func(cmd *cobra.Command, args []string) error {
        logger.InitFallback()  // Initialize dual-output logging
        ctx := eos_io.NewContext(context.Background(), cmd.Name())
        // ... rest of wrapper logic
    }
}
```

## Security Considerations

### File Permissions
- Log directories: `0700` (owner-only access)
- Log files: `0600` (owner read/write only)
- Prevents unauthorized access to log data

### Error Handling
- Graceful fallback to console output if file operations fail
- No sensitive data logged by default
- Structured logging prevents log injection attacks

### Platform Security
- Uses platform-appropriate directories (XDG on Unix, system directories on Windows)
- Respects system security boundaries
- Handles permission errors gracefully

## Error Handling

The logger package implements comprehensive error handling:

### Sync Errors
```go
func IsIgnorableSyncError(err error) bool
```
Identifies and ignores common, non-critical sync errors (e.g., stdout sync on some platforms).

### Fallback Mechanisms
- File write failure → Console output
- Permission errors → Temporary directory
- Configuration errors → Development logger

### Strict Mode
```go
logger.Sync(rc, true)  // Strict mode - all errors are fatal
logger.Sync(rc)        // Normal mode - ignorable errors are suppressed
```

## Performance Considerations

### Buffering
- File output is buffered for performance
- Console output is immediately flushed
- Sync operations are controlled and optimized

### Resource Management
- File handles are properly managed
- Log rotation is handled by external tools (logrotate, etc.)
- Memory usage is optimized through structured field reuse

## Troubleshooting

### Common Issues

**No console output:**
- Verify `InitFallback()` is called
- Check that `otelzap.Ctx(rc.Ctx)` is used for logging

**File permission errors:**
- Ensure target directory is writable
- Check that user has appropriate permissions
- Verify disk space availability

**Missing log entries:**
- Call `logger.Sync()` before application exit
- Ensure proper error handling in logging calls
- Check log level configuration

### Debug Information

Enable debug logging to troubleshoot logger issues:

```bash
export LOG_LEVEL=DEBUG
```

This will show detailed information about:
- Log path resolution
- File permission handling
- Fallback mechanism activation
- OpenTelemetry integration status

## Dependencies

- `go.uber.org/zap` - Core logging framework
- `github.com/uptrace/opentelemetry-go-extra/otelzap` - OpenTelemetry integration
- `github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io` - Runtime context
- `github.com/CodeMonkeyCybersecurity/eos/pkg/xdg` - XDG directory handling

## Related Documentation

- [CLAUDE.md](../../CLAUDE.md) - Project-wide logging requirements and patterns
- [pkg/eos_io/context.go](../eos_io/context.go) - Runtime context documentation
- [pkg/eos_cli/wrap.go](../eos_cli/wrap.go) - Command wrapper integration