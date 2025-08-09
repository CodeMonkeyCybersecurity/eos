# PATTERNS.md

*Last Updated: 2025-01-07*

Detailed code patterns and examples for the Eos project. This file contains the verbose examples referenced in CLAUDE.md.

## Table of Contents
- [Logging Patterns](#logging)
- [Error Handling](#errors)
- [Assess → Intervene → Evaluate Pattern](#aie-pattern)
- [Interactive Prompting](#prompting)
- [Helper Structure](#helpers)
- [Command Implementation](#commands)
- [Testing Patterns](#testing)

## Logging Patterns {#logging}

### Correct Structured Logging
```go
func InstallPackage(rc *eos_io.RuntimeContext, pkgName string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    logger.Info("Installing package",
        zap.String("package", pkgName),
        zap.String("action", "install"),
        zap.String("phase", "start"))
    
    // ... installation logic ...
    
    logger.Info("Package installed successfully",
        zap.String("package", pkgName),
        zap.Duration("duration", time.Since(start)))
    
    return nil
}
```

### NEVER Do This
```go
// WRONG - Never use fmt for output
func BadExample(pkgName string) error {
    fmt.Printf("Installing %s\n", pkgName)  // NEVER!
    fmt.Println("Done!")                    // NEVER!
    return nil
}
```

## Error Handling {#errors}

### Error Classification
```go
// User-correctable error (exit code 0)
if _, err := exec.LookPath("terraform"); err != nil {
    return eos_err.NewUserError("terraform not found in PATH - please install terraform first")
}

// System error (exit code 1)
if err := ioutil.WriteFile(path, data, 0644); err != nil {
    return eos_err.NewSystemError("failed to write config file: %w", err)
}

// Wrapped errors with context
if err := doOperation(); err != nil {
    return fmt.Errorf("failed to complete operation X: %w", err)
}
```

## Assess → Intervene → Evaluate Pattern {#aie-pattern}

### Complete Helper Implementation
```go
func InstallPackage(rc *eos_io.RuntimeContext, pkgName string) error {
    logger := otelzap.Ctx(rc.Ctx)

    // ASSESS - Can I execute?
    logger.Info("Checking if we can install package", zap.String("package", pkgName))

    // Check permissions
    if os.Geteuid() != 0 {
        return eos_err.NewUserError("package installation requires root privileges, please run with sudo")
    }

    // Check command availability
    if _, err := exec.LookPath("apt-get"); err != nil {
        return eos_err.NewUserError("apt-get not found - this command requires Ubuntu")
    }

    // Check for locks
    if _, err := os.Stat("/var/lib/dpkg/lock"); err == nil {
        return eos_err.NewUserError("package manager is locked by another process")
    }

    // INTERVENE - Execute
    logger.Info("Installing package", zap.String("package", pkgName))

    output, err := execute.Run(rc.Ctx, execute.Options{
        Command: "apt-get",
        Args:    []string{"install", "-y", pkgName},
        Capture: true,
    })
    if err != nil {
        return fmt.Errorf("package installation failed: %w", err)
    }

    // EVALUATE - Verify it worked
    logger.Info("Verifying package installation")

    output, err = execute.Run(rc.Ctx, execute.Options{
        Command: "dpkg",
        Args:    []string{"-l", pkgName},
        Capture: true,
    })
    if err != nil || !strings.Contains(output, "ii") {
        return fmt.Errorf("package verification failed - package may not be installed correctly")
    }

    logger.Info("Package installed successfully", zap.String("package", pkgName))
    return nil
}
```

### Key Checks to Include
- Permission checks: `os.Geteuid()`, file permissions
- Command availability: `exec.LookPath()`
- Service status: `systemctl is-active`
- File/directory existence: `os.Stat()`
- Resource availability: disk space, memory
- Lock files: dpkg lock, apt lock
- Network connectivity: for downloads
- Configuration validity: before applying

## Interactive Prompting {#prompting}

### Prompting for Missing Input
```go
func GetUserInput(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Prompt for username if not provided
    if config.Username == "" {
        logger.Info("Username not provided via flag, prompting user")
        logger.Info("terminal prompt: Please enter username")
        
        username, err := eos_io.PromptInput(rc, "Username: ")
        if err != nil {
            return fmt.Errorf("failed to read username: %w", err)
        }
        config.Username = username
    }
    
    // Prompt for password securely
    if config.Password == "" {
        logger.Info("Password not provided via flag, prompting user")
        logger.Info("terminal prompt: Please enter password")
        
        password, err := eos_io.PromptSecurePassword(rc, "Password: ")
        if err != nil {
            return fmt.Errorf("failed to read password: %w", err)
        }
        config.Password = password
    }
    
    return nil
}
```

## Helper Structure {#helpers}

### Standard Package Layout
```go
// pkg/toolname/types.go
package toolname

type Config struct {
    Version     string
    InstallPath string
    MasterMode  bool
}

const (
    DefaultVersion = "latest"
    DefaultPath    = "/opt/toolname"
)
```

```go
// pkg/toolname/install.go
package toolname

func Install(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS
    if err := checkPrerequisites(rc); err != nil {
        return fmt.Errorf("prerequisites check failed: %w", err)
    }
    
    // INTERVENE
    if err := performInstallation(rc, config); err != nil {
        return fmt.Errorf("installation failed: %w", err)
    }
    
    // EVALUATE
    if err := verifyInstallation(rc); err != nil {
        return fmt.Errorf("verification failed: %w", err)
    }
    
    return nil
}
```

## Command Implementation {#commands}

### Complete Command Example
```go
// cmd/create/saltstack.go
package create

import (
    "github.com/spf13/cobra"
    "your-repo/pkg/eos_cli"
    "your-repo/pkg/eos_io"
    "your-repo/pkg/saltstack"
)

var createSaltstackCmd = &cobra.Command{
    Use:   "saltstack",
    Short: "Install and configure SaltStack",
    Long: `Install and configure SaltStack in masterless mode by default.
This command will install Salt, configure it for local management,
and verify the installation is working correctly.`,
    RunE: eos_cli.Wrap(runCreateSaltstack),
}

func init() {
    createCmd.AddCommand(createSaltstackCmd)
    
    // Define flags with sensible defaults
    createSaltstackCmd.Flags().Bool("master-mode", false, 
        "Install as master-minion instead of masterless")
    createSaltstackCmd.Flags().String("log-level", "warning", 
        "Salt log level (debug, info, warning, error)")
    createSaltstackCmd.Flags().String("version", "latest",
        "Salt version to install (prompted if not provided)")
}

func runCreateSaltstack(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Parse flags into configuration
    masterMode, _ := cmd.Flags().GetBool("master-mode")
    logLevel, _ := cmd.Flags().GetString("log-level")
    version, _ := cmd.Flags().GetString("version")
    
    config := &saltstack.Config{
        MasterMode: masterMode,
        LogLevel:   logLevel,
        Version:    version,
    }
    
    // Prompt for any missing required values
    if config.Version == "" {
        logger.Info("Version not provided, prompting user")
        logger.Info("terminal prompt: Please enter Salt version to install")
        
        version, err := eos_io.PromptInput(rc, "Version (latest): ")
        if err != nil {
            return fmt.Errorf("failed to read version: %w", err)
        }
        if version == "" {
            version = "latest"
        }
        config.Version = version
    }
    
    // Orchestrate helpers - NO business logic here
    logger.Info("Beginning SaltStack installation")
    
    if err := saltstack.Install(rc, config); err != nil {
        return err // Error already wrapped by helper
    }
    
    if err := saltstack.Configure(rc, config); err != nil {
        return err
    }
    
    if err := saltstack.Verify(rc); err != nil {
        return err
    }
    
    logger.Info("SaltStack installation completed successfully")
    return nil
}
```

## Testing Patterns {#testing}

### Unit Test Structure
```go
// pkg/saltstack/install_test.go
package saltstack

import (
    "testing"
    "your-repo/pkg/eos_io"
)

func TestInstall(t *testing.T) {
    tests := []struct {
        name    string
        config  *Config
        setup   func(*testing.T)
        wantErr bool
    }{
        {
            name: "successful installation",
            config: &Config{
                MasterMode: false,
                Version:    "3004",
            },
            setup: func(t *testing.T) {
                // Mock successful conditions
                // Set up test environment
            },
            wantErr: false,
        },
        {
            name: "fails when already installed",
            config: &Config{
                MasterMode: false,
                Version:    "3004",
            },
            setup: func(t *testing.T) {
                // Mock already installed condition
                // Create marker files
            },
            wantErr: true,
        },
        {
            name: "fails without root privileges",
            config: &Config{
                MasterMode: false,
                Version:    "3004",
            },
            setup: func(t *testing.T) {
                // Mock non-root user
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.setup(t)
            
            rc := eos_io.NewTestContext(t)
            err := Install(rc, tt.config)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("Install() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Integration Test Pattern
```go
// integration_test.go
func TestSaltStackIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    rc := eos_io.NewTestContext(t)
    config := &saltstack.Config{
        MasterMode: false,
        Version:    "latest",
    }
    
    // Full end-to-end test
    if err := saltstack.Install(rc, config); err != nil {
        t.Fatalf("Install failed: %v", err)
    }
    
    if err := saltstack.Configure(rc, config); err != nil {
        t.Fatalf("Configure failed: %v", err)
    }
    
    if err := saltstack.Verify(rc); err != nil {
        t.Fatalf("Verify failed: %v", err)
    }
    
    // Test actual functionality
    output, err := exec.Command("salt-call", "--version").Output()
    if err != nil {
        t.Fatalf("Salt not working after installation: %v", err)
    }
    
    if !strings.Contains(string(output), "salt") {
        t.Errorf("Unexpected version output: %s", output)
    }
}
```

## Idempotency Examples

### Checking Before Acting
```go
func InstallService(rc *eos_io.RuntimeContext, serviceName string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Check if already installed
    if isServiceInstalled(serviceName) {
        logger.Info("Service already installed, skipping", 
            zap.String("service", serviceName))
        return nil  // Not an error - idempotent
    }
    
    // Proceed with installation
    logger.Info("Installing service", zap.String("service", serviceName))
    // ... installation logic ...
    
    return nil
}
```

### State-Based Operations
```go
func EnsureServiceRunning(rc *eos_io.RuntimeContext, serviceName string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Check current state
    running, err := isServiceRunning(serviceName)
    if err != nil {
        return fmt.Errorf("failed to check service status: %w", err)
    }
    
    if running {
        logger.Debug("Service already running", zap.String("service", serviceName))
        return nil
    }
    
    // Start the service
    logger.Info("Starting service", zap.String("service", serviceName))
    if err := startService(serviceName); err != nil {
        return fmt.Errorf("failed to start service: %w", err)
    }
    
    return nil
}
```

## Architecture Implementation Examples

### Infrastructure Service (SaltStack)
```go
// cmd/create/consul.go
func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check SaltStack availability
    if _, err := exec.LookPath("salt-call"); err != nil {
        return eos_err.NewUserError("saltstack is required for infrastructure services")
    }
    
    // Build pillar data
    datacenter, _ := cmd.Flags().GetString("datacenter")
    pillarData := map[string]interface{}{
        "consul": map[string]interface{}{
            "datacenter": datacenter,
            "ui_enabled": true,
        },
    }
    
    // INTERVENE - Apply SaltStack state
    logger.Info("Deploying Consul via SaltStack")
    if err := applySaltState(rc, "hashicorp.consul", pillarData); err != nil {
        return fmt.Errorf("failed to apply consul state: %w", err)
    }
    
    // EVALUATE - Verify service running
    return verifyService(rc, "consul")
}
```

### Application Service (Nomad)
```go
// cmd/create/grafana.go  
func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check Nomad availability
    if err := checkNomadRunning(rc); err != nil {
        return eos_err.NewUserError("nomad is required for application services")
    }
    
    // Build job configuration
    port, _ := cmd.Flags().GetInt("port")
    jobConfig := map[string]interface{}{
        "service_name": "grafana",
        "port":         port,
        "image":        "grafana/grafana:latest",
    }
    
    // INTERVENE - Deploy Nomad job
    logger.Info("Deploying Grafana via Nomad")
    if err := deployNomadJob(rc, "grafana", jobConfig); err != nil {
        return fmt.Errorf("failed to deploy grafana: %w", err)
    }
    
    // EVALUATE - Verify job running and healthy
    return verifyNomadJob(rc, "grafana")
}
```