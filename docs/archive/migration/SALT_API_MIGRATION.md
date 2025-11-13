#  API Migration Guide

*Last Updated: 2025-01-25*

## Overview

This document outlines the migration from direct  CLI commands (-call, -run, -key) to the unified  REST API using the CherryPy interface. All  operations in Eos must now go through the API for consistency, security, and remote management capabilities.

## Migration Status

### Completed
- [x] Created unified `.APIClient` for all  operations
- [x] Created `.ClientFactory` for consistent client creation
- [x] Created `.MigrationClient` for transitional period
- [x] Updated Consul deployment to use API-only approach

### In Progress
- [ ] Migrating all `-call` usage to API
- [ ] Migrating all `-run` usage to API  
- [ ] Migrating all `-key` usage to API
- [ ] Updating all packages to use `ClientFactory`

## API Configuration

The  API requires the following environment variables:

```bash
export _API_URL="https://localhost:8000"
export _API_USER="eos-service"
export _API_PASSWORD="<secure-password>"
export _API_EAUTH="pam"  # Optional, defaults to "pam"
export _API_INSECURE="false"  # Optional, for dev environments
```

## Usage Examples

### Creating a  Client

```go
// Always use the factory to create clients
factory := .NewClientFactory(rc)
client, err := factory.CreateClient()
if err != nil {
    return fmt.Errorf(" API not available: %w", err)
}
```

### State Application

```go
// Old way (DEPRECATED)
cmd := exec.Command("-call", "--local", "state.apply", "consul")

// New way
result, err := client.ExecuteStateApply(ctx, "consul", , progressFunc)
```

### Command Execution

```go
// Old way (DEPRECATED)
cmd := exec.Command("-call", "--local", "cmd.run", "systemctl status consul")

// New way
output, err := client.CmdRunLocal(ctx, "systemctl status consul")
```

### Key Management

```go
// Old way (DEPRECATED)
cmd := exec.Command("-key", "-L")

// New way
keyList, err := client.ListKeys(ctx)
```



## Migration Checklist

When migrating a package or command:

1. **Replace Direct Imports**
   - Remove: `os/exec`, direct command execution
   - Add: `github.com/CodeMonkeyCybersecurity/eos/pkg/`

2. **Use ClientFactory**
   ```go
   factory := .NewClientFactory(rc)
   client, err := factory.CreateClient()
   ```

3. **Update Function Calls**
   - Replace `exec.Command("-call", ...)` with appropriate API method
   - Replace `exec.Command("-run", ...)` with `RunnerExecute()`
   - Replace `exec.Command("-key", ...)` with key management methods

4. **Handle Errors Appropriately**
   - API errors should be wrapped with context
   - Check for `ErrAuthenticationFailed` and `ErrTokenExpired`

5. **Update Tests**
   - Mock the `Client` interface
   - Test both success and failure scenarios

## Common Patterns

### Local State Application
```go
// Apply state locally with  data
result, err := client.StateApplyLocal(ctx, "mystate", map[string]interface{}{
    "config": map[string]interface{}{
        "option1": "value1",
        "option2": true,
    },
})
```

### Service Management
```go
// Start a service
err := client.ServiceManage(ctx, "*", "consul", "start")

// Enable a service
err := client.ServiceManage(ctx, "*", "consul", "enable")
```

### Package Installation
```go
// Install packages
err := client.PkgInstall(ctx, "*", []string{"consul", "vault"})
```

### File Management
```go
// Create a file with specific permissions
err := client.FileManage(ctx, "*", "/etc/myapp/config.yml", configContent, "0640")
```

## Troubleshooting

### API Not Available

If the API is not available, check:

1.  API service is running: `systemctl status -api`
2. API configuration exists: `/etc//master.d/api.conf`
3. Credentials are correct in environment variables
4. Network connectivity to API endpoint

### Authentication Failures

1. Verify PAM user exists and has correct permissions
2. Check  master logs: `journalctl -u -master`
3. Ensure token hasn't expired (11-hour default)

### State Execution Failures

1. Check  file_roots configuration
2. Verify state files exist in correct location
3. Review  master logs for detailed errors

## Future Improvements

1. **Circuit Breaker**: Add circuit breaker pattern for API resilience
2. **Metrics**: Add Prometheus metrics for API calls
3. **Caching**: Implement intelligent caching for read operations
4. **Batch Operations**: Optimize multiple operations into batch calls
5. **WebSocket Support**: Use WebSocket for real-time event streaming