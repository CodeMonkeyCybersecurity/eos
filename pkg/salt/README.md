# Salt REST API Client

*Last Updated: 2025-01-23*

This package provides a Go client for interacting with the Salt REST API (salt-api), enabling programmatic control of Salt infrastructure without shell execution.

## Features

- **Authentication Management**: Automatic token management with refresh
- **Command Execution**: Synchronous and asynchronous Salt command execution
- **State Application**: Apply Salt states with real-time progress tracking
- **Event Streaming**: Monitor Salt events via server-sent events
- **Retry Logic**: Built-in retry with exponential backoff
- **Type Safety**: Strongly typed requests and responses
- **Context Support**: Full context cancellation support

## Configuration

Set the following environment variables:

```bash
export SALT_API_URL="https://salt-master.example.com:8080"
export SALT_API_USER="eos-service"
export SALT_API_PASSWORD="secure-password"
export SALT_API_INSECURE="false"  # Set to true for self-signed certificates in dev
```

## Usage Examples

### Basic Command Execution

```go
import (
    "context"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
    "go.uber.org/zap"
)

// Create client
config := salt.ClientConfig{
    BaseURL:  "https://salt-master:8080",
    Username: "eos-service",
    Password: "password",
    Logger:   zap.NewProduction(),
}

client, err := salt.NewClient(config)
if err != nil {
    log.Fatal(err)
}

// Execute a command
cmd := salt.Command{
    Client:   "local",
    Target:   "*",
    Function: "test.ping",
}

result, err := client.ExecuteCommand(context.Background(), cmd)
if err != nil {
    log.Fatal(err)
}

// Process results
for minion, response := range result.Raw {
    fmt.Printf("%s: %v\n", minion, response)
}
```

### State Application with Progress

```go
// Apply a state with progress tracking
pillar := map[string]interface{}{
    "consul": map[string]interface{}{
        "datacenter": "dc1",
        "ui_enabled": true,
    },
}

result, err := client.ExecuteStateApply(
    context.Background(),
    "hashicorp.consul",
    pillar,
    func(progress salt.StateProgress) {
        if progress.Completed {
            fmt.Printf("✓ %s - %s\n", progress.State, progress.Message)
        } else {
            fmt.Printf("... %s\n", progress.Message)
        }
    },
)

if err != nil {
    log.Fatal(err)
}

if result.Failed {
    fmt.Printf("State failed with errors: %v\n", result.Errors)
}
```

## Architecture

The client uses:
- `hashicorp/go-retryablehttp` for automatic retries
- Token-based authentication with automatic refresh
- Mutex-protected token management for thread safety
- Context-aware operations for proper cancellation

## Testing

Run tests with:

```bash
go test -v ./pkg/salt/...
```

## Security Considerations

1. Always use HTTPS in production
2. Store credentials securely (use environment variables or secrets management)
3. Use minimal permissions for the Salt API user
4. Enable audit logging on the Salt master
5. Rotate API tokens regularly

## Error Handling

The client provides typed errors:
- `ErrAuthenticationFailed`: Authentication issues
- `ErrTokenExpired`: Token needs refresh
- `ErrNoResults`: No results from command
- `ErrStateExecutionFailed`: State application failed

## Performance

- Connection pooling with configurable limits
- Automatic retry with exponential backoff
- Configurable timeouts for long-running operations
- Efficient event streaming for state progress