# Delphi Read Commands

This directory contains the read and diagnostic commands for Delphi (Wazuh) security monitoring platform integration. These commands provide comprehensive visibility into Wazuh manager configuration, users, API status, and agent connectivity.

## Commands Overview

### `eos delphi read`
Parent command for all Delphi read operations. Requires a subcommand to specify the type of information to read.

**Usage:** `eos delphi read <subcommand> [flags]`

**Aliases:** `inspect`, `get`

## Subcommands

### `api`
Read API details and perform authenticated queries against the Wazuh manager.

**Usage:** `eos delphi read api [flags]`

**Flags:**
- `--show-secrets`: Display sensitive fields like passwords and tokens
- `--permissions`: Display user permissions for the authenticated user
- `--version`: Display Wazuh manager version information

**Examples:**
```bash
# Check user permissions
eos delphi read api --permissions

# Get Wazuh manager version
eos delphi read api --version

# Show sensitive data (requires elevated privileges)
eos delphi read api --permissions --show-secrets
```

### `config`
Read the currently loaded Delphi configuration file.

**Usage:** `eos delphi read config [flags]`

**Aliases:** `cfg`, `settings`

**Flags:**
- `--show-secrets`: Display sensitive fields like passwords and tokens (masked by default)

**Examples:**
```bash
# View configuration with masked secrets
eos delphi read config

# View full configuration including secrets (requires elevated privileges)
eos delphi read config --show-secrets
```

### `credentials`
List all Delphi (Wazuh) user credentials and their status.

**Usage:** `eos delphi read credentials [flags]`

**Flags:**
- `--show-secrets`: Display sensitive fields like passwords and tokens

**Examples:**
```bash
# List all users with roles and status
eos delphi read credentials

# Include sensitive information (requires elevated privileges)
eos delphi read credentials --show-secrets
```

### `keepalive`
Check disconnected agents from the Wazuh API to monitor agent connectivity.

**Usage:** `eos delphi read keepalive`

**Description:** Queries the Wazuh API for agents with disconnected status and displays their last keepalive information.

**Examples:**
```bash
# Check disconnected agents
eos delphi read keepalive
```

### `users`
List Wazuh users and their associated user IDs.

**Usage:** `eos delphi read users`

**Description:** Fetches and displays all Wazuh users along with their user IDs from the Delphi (Wazuh) API.

**Examples:**
```bash
# List all Wazuh users
eos delphi read users
```

## Security Features

### Secrets Access Control
All commands that can display sensitive information implement security controls:

- **Elevated Privileges Required**: Commands with `--show-secrets` flag require elevated system privileges
- **Access Enforcement**: Uses `eos_unix.EnforceSecretsAccess()` to validate user permissions
- **Default Masking**: Sensitive fields are masked with `********` by default
- **Audit Logging**: All access to sensitive information is logged via structured logging

### Authentication Flow
Commands automatically handle Wazuh API authentication:

1. **Configuration Resolution**: Loads and validates Delphi configuration
2. **Token Validation**: Checks for existing valid authentication token
3. **Automatic Authentication**: Performs authentication if token is missing or expired
4. **Token Persistence**: Saves new tokens to configuration file
5. **Error Handling**: Provides clear error messages for authentication failures

## Configuration

### Delphi Configuration File
Commands read from the standard Delphi configuration file (`delphi.json`) which includes:

- **FQDN**: Wazuh manager hostname
- **Protocol**: Connection protocol (https/http)
- **Port**: API port (default: 55000)
- **Credentials**: API username and password
- **Token**: Authentication token (auto-managed)
- **Endpoints**: Custom API endpoints for specific operations

### Default Values
- **Protocol**: `https`
- **Port**: `55000`
- **Keepalive Endpoint**: `/agents?select=lastKeepAlive&select=id&status=disconnected`

## Error Handling

All commands implement comprehensive error handling:

- **Configuration Errors**: Clear messages for missing or invalid configuration
- **Authentication Failures**: Detailed authentication error reporting
- **API Errors**: HTTP status code reporting with context
- **Network Issues**: Connection timeout and network error handling
- **Permission Errors**: Clear messaging for insufficient privileges

## Logging

Commands use structured logging throughout:

- **OpenTelemetry Integration**: Full tracing and observability
- **Contextual Information**: Detailed request/response logging
- **Security Events**: Audit logging for sensitive operations
- **Error Context**: Comprehensive error context for troubleshooting

## Development Notes

### Package Structure
- **Authentication**: Shared authentication logic via `delphi.Authenticate()` and `delphi.ResolveConfig()`
- **API Calls**: Standardized API calling patterns via `delphi.AuthenticatedGet()` and `delphi.GetJSON()`
- **Response Handling**: Consistent response processing via `delphi.HandleAPIResponse()`
- **Error Patterns**: Unified error handling using `eos.Wrap()` and structured logging

### Dependencies
- **Cobra CLI**: Command structure and flag handling
- **Delphi Package**: Core Wazuh integration functionality
- **EOS CLI**: Runtime context and command wrapping
- **EOS Unix**: System-level security controls
- **OpenTelemetry**: Structured logging and observability
- **Zap**: High-performance logging library

### Security Considerations
- **Principle of Least Privilege**: Commands request minimal required permissions
- **Secure Defaults**: Sensitive information masked by default
- **Audit Trail**: All security-sensitive operations are logged
- **Input Validation**: All user inputs and API responses are validated
- **Token Management**: Secure handling of authentication tokens