# Self-Management Commands

The `eos self` command group provides machine-specific configuration and management capabilities for Eos installations.

## Available Commands

### `eos self telemetry`

Manages local telemetry collection for usage statistics and performance monitoring.

```bash
# Enable telemetry collection
eos self telemetry on

# Disable telemetry collection  
eos self telemetry off

# View telemetry status and statistics
eos self telemetry status
```

#### Telemetry Features

- **Local storage only**: No external data transmission
- **Privacy-focused**: Anonymous collection with configurable controls
- **Statistical analysis**: Built-in usage statistics and performance metrics
- **JSONL format**: Standard format compatible with common analysis tools

#### Example Output

```bash
$ eos self telemetry status
INFO    📊 Telemetry Status     {"enabled": true, "config_file": "/home/user/.eos/telemetry_on", "data_file": "/var/log/eos/telemetry.jsonl"}
INFO    📈 Telemetry Statistics {"total_commands": 156, "successful_commands": 142, "failed_commands": 14, "success_rate_percent": 91.0, "file_size": "45.2 KB", "oldest_entry": "2024-06-20 10:30:15", "newest_entry": "2024-06-23 16:45:22"}
INFO    🔝 Most Used Commands
INFO                            {"rank": 1, "command": "vault", "count": 45}
INFO                            {"rank": 2, "command": "create", "count": 32}
INFO                            {"rank": 3, "command": "read", "count": 28}
```

## Design Philosophy

The `self` command group follows these principles:

1. **Machine-specific**: Configuration that applies to individual Eos installations
2. **Local management**: Settings and data that don't require external dependencies
3. **Privacy-first**: Local storage and processing with no external transmission
4. **Developer-friendly**: Rich information and statistics for troubleshooting

## Integration with Eos Architecture

Self-management commands integrate with the core Eos architecture:

- **Runtime Context**: Uses `RuntimeContext` for consistent logging and error handling
- **Structured Logging**: All output uses structured logging with `otelzap`
- **Error Handling**: Follows Eos patterns for user vs system error classification
- **Configuration**: Follows Eos patterns for file-based configuration storage

## Future Commands

Planned additions to the `self` command group:

- **`eos self config`**: Machine-specific configuration management
- **`eos self vault`**: Local Vault client configuration and health checks
- **`eos self diagnostics`**: System health and troubleshooting information
- **`eos self backup`**: Local backup and restore of Eos configuration