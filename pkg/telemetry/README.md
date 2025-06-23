# Telemetry Package

This package provides local telemetry collection for Eos CLI usage statistics and performance metrics.

## Overview

The telemetry system collects OpenTelemetry spans containing command execution data and stores them locally in JSONL (JSON Lines) format. **No data is transmitted to external servers** - all telemetry remains on the local machine for privacy and security.

## Implementation Details

### File Storage

Telemetry data is stored in JSONL format at:
- **Production (Ubuntu)**: `/var/log/eos/telemetry.jsonl`  
- **Development (macOS/fallback)**: `~/.eos/telemetry/telemetry.jsonl`

The system automatically creates the appropriate directory structure and falls back to the user directory if system-wide storage is not available.

### Data Collection

Each telemetry span contains:
- **Command name**: The Eos command that was executed
- **Execution duration**: Time taken in milliseconds
- **Success/failure status**: Whether the command completed successfully
- **Anonymous user ID**: UUID-based identifier (stored in `~/.eos/telemetry_id`)
- **System context**: OS, hostname, command arguments (truncated for privacy)
- **Timestamps**: ISO 8601 format for accurate timing analysis

### Privacy Controls

- **Opt-in**: Telemetry is disabled by default
- **Local storage only**: No external transmission or remote endpoints
- **Anonymous identification**: No personally identifiable information
- **Argument truncation**: Command arguments are truncated to 256 characters
- **User control**: Full control via `eos self telemetry [on|off|status]`

## Usage

### Enable/Disable Telemetry

```bash
# Enable telemetry collection
eos self telemetry on

# Disable telemetry collection  
eos self telemetry off

# Check telemetry status and view statistics
eos self telemetry status
```

### Analyzing Telemetry Data

Since the data is stored in JSONL format, you can use standard Unix tools and `jq` for analysis:

```bash
# Most frequently used commands
jq -r '.name' /var/log/eos/telemetry.jsonl | sort | uniq -c | sort -nr

# Success rate analysis
jq -r 'select(.attributes.success == true) | .name' /var/log/eos/telemetry.jsonl | wc -l

# Command duration analysis
jq -r 'select(.attributes.duration_ms) | "\(.name) \(.attributes.duration_ms)"' /var/log/eos/telemetry.jsonl

# Error analysis
jq -r 'select(.attributes.success == false) | .name' /var/log/eos/telemetry.jsonl | sort | uniq -c

# Usage patterns by hour
jq -r '.timestamp' /var/log/eos/telemetry.jsonl | cut -c12-13 | sort | uniq -c
```

## Configuration Files

The telemetry system uses simple file-based configuration:

- **Enable/disable state**: `~/.eos/telemetry_on` (presence indicates enabled)
- **Anonymous user ID**: `~/.eos/telemetry_id` (UUID for correlation)
- **Telemetry data**: `/var/log/eos/telemetry.jsonl` or `~/.eos/telemetry/telemetry.jsonl`

## Integration with Eos

The telemetry system is deeply integrated with the Eos runtime:

1. **Initialization**: Called in `cmd/root.go` via `telemetry.Init("eos")`
2. **Span creation**: Automatic span creation for all commands via `RuntimeContext.End()`
3. **Structured logging**: Integrated with `otelzap` for consistent logging
4. **Error classification**: Distinguishes between user errors and system errors

## Design Decisions

### Why JSONL Format?

- **Streamable**: Can be processed line-by-line without loading entire file
- **Append-friendly**: New entries can be appended without file restructuring
- **Tool-friendly**: Works with standard Unix tools like `jq`, `grep`, `awk`
- **Human-readable**: JSON format is easy to inspect and debug

### Why Local Storage Only?

- **Privacy**: No external data transmission reduces privacy concerns
- **Security**: No network dependencies or external endpoints to secure
- **Simplicity**: No complex configuration or authentication requirements
- **Reliability**: Works offline and in air-gapped environments

### Why File-based Configuration?

- **Simplicity**: No complex configuration system needed
- **Persistence**: Settings survive system reboots
- **Transparency**: Configuration is visible and auditable
- **Compatibility**: Works across different deployment scenarios

## Future Enhancements

Potential future improvements include:

- **Metrics collection**: Beyond spans, collect system metrics
- **Retention policies**: Automatic cleanup of old telemetry data
- **Export formats**: Support for other analysis tools (CSV, Parquet, etc.)
- **Sampling**: Configurable sampling rates for high-volume usage
- **Aggregation**: Pre-computed statistics for faster analysis

## Troubleshooting

### Telemetry Not Working

1. **Check if enabled**: `eos self telemetry status`
2. **Verify file permissions**: Ensure write access to telemetry directory
3. **Check disk space**: Ensure sufficient space for telemetry file
4. **Review logs**: Check Eos logs for telemetry-related errors

### File Location Issues

- **System directory**: `/var/log/eos/` requires appropriate permissions
- **Fallback directory**: `~/.eos/telemetry/` is automatically created
- **Permissions**: Ensure directories have correct ownership and permissions

### Data Analysis Issues

- **Malformed JSON**: Use `jq` to validate JSONL format
- **Missing fields**: Check span structure matches expected format
- **Timestamp parsing**: Ensure timestamps are in ISO 8601 format