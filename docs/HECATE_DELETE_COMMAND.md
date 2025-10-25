# Hecate Delete Command

*Last Updated: 2025-10-19*

## Overview

Created comprehensive `eos delete hecate` command that properly removes all Hecate components including Docker containers, configuration files, and Consul KV data.

## Command Usage

```bash
# Interactive deletion with confirmation
sudo eos delete hecate

# Skip confirmation prompts
sudo eos delete hecate --force

# Keep Consul data (only remove containers and files)
sudo eos delete hecate --keep-data
```

## What Gets Deleted

### 1. Docker Containers & Volumes
- Stops and removes all Hecate containers via `docker compose down -v`
- Removes Docker volumes:
  - `hecate_database` (PostgreSQL data)
  - `hecate_redis` (Redis data)
  - `hecate_caddy_data` (Caddy certificates)
  - `hecate_caddy_config` (Caddy configuration)

### 2. Configuration Files
- Removes entire `/opt/hecate/` directory including:
  - `docker-compose.yml`
  - `.env` (secrets)
  - `Caddyfile`
  - `logs/`
  - `media/`
  - `custom-templates/`
  - `authentik/blueprints/`

### 3. Consul KV Data (unless --keep-data)
Removes all Hecate configuration stored in Consul:
- `hecate/routes/` - Route configurations
- `hecate/dns/` - DNS records
- `hecate/auth-policies/` - Authentication policies
- `hecate/vault-policies/` - Vault policy configurations
- `hecate/streams/` - Stream configurations
- `hecate/stream-operations/` - Stream operation logs
- `hecate/dns-operations/` - DNS operation logs
- `hecate/dns-reconciler/` - DNS reconciler schedules
- `hecate/hybrid/` - Hybrid backend configurations
- `hecate/backends/` - Backend server configurations
- `hecate/config/` - General configuration

## Consul Data Storage

**Yes, Hecate extensively uses Consul KV for configuration storage!**

Hecate stores the following in Consul:
- **Routes**: Domain routing configurations
- **DNS Records**: Managed DNS entries
- **Auth Policies**: Authentik authentication policies
- **Vault Policies**: Vault access control policies
- **Streams**: Stream processing configurations
- **Operations Log**: DNS and stream operation history
- **Hybrid Backends**: Backend server discovery and certificates
- **General Config**: Application-wide settings

This allows Hecate to:
- Maintain configuration across container restarts
- Share configuration between multiple instances
- Provide service discovery for backends
- Store operational history and audit logs

## Safety Features

### Confirmation Prompt
Unless `--force` is specified, the command shows a warning and requires confirmation:

```
  WARNING: This will delete:
  - All Docker containers and volumes
  - Configuration files in /opt/hecate
  - All Consul KV data (routes, DNS, auth policies, etc.)

Are you sure you want to continue? [y/N]:
```

### Graceful Failure Handling
- Continues even if some steps fail (e.g., containers already removed)
- Logs warnings for failed operations but doesn't abort
- Checks for directory existence before attempting removal

### Keep Data Option
The `--keep-data` flag allows you to:
- Remove containers and files
- Keep Consul configuration for later restoration
- Useful for troubleshooting or temporary removal

## Implementation Details

**File:** `cmd/delete/hecate.go`

**Functions:**
1. `runDeleteHecate()` - Main orchestration with 4 steps
2. `stopDockerContainers()` - Stops containers via docker compose down
3. `removeDockerVolumes()` - Removes named Docker volumes
4. `cleanConsulData()` - Deletes Consul KV trees
5. `removeHecateFiles()` - Removes /opt/hecate directory

**Error Handling:**
- Follows `claude.md` P1 guidelines for error context
- Uses structured logging with `otelzap.Ctx(rc.Ctx)`
- Provides actionable error messages
- Continues on non-critical failures

## Example Output

```bash
$ sudo eos delete hecate
INFO Starting Hecate deletion process

  WARNING: This will delete:
  - All Docker containers and volumes
  - Configuration files in /opt/hecate
  - All Consul KV data (routes, DNS, auth policies, etc.)

Are you sure you want to continue? [y/N]: y

[1/4] Stopping Docker containers...
INFO Docker containers stopped and removed

[2/4] Removing Docker volumes...
INFO Removed Docker volume {"volume": "hecate_database"}
INFO Removed Docker volume {"volume": "hecate_redis"}
INFO Removed Docker volume {"volume": "hecate_caddy_data"}
INFO Removed Docker volume {"volume": "hecate_caddy_config"}

[3/4] Cleaning Consul KV data...
INFO Deleted Consul KV tree {"prefix": "hecate/routes/"}
INFO Deleted Consul KV tree {"prefix": "hecate/dns/"}
INFO Deleted Consul KV tree {"prefix": "hecate/auth-policies/"}
...

[4/4] Removing configuration files...
INFO Removed Hecate directory {"directory": "/opt/hecate"}

✓ Hecate deletion completed successfully
```

## Related Commands

- `eos create hecate` - Deploy Hecate
- `eos read hecate` - View Hecate status
- `eos delete hecate-backend` - Delete specific backend
- `eos delete hecate-route` - Delete specific route

## Notes

- Requires root/sudo access for Docker and file operations
- Requires Consul to be running for KV cleanup
- Safe to run multiple times (idempotent)
- Does not remove Consul or Docker itself
- Does not affect other services using Consul

---

*This command provides a clean, complete removal of Hecate while preserving the option to keep configuration data for future restoration.*
