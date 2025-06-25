# Delphi Services Management

This module provides comprehensive CRUD operations and management capabilities for the Delphi data pipeline systemd services.

## Overview

The Delphi services module follows the Eos CRUD architecture pattern, providing standardized operations for managing security monitoring services. It handles service deployment, configuration, lifecycle management, and monitoring.

## Available Services

| Service | Description | Purpose |
|---------|-------------|---------|
| `delphi-listener` | Webhook listener for Wazuh alerts | Receives and processes incoming security alerts |
| `delphi-agent-enricher` | Agent enrichment service | Adds contextual information to alerts |
| `delphi-emailer` | Email notification service | Sends formatted alert notifications |
| `llm-worker` | LLM processing service | Processes alerts using AI for analysis |
| `prompt-ab-tester` | A/B testing worker | Tests different AI prompts for optimization |

## CRUD Operations

### Create - Deploy a Service
```bash
eos delphi services create <service-name>
```

**What it does:**
1. Deploys the service worker script to `/usr/local/bin/`
2. Creates the systemd service file in `/etc/systemd/system/`
3. Sets appropriate permissions and ownership
4. Creates required configuration directories
5. Reloads systemd daemon

**Examples:**
```bash
eos delphi services create llm-worker
eos delphi services create prompt-ab-tester
```

**Requirements:**
- Root privileges
- Source files available in `/opt/eos/assets/`

### Read - View Service Details
```bash
eos delphi services read <service-name> [--show-config]
```

**What it displays:**
- Service status and health information
- File existence and permissions
- Configuration file locations
- Dependencies
- Recent logs (last 10 lines)
- Service configuration content (with `--show-config`)

**Examples:**
```bash
eos delphi services read llm-worker
eos delphi services read prompt-ab-tester --show-config
```

### Update - Update Service Files
```bash
eos delphi services update <service-name>
```

**What it does:**
- Backs up existing worker files
- Updates worker scripts to latest version
- Preserves configuration files
- Maintains service state

**Note:** Uses the existing update functionality that was already implemented.

### Delete - Remove Service
```bash
eos delphi services delete <service-name> [--force]
```

**What it does:**
1. Stops the service if running
2. Disables the service from auto-start
3. Removes the systemd service file
4. Removes the worker script
5. Reloads systemd daemon

**Important:** Configuration files and data are preserved.

**Examples:**
```bash
eos delphi services delete llm-worker
eos delphi services delete prompt-ab-tester --force  # Ignore stop/disable failures
```

### List - Show All Services
```bash
eos delphi services list [--detailed]
```

**What it shows:**
- All available services with status icons
- Current status (active/inactive/failed)
- Installation status
- Auto-start configuration
- Summary statistics

**Status Icons:**
-  Active and running
-  Installed but stopped
- 🔥 Failed state
-  Not installed

**Examples:**
```bash
eos delphi services list
eos delphi services list --detailed
```

## Service Management Operations

### Lifecycle Control
```bash
eos delphi services start <service-name>    # Start service
eos delphi services stop <service-name>     # Stop service
eos delphi services restart <service-name>  # Restart service
```

### Auto-start Configuration
```bash
eos delphi services enable <service-name>   # Enable auto-start
eos delphi services disable <service-name>  # Disable auto-start
```

### Monitoring
```bash
eos delphi services status <service-name>   # View status
eos delphi services logs <service-name>     # View logs
```

## Special Operations

### Dependency Management
```bash
eos delphi services check              # Check Python dependencies
eos delphi services preflight-install # Install required dependencies
```

### A/B Testing
```bash
eos delphi services deploy-ab-config   # Deploy A/B testing configuration
eos delphi services analyze-ab-results # Analyze test results
```

### Email Templates
```bash
eos delphi services deploy-template    # Deploy email notification template
```

## Service Configuration

### File Locations

| Service | Worker Script | Service File | Configuration |
|---------|---------------|--------------|---------------|
| delphi-listener | `/usr/local/bin/delphi-listener.py` | `/etc/systemd/system/delphi-listener.service` | `/opt/stackstorm/packs/delphi/.env` |
| delphi-agent-enricher | `/usr/local/bin/delphi-agent-enricher.py` | `/etc/systemd/system/delphi-agent-enricher.service` | `/opt/stackstorm/packs/delphi/.env` |
| delphi-emailer | `/usr/local/bin/delphi-emailer.py` | `/etc/systemd/system/delphi-emailer.service` | `/opt/stackstorm/packs/delphi/.env`<br>`/opt/delphi/email-template.html` |
| llm-worker | `/usr/local/bin/llm-worker.py` | `/etc/systemd/system/llm-worker.service` | `/opt/stackstorm/packs/delphi/.env`<br>`/srv/eos/system-prompts/default.txt` |
| prompt-ab-tester | `/usr/local/bin/prompt-ab-tester.py` | `/etc/systemd/system/prompt-ab-tester.service` | `/opt/stackstorm/packs/delphi/.env`<br>`/opt/delphi/ab-test-config.json`<br>`/srv/eos/system-prompts/` |

### Dependencies

**System Packages:**
- `python3`
- `python3-pip`

**Python Packages:**
- `psycopg2-binary` (PostgreSQL adapter)
- `requests` (HTTP client)
- `python-dotenv` (Environment variables)
- `openai` (Azure OpenAI API - for LLM services)

## Workflow Examples

### Complete Service Deployment
```bash
# 1. Install dependencies
sudo eos delphi services preflight-install

# 2. Create and deploy service
sudo eos delphi services create llm-worker

# 3. Configure environment variables (manual step)
sudo nano /opt/stackstorm/packs/delphi/.env

# 4. Deploy prompt files
sudo mkdir -p /srv/eos/system-prompts
sudo cp your-prompts/*.txt /srv/eos/system-prompts/

# 5. Enable and start service
sudo eos delphi services enable llm-worker
sudo eos delphi services start llm-worker

# 6. Verify deployment
eos delphi services read llm-worker
eos delphi services status llm-worker
```

### A/B Testing Setup
```bash
# 1. Deploy A/B tester service
sudo eos delphi services create prompt-ab-tester

# 2. Deploy A/B configuration
sudo eos delphi services deploy-ab-config

# 3. Configure test prompts
sudo cp test-prompts/*.txt /srv/eos/system-prompts/

# 4. Start testing
sudo eos delphi services enable prompt-ab-tester
sudo eos delphi services start prompt-ab-tester

# 5. Monitor and analyze
eos delphi services logs prompt-ab-tester
eos delphi services analyze-ab-results
```

### Service Maintenance
```bash
# Update all services
for service in delphi-listener delphi-agent-enricher delphi-emailer llm-worker prompt-ab-tester; do
    sudo eos delphi services update $service
done

# Check service health
eos delphi services list --detailed

# Restart problematic services
sudo eos delphi services restart llm-worker

# Clean up unused services
sudo eos delphi services delete old-service-name
```

## Security Considerations

### File Permissions
- Worker scripts: `755` (root:root)
- Service files: `644` (root:root)
- Configuration files: Vary by service requirements

### Service Isolation
- Services run as dedicated users when configured
- Systemd provides process isolation
- Configuration files contain sensitive information (database credentials, API keys)

### Access Control
- Service management requires root privileges
- Configuration files should be readable only by service users
- Log files may contain sensitive alert data

## Troubleshooting

### Common Issues

**Service Won't Start:**
```bash
# Check service status
eos delphi services read service-name

# View detailed logs
eos delphi services logs service-name

# Check configuration
eos delphi services read service-name --show-config
```

**Dependencies Missing:**
```bash
# Check dependencies
eos delphi services check

# Install missing dependencies
sudo eos delphi services preflight-install
```

**Configuration Issues:**
```bash
# Verify configuration files exist
eos delphi services read service-name

# Check environment variables
sudo cat /opt/stackstorm/packs/delphi/.env

# Validate database connectivity
sudo -u postgres psql -c "SELECT version();"
```

### Log Locations
- Service logs: `journalctl -u service-name`
- Application logs: `/var/log/stackstorm/`
- A/B testing metrics: `/var/log/stackstorm/ab-test-metrics.log`

## Integration

### Database Requirements
- PostgreSQL server with delphi database
- Connection string in `/opt/stackstorm/packs/delphi/.env`
- LISTEN/NOTIFY channels for inter-service communication

### External APIs
- Azure OpenAI API for LLM services
- SMTP server for email notifications
- Webhook endpoints for alert ingestion

## Development

### Adding New Services
1. Create worker script in `/opt/eos/assets/python_workers/`
2. Create service file in `/opt/eos/assets/services/`
3. Add service configuration to `GetServiceConfigurations()` in `create.go`
4. Update service lists in commands

### Testing
```bash
# Compile and test
go build -o /tmp/eos-build ./cmd/
golangci-lint run

# Test commands
go run . delphi services list
go run . delphi services read llm-worker
```

---

*This documentation covers the Delphi services management module that implements the Eos CRUD architecture pattern for comprehensive service lifecycle management.*