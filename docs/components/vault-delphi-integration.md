# Vault Integration for Delphi Dashboard

*Last Updated: 2025-01-14*

## Overview

The Eos Delphi dashboard now supports secure credential management through HashiCorp Vault integration. This ensures that database passwords and other sensitive configuration data are stored securely and retrieved dynamically, rather than being hardcoded or stored in environment files.

## Quick Setup

### Option 1: Automated Setup (Recommended)
```bash
# Run the setup script for guided configuration
sudo /opt/eos/scripts/setup-vault-delphi.sh
```

### Option 2: Manual Setup
```bash
# 1. Configure Vault connection
eos self secrets configure

# 2. Set database credentials
eos self secrets set delphi-db

# 3. Test the configuration
eos self secrets test

# 4. Launch the dashboard
eos delphi dashboard
```

## Detailed Configuration

### Step 1: Vault Server Configuration

Configure your Vault server address and authentication:

```bash
eos self secrets configure
```

This interactive command will prompt you for:
- **Vault Address**: e.g., `https://vhost11:8200` or `https://stackstorm:8179`
- **Authentication Method**: 
  - Token (recommended for initial setup)
  - Username/Password (userpass auth)
  - AppRole (for production services)

### Step 2: Database Credentials

Store your Delphi database credentials securely in Vault:

```bash
eos self secrets set delphi-db
```

You'll be prompted for:
- Database host (default: localhost)
- Database port (default: 5432)
- Database name (default: delphi)
- Database username (default: delphi)
- Database password (secure input)

### Step 3: Verification

Test your configuration:

```bash
# Test Vault connectivity
eos self secrets test

# Check stored credentials
eos self secrets status

# Verify specific secrets (without showing values)
eos self secrets get delphi/database/username
```

## Usage

### Launching the Dashboard

Once configured, simply run:

```bash
eos delphi dashboard
```

The dashboard will automatically:
1. Connect to your configured Vault server
2. Retrieve database credentials
3. Establish a secure database connection
4. Launch the interactive interface

### Managing Secrets

#### View Secret Status
```bash
eos self secrets status
```

#### Update Database Credentials
```bash
eos self secrets set delphi-db
```

#### Set Additional Secrets
```bash
# SMTP credentials for email services
eos self secrets set smtp

# OpenAI API key for LLM services
eos self secrets set openai

# Custom application secrets
eos self secrets set custom
```

#### Retrieve Secrets
```bash
# Show masked values
eos self secrets get delphi/database/username

# Show actual values (use with caution)
eos self secrets get delphi/database/password --show-value
```

## Authentication Methods

### Token Authentication (Recommended for Setup)

Best for initial setup and development:

```bash
eos self secrets configure
# Select option 1 (Token)
# Enter your Vault token when prompted
```

### Username/Password Authentication

For environments using Vault's userpass auth method:

```bash
eos self secrets configure
# Select option 2 (Username/Password)
# Enter your Vault username and password
```

### AppRole Authentication

For production services and automated deployments:

```bash
eos self secrets configure
# Select option 3 (AppRole)
# Enter your Role ID and Secret ID
```

## Secret Storage Structure

Secrets are stored in Vault with the following paths:

### Database Credentials
- `delphi/database/host` - Database server hostname
- `delphi/database/port` - Database port (usually 5432)
- `delphi/database/name` - Database name (usually delphi)
- `delphi/database/username` - Database username
- `delphi/database/password` - Database password

### SMTP Configuration
- `smtp/host` - SMTP server hostname
- `smtp/port` - SMTP port (usually 587)
- `smtp/username` - SMTP username
- `smtp/password` - SMTP password

### API Keys
- `openai/api_key` - OpenAI API key for LLM services

## Troubleshooting

### Connection Issues

**Error**: `VAULT_ADDR unreachable over TLS`
```bash
# Check Vault server status
ping vhost11  # or your Vault server

# Verify Vault is running
curl -k https://vhost11:8200/v1/sys/health

# Reconfigure if needed
eos self secrets configure
```

**Error**: `password authentication failed for user "delphi"`
```bash
# Check if credentials are set in Vault
eos self secrets status

# Reconfigure database credentials
eos self secrets set delphi-db

# Test Vault connectivity
eos self secrets test
```

### Authentication Issues

**Error**: `Vault service initialization failed`
```bash
# Check VAULT_ADDR environment variable
echo $VAULT_ADDR

# Reconfigure Vault connection
eos self secrets configure

# Test with specific auth method
eos self secrets test
```

**Error**: `Secret access test failed`
```bash
# Check Vault authentication
vault auth -method=userpass username=myuser  # if using userpass

# Verify token is valid
vault token lookup  # if using token auth

# Check secret permissions
vault policy read myPolicy  # check your policy permissions
```

### Database Connection Issues

**Error**: `failed to ping database`
```bash
# Verify database server is running
sudo systemctl status postgresql

# Check database connectivity
psql -h localhost -U delphi -d delphi

# Verify credentials in Vault
eos self secrets get delphi/database/username
eos self secrets get delphi/database/host

# Test with correct credentials
eos self secrets set delphi-db
```

## Fallback Behavior

If Vault is unavailable, the system gracefully falls back to:

1. **Environment Variables**: 
   - `PG_DSN` (PostgreSQL Data Source Name)
   - `DELPHI_DB_HOST`, `DELPHI_DB_PORT`, etc.

2. **Default Values**:
   - Host: localhost
   - Port: 5432
   - Database: delphi
   - Username: delphi
   - Password: delphi

## Security Best Practices

### Vault Configuration
- Use TLS for all Vault communications
- Implement proper Vault policies with least-privilege access
- Regularly rotate Vault tokens and credentials
- Use AppRole authentication for production services

### Credential Management
- Never hardcode credentials in configuration files
- Rotate database passwords regularly
- Use strong, unique passwords for all services
- Monitor Vault audit logs for credential access

### Network Security
- Restrict Vault access to authorized networks only
- Use firewall rules to limit database connections
- Implement proper TLS certificates for all services

## Integration with Python Workers

The Python workers in `assets/python_workers/` can also be configured to use the same Vault-stored credentials:

```python
# Example integration (to be implemented)
from eos_vault import get_secret

# Get database connection
pg_dsn = get_secret("delphi/database/dsn")

# Get SMTP credentials  
smtp_user = get_secret("smtp/username")
smtp_pass = get_secret("smtp/password")
```

## Advanced Configuration

### Custom Vault Mount Points

If your Vault uses custom mount points, update the configuration:

```bash
# Set custom KV mount point
export VAULT_KV_MOUNT="secret/v2"

# Configure with custom paths
eos self secrets configure
```

### Multiple Environments

For multiple environments (dev/staging/prod):

```bash
# Use environment-specific secret paths
eos self secrets set custom
# Path: environments/production/delphi/database/password

# Or use separate Vault namespaces
export VAULT_NAMESPACE="production"
eos self secrets configure
```

### Automated Deployment

For CI/CD pipelines:

```bash
# Set Vault credentials via environment variables
export VAULT_ADDR="https://vault.company.com"
export VAULT_TOKEN="hvs.XXXXXXXXXXXXXXXX"

# Run automated setup
/opt/eos/scripts/setup-vault-delphi.sh --vault-only
eos self secrets set delphi-db --non-interactive
```

## Monitoring and Logging

### Vault Audit Logs
```bash
# Enable Vault audit logging
vault audit enable file file_path=/var/log/vault/audit.log

# Monitor secret access
tail -f /var/log/vault/audit.log | grep delphi
```

### Application Logs
```bash
# Check Eos dashboard logs
tail -f /var/log/eos/eos.log | grep -i vault

# Check for authentication issues
journalctl -u eos-dashboard -f
```

## Migration from Environment Variables

If you're migrating from environment-based configuration:

1. **Backup Current Configuration**:
   ```bash
   # Save current environment variables
   env | grep -E "(DELPHI_|PG_)" > backup.env
   ```

2. **Set Up Vault**:
   ```bash
   eos self secrets configure
   eos self secrets set delphi-db
   ```

3. **Test Migration**:
   ```bash
   # Test with Vault
   eos self secrets test
   eos delphi dashboard services  # Quick test

   # Verify all services work
   eos delphi services status --all
   ```

4. **Clean Up** (optional):
   ```bash
   # Remove environment variables once confirmed working
   unset PG_DSN DELPHI_DB_PASSWORD
   ```

This integration provides a secure, scalable foundation for credential management while maintaining backward compatibility and graceful fallback behavior.