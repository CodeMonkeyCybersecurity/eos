# Vault Dynamic Database Credentials for Delphi Dashboard

*Last Updated: 2025-01-14*

## Overview

This document describes the enhanced Vault integration that supports dynamic PostgreSQL credentials using Vault's database secrets engine. This approach provides superior security by generating temporary database credentials on-demand rather than storing static passwords.

## Architecture

### Host-Guest Setup
- **Vault Server**: Runs on host machine (e.g., vhost11:8200)
- **PostgreSQL Database**: Runs in guest VM (e.g., 100.88.69.11:5432)
- **Eos Dashboard**: Runs on host, connects to guest database using dynamic credentials from Vault

### Credential Flow
1. **Dashboard Start**: Eos requests dynamic credentials from Vault
2. **Vault Generation**: Vault creates temporary PostgreSQL user with limited permissions
3. **Database Connection**: Dashboard connects using temporary credentials
4. **Automatic Renewal**: Credentials are renewed before expiration
5. **Cleanup**: Expired credentials are automatically revoked

## Setup Guide

### Step 1: Configure Vault Connection
```bash
# Configure Vault server address (pointing to host Vault)
eos self secrets configure
# Enter: https://vhost11:8200 (or your host Vault address)
```

### Step 2: Set Database Connection Parameters
```bash
# Set database connection info (pointing to guest database)
eos self secrets set delphi-db-config
# Host: 100.88.69.11 (or your guest VM IP)
# Port: 5432
# Database: delphi
```

### Step 3: Configure Vault Database Secrets Engine
```bash
# Generate setup commands for database engine
eos self secrets set delphi-db-engine
# Follow the generated Vault commands to configure dynamic credentials
```

The setup will generate Vault commands like:
```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection (run on host)
vault write database/config/delphi-postgresql \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@100.88.69.11:5432/delphi?sslmode=disable" \
    allowed_roles="delphi-readonly" \
    username="postgres" \
    password="your_admin_password"

# Create read-only role for Delphi
vault write database/roles/delphi-readonly \
    db_name=delphi-postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
                          GRANT CONNECT ON DATABASE delphi TO \"{{name}}\"; \
                          GRANT USAGE ON SCHEMA public TO \"{{name}}\"; \
                          GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
                          ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

### Step 4: Test and Launch
```bash
# Test the complete setup
eos self secrets test

# Check status
eos self secrets status

# Launch dashboard with dynamic credentials
eos delphi dashboard
```

## Security Benefits

### Dynamic Credentials
- **Temporary Access**: Credentials expire automatically (1-24 hours)
- **Unique Users**: Each dashboard session gets unique PostgreSQL users
- **Principle of Least Privilege**: Read-only access with minimal permissions
- **Automatic Rotation**: No manual password management required

### Network Security
- **Host-Controlled**: All credential generation happens on trusted host
- **Guest Isolation**: Guest VM only receives temporary, limited credentials
- **No Stored Secrets**: No permanent passwords stored in guest environment

### Audit Trail
- **Vault Audit Logs**: Complete history of credential requests
- **PostgreSQL Logs**: Database access patterns tracked
- **Eos Structured Logging**: Detailed connection and operation logs

## Credential Management

### Automatic Features
- **Renewal**: Credentials renewed at 75% of TTL (45 minutes for 1-hour TTL)
- **Expiration Handling**: Graceful handling of expired credentials
- **Connection Pooling**: Optimized for dynamic credential lifetimes
- **Fallback**: Automatic fallback to static credentials or environment variables

### Manual Operations
```bash
# Check credential status
eos self secrets status

# Force credential renewal (if needed)
eos self secrets test

# View dynamic credential info (masked)
eos self secrets get database/creds/delphi-readonly
```

## Troubleshooting

### Common Issues

**Error**: `failed to get dynamic credentials`
```bash
# Check if database engine is enabled
vault secrets list | grep database

# Test direct credential generation
vault read database/creds/delphi-readonly

# Verify PostgreSQL connectivity from host
psql -h 100.88.69.11 -U postgres -d delphi
```

**Error**: `PostgreSQL connection failed`
```bash
# Check network connectivity
ping 100.88.69.11

# Verify PostgreSQL is accepting connections
telnet 100.88.69.11 5432

# Check PostgreSQL configuration
# Ensure postgresql.conf has: listen_addresses = '*'
# Ensure pg_hba.conf allows connections from host
```

**Error**: `Vault server unreachable`
```bash
# Check Vault server status
curl -k https://vhost11:8200/v1/sys/health

# Verify VAULT_ADDR
echo $VAULT_ADDR

# Reconfigure if needed
eos self secrets configure
```

### Database Permissions
For the database engine to work, ensure the PostgreSQL admin user has sufficient privileges:
```sql
-- Grant necessary permissions to the admin user
GRANT CREATE ON DATABASE delphi TO postgres;
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER USER postgres CREATEROLE;
```

### Network Configuration
Ensure the guest VM PostgreSQL accepts connections from the host:

**postgresql.conf**:
```
listen_addresses = '*'
port = 5432
```

**pg_hba.conf** (add line for host access):
```
host    delphi    all    100.88.69.0/24    md5
```

## Fallback Behavior

The system provides graceful fallback in this order:
1. **Dynamic Credentials**: From Vault database engine
2. **Static Credentials**: From Vault KV store (`delphi/database/*`)
3. **Environment Variables**: `PG_DSN`, `DELPHI_DB_*`
4. **Defaults**: localhost with default credentials

## Monitoring

### Vault Metrics
- Monitor `database/creds/delphi-readonly` access patterns
- Track credential TTL and renewal rates
- Watch for authentication failures

### PostgreSQL Monitoring
- Monitor temporary user creation/deletion
- Track connection patterns from dynamic users
- Alert on permission escalation attempts

### Eos Dashboard Logs
```bash
# Monitor credential operations
tail -f /var/log/eos/eos.log | grep -i "dynamic\|credential\|database"

# Check connection health
eos self secrets status
```

## Migration from Static Credentials

To migrate from static to dynamic credentials:

1. **Set up dynamic engine** (keeping static as fallback):
   ```bash
   eos self secrets set delphi-db-config
   eos self secrets set delphi-db-engine
   ```

2. **Test dynamic credentials**:
   ```bash
   eos self secrets test
   eos delphi dashboard  # Should use dynamic credentials
   ```

3. **Remove static credentials** (optional):
   ```bash
   # Only after confirming dynamic credentials work
   vault kv delete secret/delphi/database/password
   ```

## Python Worker Integration

The Python workers can also be updated to use dynamic credentials:

```python
# Example integration in delphi-listener.py
import hvac
import os

def get_dynamic_db_credentials():
    """Get dynamic database credentials from Vault"""
    client = hvac.Client(url=os.getenv('VAULT_ADDR'))
    client.token = os.getenv('VAULT_TOKEN')
    
    response = client.read('database/creds/delphi-readonly')
    return {
        'username': response['data']['username'],
        'password': response['data']['password'],
        'lease_id': response['lease_id'],
        'lease_duration': response['lease_duration']
    }

# Update connection string with dynamic credentials
def get_postgres_connection():
    try:
        creds = get_dynamic_db_credentials()
        conn_str = f"postgresql://{creds['username']}:{creds['password']}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        return psycopg2.connect(conn_str)
    except Exception as e:
        # Fallback to static credentials
        return psycopg2.connect(os.getenv('PG_DSN'))
```

This approach provides safe, high-quality and effective security for database access while maintaining compatibility with existing setups through graceful fallbacks.