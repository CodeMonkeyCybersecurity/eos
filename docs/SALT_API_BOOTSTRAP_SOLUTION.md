# Salt API Bootstrap Solution

*Last Updated: 2025-01-25*

## Problem Summary

The error "Specified SLS dependencies in saltenv base is not available on the salt master or through a configured fileserver" occurs because:

1. Salt can't find the state files in `/opt/eos/salt/states/`
2. The API credentials aren't configured
3. The file_roots configuration is missing or incorrect

## Solution Overview

We've created a comprehensive Salt API bootstrap system that:

1. **Configures file_roots properly** - Ensures Salt can find Eos state files
2. **Sets up REST API automatically** - No manual configuration needed
3. **Generates secure credentials** - Stored in `/etc/eos/salt/api.env`
4. **Creates necessary symlinks** - Links `/srv/salt` to `/opt/eos/salt/states`
5. **Starts services correctly** - Proper service ordering and verification

## Implementation

### 1. Enhanced Bootstrap Function

The `BootstrapAPIConfig()` function in `pkg/saltstack/bootstrap_api.go`:

```go
// Performs these steps:
1. Configure master/minion with proper file_roots
2. Configure REST API with CherryPy  
3. Create API user with secure credentials
4. Setup file_roots and symlinks
5. Start services in correct order
6. Save API credentials for future use
```

### 2. File Roots Configuration

Automatically configures both master and minion with:

```yaml
file_roots:
  base:
    - /srv/salt
    - /srv/salt/eos
    - /opt/eos/salt/states

pillar_roots:
  base:
    - /srv/pillar
    - /opt/eos/salt/pillar
```

### 3. API Configuration

Creates `/etc/salt/master.d/api.conf` with:

```yaml
rest_cherrypy:
  port: 8000
  ssl_crt: /etc/salt/pki/api/cert.pem
  ssl_key: /etc/salt/pki/api/key.pem
  host: 0.0.0.0

external_auth:
  pam:
    eos-api:
      - .*
      - '@wheel'
      - '@runner'
      - '@jobs'
```

### 4. Secure Credentials

- Creates system user `eos-api` with secure password
- Generates self-signed SSL certificates
- Saves credentials to `/etc/eos/salt/api.env`

## User Experience

### Installation

```bash
# Standard installation (now includes API setup)
sudo eos create saltstack

# Or use enhanced command for explicit API focus
sudo eos create saltstack-enhanced
```

### Post-Installation

The user sees:
```
===== Salt API Installation Complete =====

API URL: https://localhost:8000
API User: eos-api

To use the Salt API:
  source /etc/eos/salt/api.env

Test commands:
  # Test local Salt
  salt-call --local test.ping
  
  # Test API
  curl -k https://localhost:8000

Now ready to deploy services like Consul:
  eos create consul
```

### Using the API

```bash
# Load credentials
source /etc/eos/salt/api.env

# Deploy Consul (will use API automatically)
sudo eos create consul
```

## Security Considerations

1. **Credentials Storage**
   - Stored in `/etc/eos/salt/api.env` with 0600 permissions
   - Only root can read the file

2. **API User**
   - System user with no shell (`/bin/false`)
   - PAM authentication
   - Full API permissions for Eos operations

3. **SSL/TLS**
   - Self-signed certificates generated automatically
   - Can be replaced with proper certificates

4. **Network Security**
   - API binds to all interfaces (0.0.0.0)
   - Consider firewall rules for production

## Troubleshooting

### If Consul still can't find states:

1. **Check file_roots configuration:**
   ```bash
   salt-call --local config.get file_roots
   ```

2. **Verify symlinks exist:**
   ```bash
   ls -la /srv/salt/
   ```

3. **Test state accessibility:**
   ```bash
   salt-call --local state.show_sls hashicorp.consul
   ```

4. **Check API is running:**
   ```bash
   systemctl status salt-api
   curl -k https://localhost:8000
   ```

### Common Fixes:

1. **Recreate symlinks:**
   ```bash
   sudo ln -sf /opt/eos/salt/states/hashicorp /srv/salt/hashicorp
   ```

2. **Restart services:**
   ```bash
   sudo systemctl restart salt-minion salt-api
   ```

3. **Re-run bootstrap:**
   ```bash
   sudo eos create saltstack --force
   ```

## Migration Path

All Eos commands will automatically use the API when available:

1. Commands check for API credentials in environment
2. If found, use API client
3. If not found, check `/etc/eos/salt/api.env`
4. Load credentials and retry
5. Only fall back to `salt-call` if API truly unavailable

## Benefits

1. **Consistency** - All Salt operations go through API
2. **Remote Management** - Can manage from anywhere
3. **Security** - Better audit trail and access control
4. **Reliability** - No more file permission issues
5. **Scalability** - Ready for multi-node deployments