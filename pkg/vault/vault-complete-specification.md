# EOS Vault Installation - Complete Specification & History

## Document Purpose
This document captures **every detail** of the `eos create vault` implementation based on months of development, debugging, and refinement. Use this for comprehensive auditing after refactoring.

---

## Phase 0: Pre-Installation Checks

### 0.1 Check for Existing Installation
```bash
# Check if vault binary exists
which vault

# Check if vault service exists
systemctl status vault

# Check if configuration exists
test -f /etc/vault.d/vault.hcl
```

### 0.2 Check for Port Conflicts
**Critical Issue We Encountered:** Port 8179 (or configured port) was already in use by previous Vault installation or other process.

**Solution:**
```bash
# Check what's using the port
sudo lsof -i :8179
sudo ss -tlnp | grep 8179

# If old vault process, kill it
sudo pkill vault

# If port still in use by something else, fail with clear error
```

### 0.3 Clean Up Previous Failed Installations
**Issue:** Incomplete cleanup left conflicting files.

**Solution:**
```bash
# Stop and disable any existing vault services
sudo systemctl stop vault 2>/dev/null
sudo systemctl disable vault 2>/dev/null
sudo systemctl stop vault-agent-eos 2>/dev/null
sudo systemctl disable vault-agent-eos 2>/dev/null

# Remove systemd service files
sudo rm -f /etc/systemd/system/vault.service
sudo rm -f /etc/systemd/system/vault-agent-eos.service
sudo systemctl daemon-reload

# Clean up binaries
sudo rm -f /usr/local/bin/vault
sudo rm -f /usr/bin/vault

# Backup and remove configurations (don't delete data!)
if [ -d /etc/vault.d ]; then
    sudo cp -r /etc/vault.d /etc/vault.d.backup.$(date +%s)
    sudo rm -rf /etc/vault.d
fi
```

---

## Phase 1: User and Group Creation

### 1.1 Create Vault System User
**CRITICAL:** User MUST be created BEFORE directories.

**Issue We Encountered:** Directories created before user existed, causing ownership problems.

**Solution:**
```bash
# Create vault system user (no login, no home directory)
sudo useradd --system --no-create-home --shell /bin/false vault || true

# Verify user was created
id vault
# Expected output: uid=XXX(vault) gid=XXX(vault) groups=XXX(vault)
```

**User Specifications:**
- Username: `vault`
- Type: System user (`--system`)
- Shell: `/bin/false` (no login)
- Home: None (`--no-create-home`)
- Groups: `vault` (primary group auto-created)

---

## Phase 2: Directory Structure Creation

### 2.1 Create All Required Directories
```bash
# Data directory
sudo mkdir -p /opt/vault/data

# Configuration directory
sudo mkdir -p /etc/vault.d

# TLS certificates directory
sudo mkdir -p /etc/vault.d/tls

# EOS secrets directory (for init keys)
sudo mkdir -p /var/lib/eos/secret
```

### 2.2 Set Directory Ownership
```bash
# Vault directories owned by vault user
sudo chown -R vault:vault /opt/vault
sudo chown -R vault:vault /etc/vault.d

# EOS secrets owned by root (contains sensitive init data)
sudo chown -R root:root /var/lib/eos/secret
```

### 2.3 Set Directory Permissions
```bash
# Vault data directory
sudo chmod 755 /opt/vault/data

# Config directory
sudo chmod 755 /etc/vault.d

# TLS directory
sudo chmod 755 /etc/vault.d/tls

# EOS secrets directory (more restrictive)
sudo chmod 700 /var/lib/eos/secret
```

### Complete Directory Structure
```
/opt/vault/
├── data/                      # 755 vault:vault - Vault's encrypted storage
│   └── (vault data files)

/etc/vault.d/                  # 755 vault:vault - Vault configuration
├── vault.hcl                  # 644 vault:vault - Main config file
└── tls/                       # 755 vault:vault - TLS certificates
    ├── vault-cert.pem         # 644 vault:vault - Public certificate
    └── vault-key.pem          # 600 vault:vault - Private key

/var/lib/eos/secret/           # 700 root:root - EOS secrets
└── vault_init.json            # 600 root:root - Unseal keys & root token
```

---

## Phase 3: TLS Certificate Generation

### 3.1 The Critical Bug We Fixed
**CRITICAL ISSUE:** Config file would have **empty strings** for certificate paths:
```hcl
listener "tcp" {
  tls_cert_file = ""   # ❌ EMPTY STRING - causes crash!
  tls_key_file = ""    # ❌ EMPTY STRING - causes crash!
}
```

This caused:
```
Error initializing listener of type tcp: error loading TLS cert: open : no such file or directory
```

Notice: `open :` with nothing between "open" and the colon.

### 3.2 The Solution: Auto-Generate Self-Signed Certificates

When `--tls=true` (default), **MUST** generate certificates BEFORE writing config:

```bash
CERT_DIR="/etc/vault.d/tls"
HOSTNAME=$(hostname -f)

# Generate self-signed certificate valid for 1 year
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERT_DIR/vault-key.pem" \
  -out "$CERT_DIR/vault-cert.pem" \
  -subj "/C=AU/ST=WA/L=Fremantle/O=Code Monkey Cybersecurity/CN=$HOSTNAME" \
  -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1"

# Set correct ownership
sudo chown vault:vault "$CERT_DIR/vault-cert.pem"
sudo chown vault:vault "$CERT_DIR/vault-key.pem"

# Set correct permissions
sudo chmod 644 "$CERT_DIR/vault-cert.pem"  # Public cert - readable
sudo chmod 600 "$CERT_DIR/vault-key.pem"   # Private key - restricted
```

### 3.3 TLS Configuration Flags
```bash
# Default: Enable TLS with auto-generated certs
eos create vault

# Disable TLS (development only!)
eos create vault --tls=false

# Use existing certificates
eos create vault \
  --tls-cert=/path/to/cert.pem \
  --tls-key=/path/to/key.pem
```

### 3.4 Certificate Validation
Before using certificates, MUST validate:
```bash
# Check certificate exists and is readable
test -r "$CERT_DIR/vault-cert.pem" || exit 1

# Check private key exists and has correct permissions
test -f "$CERT_DIR/vault-key.pem" || exit 1
PERMS=$(stat -c %a "$CERT_DIR/vault-key.pem")
[ "$PERMS" = "600" ] || exit 1

# Verify certificate is valid
openssl x509 -in "$CERT_DIR/vault-cert.pem" -noout -text || exit 1

# Verify private key matches certificate
CERT_MOD=$(openssl x509 -noout -modulus -in "$CERT_DIR/vault-cert.pem" | openssl md5)
KEY_MOD=$(openssl rsa -noout -modulus -in "$CERT_DIR/vault-key.pem" | openssl md5)
[ "$CERT_MOD" = "$KEY_MOD" ] || exit 1
```

---

## Phase 4: Vault Binary Installation

### 4.1 Download Vault Binary
```bash
# Version to install
VAULT_VERSION="1.20.4"

# Download URL
DOWNLOAD_URL="https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip"

# Checksum URL
CHECKSUM_URL="https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS"

# Download binary
curl -sLO "$DOWNLOAD_URL"

# Download and verify checksum
curl -sLO "$CHECKSUM_URL"
EXPECTED_SHA=$(grep "vault_${VAULT_VERSION}_linux_amd64.zip" vault_${VAULT_VERSION}_SHA256SUMS | cut -d' ' -f1)
ACTUAL_SHA=$(sha256sum "vault_${VAULT_VERSION}_linux_amd64.zip" | cut -d' ' -f1)

# Verify checksum matches
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "Checksum mismatch!"
    exit 1
fi

# Extract binary
unzip "vault_${VAULT_VERSION}_linux_amd64.zip"

# Install to standard location
sudo mv vault /usr/local/bin/vault
sudo chmod 755 /usr/local/bin/vault

# Verify installation
/usr/local/bin/vault version
```

### 4.2 Check for Duplicate Binaries
**Issue:** Sometimes vault existed in multiple locations.

**Solution:**
```bash
# Find all vault binaries
VAULT_BINS=$(which -a vault 2>/dev/null)

# If multiple found, remove all except /usr/local/bin/vault
for BIN in $VAULT_BINS; do
    if [ "$BIN" != "/usr/local/bin/vault" ]; then
        sudo rm -f "$BIN"
    fi
done
```

### 4.3 Set Up mlock Capability
```bash
# Allow vault to lock memory (prevents secrets from being swapped to disk)
sudo setcap cap_ipc_lock=+ep /usr/local/bin/vault

# Verify capability was set
getcap /usr/local/bin/vault
# Expected: /usr/local/bin/vault = cap_ipc_lock+ep
```

---

## Phase 5: Configuration File Creation

### 5.1 Final Vault Configuration (vault.hcl)

**File:** `/etc/vault.d/vault.hcl`

**WITH TLS (default):**
```hcl
# TCP Listener with TLS
listener "tcp" {
  address       = "0.0.0.0:8179"
  tls_cert_file = "/etc/vault.d/tls/vault-cert.pem"
  tls_key_file  = "/etc/vault.d/tls/vault-key.pem"
}

# File-based storage (suitable for single-node deployments)
storage "file" {
  path = "/opt/vault/data"
}

# Disable mlock if running without CAP_IPC_LOCK
disable_mlock = true

# API address for Vault CLI and agents
api_addr = "https://localhost:8179"

# Enable the web UI
ui = true

# Logging configuration
log_level = "info"
log_format = "json"
```

**WITHOUT TLS (development only):**
```hcl
listener "tcp" {
  address     = "0.0.0.0:8179"
  tls_disable = 1
}

storage "file" {
  path = "/opt/vault/data"
}

disable_mlock = true
api_addr = "http://localhost:8179"
ui = true
log_level = "info"
log_format = "json"
```

### 5.2 Configuration Validation

**CRITICAL:** Must validate config BEFORE starting service.

**Issue We Encountered:** Validation would fail silently (exit code 127), but installation continued.

**Solution:**
```bash
# Check if vault binary exists and is in PATH
if ! command -v vault &> /dev/null; then
    echo "ERROR: vault binary not found in PATH"
    exit 1
fi

# Validate configuration
if ! vault validate /etc/vault.d/vault.hcl; then
    echo "ERROR: Configuration validation failed"
    cat /etc/vault.d/vault.hcl
    exit 1
fi

# Must see: "Success! Configuration is valid."
```

### 5.3 Manual Validation Checks

Even if `vault validate` is unavailable, check:
```bash
# 1. Config file exists
test -f /etc/vault.d/vault.hcl || exit 1

# 2. If TLS enabled, cert paths are NOT empty
if grep -q 'tls_cert_file' /etc/vault.d/vault.hcl; then
    CERT_PATH=$(grep 'tls_cert_file' /etc/vault.d/vault.hcl | cut -d'"' -f2)
    if [ -z "$CERT_PATH" ]; then
        echo "ERROR: tls_cert_file is empty string!"
        exit 1
    fi
    test -r "$CERT_PATH" || exit 1
fi

# 3. Storage path exists
STORAGE_PATH=$(grep 'path =' /etc/vault.d/vault.hcl | cut -d'"' -f2)
test -d "$STORAGE_PATH" || exit 1

# 4. Storage path is writable by vault user
sudo -u vault test -w "$STORAGE_PATH" || exit 1
```

### 5.4 Config File Permissions
```bash
sudo chown vault:vault /etc/vault.d/vault.hcl
sudo chmod 644 /etc/vault.d/vault.hcl
```

---

## Phase 6: Systemd Service Configuration

### 6.1 Systemd Service File

**File:** `/etc/systemd/system/vault.service`

**CRITICAL ISSUE:** Old syntax used deprecated `Capabilities=`, causing systemd warnings.

**CORRECT Modern Syntax:**
```ini
[Unit]
Description=HashiCorp Vault - A tool for managing secrets
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
User=vault
Group=vault

# Modern capability syntax (NOT Capabilities=!)
AmbientCapabilities=CAP_IPC_LOCK
NoNewPrivileges=true

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
SecureBits=keep-caps

# Allow writes only to data directory
ReadWritePaths=/opt/vault/data

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Service execution
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID

# Process management
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vault

[Install]
WantedBy=multi-user.target
```

### 6.2 Enable and Start Service
```bash
# Reload systemd to pick up new service file
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable vault

# Start the service
sudo systemctl start vault

# Wait for service to become active
sleep 3

# Verify service is running
sudo systemctl is-active vault || exit 1

# Check for any errors
sudo journalctl -u vault -n 50 --no-pager
```

---

## Phase 7: Vault Initialization

### 7.1 Initialize Vault

**CRITICAL:** This step generates unseal keys and root token.

```bash
# Set VAULT_ADDR
export VAULT_ADDR="https://localhost:8179"

# If using self-signed cert, skip verification (dev only!)
export VAULT_SKIP_VERIFY=1

# Wait for Vault to be ready
MAX_WAIT=30
ELAPSED=0
until vault status &>/dev/null; do
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        echo "ERROR: Vault did not become ready in ${MAX_WAIT}s"
        exit 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

# Initialize with 5 key shares, 3 required to unseal
vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json > /tmp/vault_init.json

# Move to secure location with restricted permissions
sudo mv /tmp/vault_init.json /var/lib/eos/secret/vault_init.json
sudo chown root:root /var/lib/eos/secret/vault_init.json
sudo chmod 600 /var/lib/eos/secret/vault_init.json
```

### 7.2 vault_init.json Structure
```json
{
  "unseal_keys_b64": [
    "key1_base64_encoded",
    "key2_base64_encoded",
    "key3_base64_encoded",
    "key4_base64_encoded",
    "key5_base64_encoded"
  ],
  "unseal_keys_hex": [
    "key1_hex_encoded",
    "key2_hex_encoded",
    "key3_hex_encoded",
    "key4_hex_encoded",
    "key5_hex_encoded"
  ],
  "unseal_shares": 5,
  "unseal_threshold": 3,
  "recovery_keys_b64": [],
  "recovery_keys_hex": [],
  "root_token": "hvs.CAESXXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### 7.3 SECURITY WARNING

**CRITICAL SECURITY ISSUE WE IDENTIFIED:**

Storing all unseal keys in one file (`/var/lib/eos/secret/vault_init.json`) **completely defeats** Vault's Shamir's Secret Sharing security model!

**The Problem:**
- Vault splits the master key into 5 shares
- Requires ANY 3 shares to unseal
- **But we store all 5 in one place!**
- Anyone with file access can unseal Vault
- This is **security theater**

**This is ONLY acceptable for:**
- Development environments
- Testing
- Single-user systems where you trust the system admin

**For Production, MUST use ONE of these:**
1. **AWS KMS Auto-Unseal** - Vault uses AWS KMS to automatically unseal
2. **Azure Key Vault Auto-Unseal** - Similar but for Azure
3. **GCP KMS Auto-Unseal** - Similar but for GCP
4. **Manual Unsealing with Distributed Keys** - Give each of 5 people one key
5. **HSM Integration** - Hardware Security Module auto-unseal

**Display this warning during installation:**
```
  SECURITY WARNING 

All 5 unseal keys are stored in:
/var/lib/eos/secret/vault_init.json

This configuration is INSECURE and suitable for:
  • Development environments only
  • Testing purposes
  • Non-production systems

For production, you MUST:
  1. Distribute unseal keys to different people, OR
  2. Use cloud KMS auto-unseal, OR
  3. Use HSM auto-unseal

Press ENTER to acknowledge this warning...
```

---

## Phase 8: Vault Unsealing

### 8.1 The Unsealing Process

Vault starts in a **sealed** state. It must be unsealed before use.

```bash
# Set environment
export VAULT_ADDR="https://localhost:8179"
export VAULT_SKIP_VERIFY=1  # Only if self-signed cert

# Check seal status
vault status

# Should show:
# Sealed: true
# Unseal Progress: 0/3

# Unseal using stored keys
KEY1=$(jq -r '.unseal_keys_hex[0]' /var/lib/eos/secret/vault_init.json)
KEY2=$(jq -r '.unseal_keys_hex[1]' /var/lib/eos/secret/vault_init.json)
KEY3=$(jq -r '.unseal_keys_hex[2]' /var/lib/eos/secret/vault_init.json)

vault operator unseal "$KEY1"
# Unseal Progress: 1/3

vault operator unseal "$KEY2"
# Unseal Progress: 2/3

vault operator unseal "$KEY3"
# Sealed: false - UNSEALED!
```

### 8.2 The `eos pandora unseal` Command

**File Location:** `cmd/pandora/unseal.go`

**Usage:**
```bash
# Interactive unsealing (asks which keys to use)
sudo eos pandora unseal

# Automatic unsealing (uses first 3 keys)
sudo eos pandora unseal --auto

# Use specific key file
sudo eos pandora unseal --key-file /path/to/keys.json
```

**Issues We Encountered:**

**Problem 1:** User input format confusion
```bash
# User would paste actual keys when asked for indices:
Enter 3 key indices (0-4) separated by spaces: el6mTwLTQYfznXyEq90oIXl9bRPoEF2GXEhmFm8eZ+iG, ...
ERROR: invalid input format
```

**Solution:** Accept BOTH indices AND actual key values:
```go
// Parse input - could be indices or actual keys
input := strings.TrimSpace(userInput)

// Try parsing as indices first
indices := strings.Fields(input)
if len(indices) == 3 {
    // Check if they're all numbers 0-4
    allNumeric := true
    for _, idx := range indices {
        if num, err := strconv.Atoi(idx); err != nil || num < 0 || num > 4 {
            allNumeric = false
            break
        }
    }
    
    if allNumeric {
        // Use as indices
        keys = extractKeysByIndices(indices)
    } else {
        // Treat as actual key values
        keys = indices
    }
}
```

**Problem 2:** Path confusion between `/var/lib/eos/secrets/` (plural) and `/var/lib/eos/secret/` (singular)

**Solution:** Standardize on `/var/lib/eos/secret/` (singular) everywhere.

**Problem 3:** Security theater - prompting for key selection when all keys are already loaded

**Solution:** 
- For `--auto`: Just use first 3 keys silently
- For interactive: Still prompt, but make it clear this is for convenience, not security
- Display security warning about key storage

### 8.3 Auto-Unseal on Boot

**For Development:** Create systemd service to auto-unseal after Vault starts

**File:** `/etc/systemd/system/vault-unseal.service`
```ini
[Unit]
Description=Vault Auto-Unseal
After=vault.service
Requires=vault.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/eos pandora unseal --auto
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Enable it:**
```bash
sudo systemctl enable vault-unseal.service
```

---

## Phase 9: Root Token Setup

### 9.1 Extract Root Token
```bash
# Get root token from init file
ROOT_TOKEN=$(jq -r '.root_token' /var/lib/eos/secret/vault_init.json)

# Set as environment variable
export VAULT_TOKEN="$ROOT_TOKEN"

# Verify authentication
vault token lookup

# Should show token details
```

### 9.2 Persist Root Token (Development Only!)

**CRITICAL:** Root token has unlimited permissions. **NEVER** do this in production!

**For development convenience:**
```bash
# Add to user's shell profile (example for bash)
echo "export VAULT_ADDR='https://localhost:8179'" >> ~/.bashrc
echo "export VAULT_SKIP_VERIFY=1" >> ~/.bashrc
echo "export VAULT_TOKEN='$(jq -r .root_token /var/lib/eos/secret/vault_init.json)'" >> ~/.bashrc
source ~/.bashrc
```

**For production:**
- Create policies with minimal required permissions
- Generate tokens with limited TTL
- Use AppRole authentication for services
- **Never use root token except for initial setup**

---

## Phase 10: Vault Agent Configuration (EOS Integration)

### 10.1 Vault Agent Config File

**File:** `/etc/vault.d/vault-agent-eos.hcl`

```hcl
pid_file = "/run/eos/vault-agent-eos.pid"

# Where to find Vault server
vault {
  address = "https://localhost:8179"
  
  # Only for self-signed certs (remove in production!)
  tls_skip_verify = true
}

# Auto-authentication using AppRole
auto_auth {
  method {
    type = "approle"
    
    config = {
      role_id_file_path   = "/etc/vault.d/role-id"
      secret_id_file_path = "/etc/vault.d/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  # Where to write the token
  sink "file" {
    config = {
      path = "/run/eos/vault_agent_eos.token"
      mode = 0600  # CRITICAL: Must be exactly 0600!
    }
  }
}

# Optional: Caching
cache {
  use_auto_auth_token = true
}

# Optional: Templating
template {
  source      = "/etc/vault.d/templates/config.tmpl"
  destination = "/etc/eos/config.json"
}
```

### 10.2 Token File Permissions Issue

**CRITICAL BUG WE FIXED:**

**Problem:** Vault Agent was writing token file with permissions `640` (rw-r-----):
```bash
-rw-r----- 1 eos eos 95 Jun 24 14:35 /run/eos/vault_agent_eos.token
```

But EOS required **exactly** `600` (rw-------).

**Solution:** Explicitly set `mode = 0600` in the sink configuration:
```hcl
sink "file" {
  config = {
    path = "/run/eos/vault_agent_eos.token"
    mode = 0600  # ← THIS IS CRITICAL!
  }
}
```

### 10.3 Vault Agent Systemd Service

**File:** `/etc/systemd/system/vault-agent-eos.service`

```ini
[Unit]
Description=Vault Agent (EOS)
After=network.target vault.service
Requires=vault.service
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=simple
User=eos
Group=eos

# Ensure runtime directory exists
RuntimeDirectory=eos
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes

# Environment
Environment=VAULT_ADDR=https://localhost:8179
Environment=VAULT_SKIP_VERIFY=1

# Pre-start: ensure directory exists with correct permissions
ExecStartPre=/bin/mkdir -p /run/eos
ExecStartPre=/bin/chown eos:eos /run/eos
ExecStartPre=/bin/chmod 700 /run/eos

# Main process
ExecStart=/usr/local/bin/vault agent -config=/etc/vault.d/vault-agent-eos.hcl

# Restart on failure
Restart=on-failure
RestartSec=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vault-agent-eos

[Install]
WantedBy=multi-user.target
```

---

## Complete File Permissions Matrix

| File/Directory | Owner | Group | Mode | Octal | Symbolic | Notes |
|---------------|-------|-------|------|-------|----------|-------|
| `/usr/local/bin/vault` | root | root | 0755 | 755 | rwxr-xr-x | Binary |
| `/etc/vault.d/` | vault | vault | 0755 | 755 | rwxr-xr-x | Config dir |
| `/etc/vault.d/vault.hcl` | vault | vault | 0644 | 644 | rw-r--r-- | Config file |
| `/etc/vault.d/tls/` | vault | vault | 0755 | 755 | rwxr-xr-x | TLS dir |
| `/etc/vault.d/tls/vault-cert.pem` | vault | vault | 0644 | 644 | rw-r--r-- | Public cert |
| `/etc/vault.d/tls/vault-key.pem` | vault | vault | 0600 | 600 | rw------- | Private key |
| `/opt/vault/` | vault | vault | 0755 | 755 | rwxr-xr-x | Data root |
| `/opt/vault/data/` | vault | vault | 0755 | 755 | rwxr-xr-x | Storage |
| `/var/lib/eos/secret/` | root | root | 0700 | 700 | rwx------ | Secrets dir |
| `/var/lib/eos/secret/vault_init.json` | root | root | 0600 | 600 | rw------- | Init data |
| `/run/eos/` | eos | eos | 0700 | 700 | rwx------ | Runtime |
| `/run/eos/vault_agent_eos.token` | eos | eos | 0600 | 600 | rw------- | Agent token |

---

## Enhanced Debugging Commands

### `eos debug vault`

Comprehensive diagnostic output:

```bash
sudo eos debug vault
```

**Output includes:**
1. Vault binary location and version
2. Configuration file validation
3. TLS certificate status (if enabled)
4. Systemd service status and recent logs
5. Network connectivity check
6. Seal status
7. Environment variables
8. Recent error messages
9. Recommendations for fixes

### `eos validate vault`

Quick validation checks:

```bash
sudo eos validate vault
```

**Checks:**
- Binary exists and is executable
- Config file exists and is valid
- TLS certificates exist (if TLS enabled)
- Certificates are valid and not expired
- Service is running
- Port is accessible
- Vault responds to API requests
- Exit code 0 if all checks pass

### `eos repair vault`

Automatically fix common issues:

```bash
sudo eos repair vault
```

**Fixes:**
- Generates missing TLS certificates
- Fixes empty certificate paths in config
- Corrects file permissions
- Updates systemd service to modern syntax
- Restarts service if needed
- Attempts unsealing if sealed

---

## Testing Checklist for Claude Code

After refactoring, verify ALL of the following:

### Installation Tests

- [ ] Clean install on fresh system succeeds
- [ ] Can install with `--tls=true` (default)
- [ ] Can install with `--tls=false`
- [ ] Can install with custom cert paths
- [ ] Port conflict detected and reported clearly
- [ ] Previous installation cleaned up properly

### TLS Certificate Tests

- [ ] Auto-generated certs are valid
- [ ] Certs have correct SANs (hostname, localhost, 127.0.0.1)
- [ ] Cert file permissions are 644
- [ ] Key file permissions are 600
- [ ] Config NEVER contains empty strings for cert paths
- [ ] Config without TLS doesn't reference cert paths

### Configuration Tests

- [ ] `vault validate` runs successfully
- [ ] Validation errors cause installation to fail
- [ ] Config has correct syntax
- [ ] Storage path is valid and writable
- [ ] API address is correct (http/https based on TLS)

### Permission Tests

- [ ] Vault user created before directories
- [ ] All directories have correct ownership
- [ ] All files have correct permissions (see matrix)
- [ ] Token file created with mode 0600
- [ ] Init file created with mode 600

### Service Tests

- [ ] Systemd service uses `AmbientCapabilities`
- [ ] Service does NOT use deprecated `Capabilities=`
- [ ] Service starts successfully
- [ ] Service restarts on failure
- [ ] Service logs to journal
- [ ] Binary has CAP_IPC_LOCK capability

### Initialization Tests

- [ ] `vault operator init` succeeds
- [ ] Init data saved to correct location
- [ ] Init file has correct permissions (600)
- [ ] Init file contains all expected fields

### Unsealing Tests

- [ ] Manual unsealing works
- [ ] `eos pandora unseal --auto` works
- [ ] Interactive unsealing accepts indices
- [ ] Interactive unsealing accepts key values
- [ ] Security warning displayed
- [ ] Handles path `/var/lib/eos/secret/` (singular)

### Binary Tests

- [ ] Only one vault binary exists
- [ ] Binary is in `/usr/local/bin/vault`
- [ ] Binary has correct version
- [ ] Binary has execute permissions
- [ ] No duplicate binaries in PATH

### Debugging Command Tests

- [ ] `eos debug vault` runs and provides useful output
- [ ] `eos validate vault` detects all major issues
- [ ] `eos repair vault` fixes common problems
- [ ] All commands have helpful error messages

### Security Tests

- [ ] Security warning displayed about key storage
- [ ] Production alternatives documented
- [ ] File permissions prevent unauthorized access
- [ ] Private keys are never world-readable

### Upgrade/Reinstall Tests

- [ ] Can upgrade from previous version
- [ ] Reinstall doesn't lose data
- [ ] Reinstall preserves init keys
- [ ] Old configs backed up before changes

---

## Common Errors and Solutions

### Error: "open : no such file or directory"

**Cause:** Empty TLS certificate paths in config

**Solution:** 
```bash
# Check config for empty paths
grep -E 'tls_(cert|key)_file.*""' /etc/vault.d/vault.hcl

# Fix: Regenerate certificates or disable TLS
sudo eos repair vault
```

### Error: "Configuration validation failed" (with no details)

**Cause:** `vault validate` command not in PATH or failed silently

**Solution:**
```bash
# Check if vault is in PATH
which vault

# Manually validate
vault validate /etc/vault.d/vault.hcl

# Check logs
journalctl -u vault -n 50
```

### Error: "Permission denied" (token file)

**Cause:** Token file has wrong permissions (640 instead of 600)

**Solution:**
```bash
# Fix permissions
chmod 600 /run/eos/vault_agent_eos.token

# Update vault-agent config to set mode explicitly
# Add: mode = 0600 in sink config
```

### Error: "Support for option Capabilities= has been removed"

**Cause:** Systemd service using deprecated syntax

**Solution:**
```bash
# Edit service file
sudo nano /etc/systemd/system/vault.service

# Change: Capabilities=CAP_IPC_LOCK+ep
# To:     AmbientCapabilities=CAP_IPC_LOCK

sudo systemctl daemon-reload
sudo systemctl restart vault
```

### Error: Port 8179 already in use

**Cause:** Previous Vault instance still running or port used by other process

**Solution:**
```bash
# Find what's using the port
sudo lsof -i :8179

# If it's vault, kill it
sudo pkill vault

# If it's something else, choose different port or stop that process
```

---

## Environment Variables

Set these for vault CLI usage:

```bash
# Vault server address
export VAULT_ADDR="https://localhost:8179"

# Skip TLS verification (only for self-signed certs!)
export VAULT_SKIP_VERIFY=1

# Authentication token (use root token or generated token)
export VAULT_TOKEN="hvs.CAESXXX..."

# CA certificate (alternative to VAULT_SKIP_VERIFY)
export VAULT_CACERT="/etc/vault.d/tls/vault-cert.pem"

# Namespace (if using Vault Enterprise)
# export VAULT_NAMESPACE="admin"
```

---

## Final Notes

1. **This entire spec is based on months of debugging**. Every detail here was learned through trial and error.

2. **The TLS certificate empty string bug** was the #1 cause of failed installations. It MUST be prevented.

3. **The key storage security issue** is real. For production, the current approach is inadequate and must be replaced with proper key distribution or auto-unseal.

4. **File permissions matter**. EOS is strict about 600 vs 640 for good security reasons.

5. **Systemd service syntax** has changed. Use modern `AmbientCapabilities`, not deprecated `Capabilities=`.

6. **Path consistency** is critical. Stick with `/var/lib/eos/secret/` (singular), not `/secrets/` (plural).

7. **Validation before service start** prevents 90% of runtime failures. Always validate config before writing it and before starting the service.

---

## End of Specification

This document represents the complete knowledge of the vault installation process as developed over several months. Use it to audit the current implementation after refactoring and ensure no regressions.