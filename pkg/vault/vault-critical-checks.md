# Quick Reference: Critical Vault Installation Checks

## 🔴 CRITICAL BUGS TO CHECK IMMEDIATELY

These were our TOP failure causes. Check these FIRST:

### 1. Empty TLS Certificate Paths (90% of failures)
```bash
# Check config for empty strings
grep -E 'tls_(cert|key)_file.*""' /etc/vault.d/vault.hcl

# If found: CRITICAL BUG STILL PRESENT
# Config should NEVER have:
# tls_cert_file = ""
# tls_key_file  = ""
```

**In Code:**
```go
// WRONG - Can write empty strings
fmt.Fprintf(w, `tls_cert_file = "%s"`, certPath)

// RIGHT - Validates first
if certPath == "" {
    return errors.New("cert path cannot be empty")
}
```

### 2. Config Validation Not Running
```bash
# Installation logs should show:
[INFO] Validating configuration
[DEBUG] Running: vault validate /etc/vault.d/vault.hcl
[TRACE] Validation output: Success! Configuration is valid.

# NOT:
[DEBUG] Configuration validation failed:    ← empty error message!
```

### 3. File Permissions Wrong
```bash
# Check token file permissions
stat -c %a /run/eos/vault_agent_eos.token
# MUST be: 600
# NOT: 640 or 644

# Check private key
stat -c %a /etc/vault.d/tls/vault-key.pem
# MUST be: 600
```

### 4. Systemd Deprecated Syntax
```bash
# Check service file
grep "^Capabilities=" /etc/systemd/system/vault.service

# If found: BUG (deprecated)
# Should use: AmbientCapabilities=CAP_IPC_LOCK
```

### 5. Path Inconsistency
```bash
# Check unsealing code
grep -r "/var/lib/eos/secrets/" cmd/ pkg/

# If found: BUG (wrong path - plural)
# Should be: /var/lib/eos/secret/ (singular)
```

---

## 🟡 IMPORTANT CHECKS

### User Creation Order
```bash
# In installation logs, user MUST come before directories:
[INFO] Creating vault user        ← MUST BE FIRST
[INFO] Creating directories       ← THEN THIS

# NOT the other way around
```

### Binary Location
```bash
# Only one location
which -a vault
# Should return: /usr/local/bin/vault
# NOT: Multiple paths

# No duplicate in /usr/bin
test -f /usr/bin/vault && echo "WARNING: Duplicate binary"
```

### Security Warning
```bash
# Installation output MUST include:
  SECURITY WARNING 
All 5 unseal keys are stored in:
/var/lib/eos/secret/vault_init.json

# If not present: Security feature missing
```

---

## COMPLETE CHECKS BY PHASE

### Phase 0: Pre-Installation
- [ ] Detects existing installation
- [ ] Checks port availability
- [ ] Backs up existing configs

### Phase 1: User Creation
- [ ] Creates user before directories
- [ ] System user, no shell
- [ ] `id vault` works after creation

### Phase 2: Directories
- [ ] `/opt/vault/data` - 755 vault:vault
- [ ] `/etc/vault.d` - 755 vault:vault
- [ ] `/etc/vault.d/tls` - 755 vault:vault
- [ ] `/var/lib/eos/secret` - 700 root:root

### Phase 3: TLS Certificates
- [ ] **NO empty strings in config**
- [ ] Auto-generates when `--tls=true`
- [ ] vault-cert.pem - 644
- [ ] vault-key.pem - 600
- [ ] Valid X.509 certificates
- [ ] Correct SANs (hostname, localhost, 127.0.0.1)

### Phase 4: Binary
- [ ] In `/usr/local/bin/vault`
- [ ] Correct version (1.20.4 or newer)
- [ ] Has CAP_IPC_LOCK capability
- [ ] 755 permissions
- [ ] No duplicates

### Phase 5: Configuration
- [ ] `vault validate` runs successfully
- [ ] No empty TLS paths
- [ ] Storage path valid
- [ ] API address matches TLS (https/http)
- [ ] Config file 644 permissions

### Phase 6: Systemd Service
- [ ] Uses `AmbientCapabilities` (not `Capabilities=`)
- [ ] Has `After=network-online.target`
- [ ] Has `ConditionFileNotEmpty=/etc/vault.d/vault.hcl`
- [ ] Restart policy: `Restart=on-failure`
- [ ] Security hardening present
- [ ] Logs to journal

### Phase 7: Initialization
- [ ] Creates `/var/lib/eos/secret/vault_init.json`
- [ ] File is 600 root:root
- [ ] Contains 5 unseal keys
- [ ] Contains root token
- [ ] Security warning displayed

### Phase 8: Unsealing
- [ ] `eos pandora unseal` exists
- [ ] `--auto` flag works
- [ ] Uses correct path (singular)
- [ ] Accepts indices or keys
- [ ] Clear error messages

### Phase 9: Root Token
- [ ] Extracts correctly
- [ ] Sets VAULT_TOKEN
- [ ] Instructions provided

### Phase 10: Vault Agent
- [ ] Config has `mode = 0600` in sink
- [ ] Token file created with 600 perms
- [ ] Service creates /run/eos
- [ ] Depends on vault.service

---

## 🔧 QUICK VERIFICATION SCRIPT

```bash
#!/bin/bash
# Run this after installation to verify

echo "=== Critical Checks ==="

# 1. Empty paths check
echo -n "Empty TLS paths: "
grep -qE 'tls_(cert|key)_file.*""' /etc/vault.d/vault.hcl && echo " FAIL" || echo " PASS"

# 2. Cert files exist
echo -n "Cert files exist: "
test -f /etc/vault.d/tls/vault-cert.pem && test -f /etc/vault.d/tls/vault-key.pem && echo " PASS" || echo " FAIL"

# 3. Key permissions
echo -n "Key permissions: "
test "$(stat -c %a /etc/vault.d/tls/vault-key.pem)" = "600" && echo " PASS" || echo " FAIL"

# 4. Systemd syntax
echo -n "Systemd syntax: "
grep -q "AmbientCapabilities=CAP_IPC_LOCK" /etc/systemd/system/vault.service && echo " PASS" || echo " FAIL"
grep -q "^Capabilities=" /etc/systemd/system/vault.service && echo " FAIL (deprecated)" || echo " PASS"

# 5. Vault running
echo -n "Vault running: "
systemctl is-active vault && echo " PASS" || echo " FAIL"

# 6. Binary location
echo -n "Binary location: "
test -x /usr/local/bin/vault && echo " PASS" || echo " FAIL"

# 7. No duplicates
echo -n "No duplicate binary: "
test ! -f /usr/bin/vault && echo " PASS" || echo "  WARNING: Duplicate at /usr/bin/vault"

# 8. Init file permissions
echo -n "Init file perms: "
test "$(stat -c %a /var/lib/eos/secret/vault_init.json)" = "600" && echo " PASS" || echo " FAIL"

# 9. Config validation
echo -n "Config valid: "
vault validate /etc/vault.d/vault.hcl &>/dev/null && echo " PASS" || echo " FAIL"

# 10. User created first
echo -n "Vault user exists: "
id vault &>/dev/null && echo " PASS" || echo " FAIL"

echo ""
echo "=== End Checks ==="
```

Save as `check-vault-install.sh` and run:
```bash
chmod +x check-vault-install.sh
sudo ./check-vault-install.sh
```

---

## 🚨 RED FLAGS IN CODE

### Anti-Pattern #1: Empty String Paths
```go
//  DANGEROUS
config := fmt.Sprintf(`
listener "tcp" {
  tls_cert_file = "%s"
  tls_key_file  = "%s"
}`, certPath, keyPath)
// If certPath is "", this crashes Vault
```

### Anti-Pattern #2: Ignoring Validation Errors
```go
//  DANGEROUS
err := validateConfig()
if err != nil {
    log.Warn("Validation failed, continuing anyway...")
}
// Should: return err
```

### Anti-Pattern #3: Wrong Path Variables
```go
//  WRONG
secretsDir := "/var/lib/eos/secrets"  // Plural!

//  CORRECT
secretDir := "/var/lib/eos/secret"    // Singular!
```

### Anti-Pattern #4: Creating Dirs Before User
```go
//  WRONG ORDER
createDirectories()
createUser()

//  CORRECT ORDER
createUser()
createDirectories()
```

### Anti-Pattern #5: Not Setting Sink Mode
```hcl
#  WRONG
sink "file" {
  config = {
    path = "/run/eos/vault_agent_eos.token"
  }
}

#  CORRECT
sink "file" {
  config = {
    path = "/run/eos/vault_agent_eos.token"
    mode = 0600
  }
}
```

---

##  QUICK FIXES

### Fix #1: Empty TLS Paths
```go
func (c *Config) Validate() error {
    if c.TLSEnabled {
        if c.TLSCertFile == "" || c.TLSKeyFile == "" {
            return fmt.Errorf("TLS enabled but certificate paths not set")
        }
        
        if !fileExists(c.TLSCertFile) {
            return fmt.Errorf("TLS cert not found: %s", c.TLSCertFile)
        }
        
        if !fileExists(c.TLSKeyFile) {
            return fmt.Errorf("TLS key not found: %s", c.TLSKeyFile)
        }
    }
    return nil
}
```

### Fix #2: Add Validation Step
```go
func installVault() error {
    // ... generate config ...
    
    // MUST validate before writing
    if err := config.Validate(); err != nil {
        return fmt.Errorf("config validation failed: %w", err)
    }
    
    // Write config
    if err := config.WriteTo("/etc/vault.d/vault.hcl"); err != nil {
        return err
    }
    
    // Validate with vault binary
    if err := exec.Command("vault", "validate", "/etc/vault.d/vault.hcl").Run(); err != nil {
        return fmt.Errorf("vault validation failed: %w", err)
    }
    
    return nil
}
```

### Fix #3: Correct Systemd
```ini
# Change this line in /etc/systemd/system/vault.service
# FROM:
Capabilities=CAP_IPC_LOCK+ep

# TO:
AmbientCapabilities=CAP_IPC_LOCK
```

### Fix #4: Set Sink Permissions
```hcl
# In /etc/vault.d/vault-agent-eos.hcl
sink "file" {
  config = {
    path = "/run/eos/vault_agent_eos.token"
    mode = 0600  # ADD THIS LINE
  }
}
```

---

##  FILE PERMISSIONS MATRIX (QUICK REF)

| File | Perms | Owner | WHY |
|------|-------|-------|-----|
| vault binary | 755 | root:root | Executable |
| vault.hcl | 644 | vault:vault | Readable config |
| vault-cert.pem | 644 | vault:vault | Public cert |
| vault-key.pem | **600** | vault:vault | **Private key!** |
| vault_init.json | **600** | root:root | **Sensitive keys!** |
| vault_agent_eos.token | **600** | eos:eos | **Auth token!** |

**Rule:** Anything with keys/tokens/secrets = **600**

---

##  SUCCESS CRITERIA

Installation is correct when:

 ALL certificate paths have values (never empty strings)
 Config passes `vault validate`
 Vault service starts and stays running
 All file permissions match matrix
 Systemd uses modern syntax
 Security warning was displayed
 Can unseal with `eos pandora unseal --auto`
 Only one vault binary in /usr/local/bin
 User created before directories
 Paths use singular `secret/` not `secrets/`

---

## 🆘 IF INSTALLATION FAILS

1. **Run the verification script** above
2. **Check logs:** `journalctl -u vault -n 100`
3. **Look for:** "open : no such file" = Empty cert paths
4. **Check config:** `cat /etc/vault.d/vault.hcl`
5. **Validate manually:** `vault validate /etc/vault.d/vault.hcl`
6. **Check certs exist:** `ls -la /etc/vault.d/tls/`
7. **Check permissions:** `stat -c %a /etc/vault.d/tls/vault-key.pem`

Most failures = empty TLS certificate paths in config.

---

This checklist represents months of debugging distilled into critical checks. Use it!