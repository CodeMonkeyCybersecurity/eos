# Vault TLS Certificate Fix

*Last Updated: 2025-10-14*

## Problem Identified

The TLS consolidation code with proper SANs was deployed, but existing Vault installations **skip certificate regeneration** when certificates already exist. This means installations with broken certificates (missing host IP SANs) continue to fail even after updating EOS.

### Symptoms:
```
INFO TLS certificate already exists, skipping generation
WARN Vault process is running but not responding as expected
ERROR http: TLS handshake error from 127.0.0.1:xxxxx: remote error: tls: bad certificate
```

## Root Cause

**File:** `pkg/vault/install.go:1371-1373`

**Old Code:**
```go
if vi.fileExists(certPath) && vi.fileExists(keyPath) {
    vi.logger.Info("TLS certificate already exists, skipping generation")
    return nil  // Skips regeneration even if cert is broken
}
```

**Problem:** No validation of existing certificate, no respect for `--force` flag.

## Fix Applied

**New Code:** Now respects `--force` flag and backs up old certificates:
```go
if vi.fileExists(certPath) && vi.fileExists(keyPath) {
    if vi.config.ForceReinstall {
        vi.logger.Info("Force flag set, regenerating TLS certificate")
        // Backup existing certificate
        backupPath := certPath + ".backup." + time.Now().Format("20060102-150405")
        os.Rename(certPath, backupPath)
        os.Rename(keyPath, keyPath+".backup."+time.Now().Format("20060102-150405"))
        // Continue to regenerate
    } else {
        vi.logger.Info("TLS certificate already exists, skipping generation")
        vi.logger.Info("Use --force flag to regenerate certificate with updated SANs")
        return nil
    }
}
```

## Quick Fix for Existing Installations

### Option 1: Use --force Flag (Recommended)
```bash
# Update EOS first
sudo eos self update

# Force certificate regeneration
sudo eos create vault --force

# This will:
# 1. Backup old certificate to /etc/vault.d/tls/vault.crt.backup.TIMESTAMP
# 2. Generate new certificate with comprehensive SANs
# 3. Restart Vault with new certificate
```

### Option 2: Manual Certificate Removal
```bash
# Delete old broken certificates
sudo rm /etc/vault.d/tls/vault.crt
sudo rm /etc/vault.d/tls/vault.key

# Reinstall (will generate new certificates)
sudo eos create vault
```

### Option 3: Clean Reinstall
```bash
# Nuclear option - full cleanup
sudo eos delete vault
sudo eos create vault
```

## Verification Steps

### 1. Check Certificate SANs
```bash
sudo openssl x509 -in /etc/vault.d/tls/vault.crt -text -noout | grep -A 10 "Subject Alternative Name"
```

**Expected Output (Good):**
```
X509v3 Subject Alternative Name:
    DNS:vhost5, DNS:localhost, DNS:*.vhost5, DNS:vhost5.local,
    DNS:vault, DNS:vault.service.consul, DNS:*.localhost,
    IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1, IP Address:10.x.x.x
```

**Bad Output (Old Certificate):**
```
X509v3 Subject Alternative Name:
    DNS:vhost5, DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
```
(Missing: wildcards, .local, actual host IP, consul DNS)

### 2. Test Vault Connection
```bash
export VAULT_ADDR='https://localhost:8179'
export VAULT_SKIP_VERIFY=1
vault status
```

**Expected:** Should return status without TLS errors.

### 3. Check Service Logs for TLS Errors
```bash
sudo journalctl -u vault -n 50 --no-pager | grep -i "tls\|handshake"
```

**Expected:** No "TLS handshake error" messages after fix.

### 4. Run EOS Diagnostics
```bash
sudo eos debug vault
```

**Expected:** All checks should pass.

## Certificate Comparison

### Old Certificate (Broken):
- **Key Size:** 2048-bit RSA
- **Validity:** 1 year
- **SANs:** hostname, localhost, 127.0.0.1, ::1
- **Missing:**
  - Actual host IP (e.g., 10.x.x.x)
  - Wildcard DNS (*.hostname)
  - .local variants
  - vault.service.consul

### New Certificate (Fixed):
- **Key Size:** 4096-bit RSA
- **Validity:** 10 years
- **SANs:** Comprehensive list including:
  - All DNS: hostname, localhost, vault, *.hostname, *.localhost, hostname.local, vault.service.consul
  - All IPs: 127.0.0.1, ::1, **actual host IP from network interfaces**
  - FQDN and reverse DNS entries

## Why This Matters

The missing host IP in SANs causes:
1. ❌ Vault CLI cannot connect over TLS
2. ❌ Health checks fail with certificate validation errors
3. ❌ Vault appears "running but not responding"
4. ❌ Agent configuration fails
5. ❌ Cluster communication breaks

With proper SANs:
1.  Vault CLI connects successfully
2.  Health checks pass
3.  Agent configuration works
4.  Cluster communication established
5.  Proper TLS validation throughout

## Implementation Timeline

- **2025-10-14 (Earlier):** TLS consolidation code created with proper SANs
- **2025-10-14 (Now):** Fixed installer skip logic to respect --force flag
- **Next:** Test on existing installations, ensure fix propagates

## Future Improvements

Consider these enhancements:

### Option A: Certificate Validation
```go
if vi.fileExists(certPath) {
    if isValidCertificate(certPath) {
        vi.logger.Info("Valid certificate exists, skipping")
        return nil
    }
    vi.logger.Warn("Invalid certificate detected, regenerating")
}
```

### Option B: Always Regenerate
```go
// Always regenerate during installation to ensure consistency
if vi.fileExists(certPath) {
    vi.logger.Info("Backing up existing certificate")
    backupCertificate(certPath)
}
vi.logger.Info("Generating TLS certificate with proper SANs")
return generateCertificate()
```

### Option C: Certificate Version Check
```go
// Check certificate metadata to see if it was generated by old code
certVersion := getCertificateVersion(certPath)
if certVersion < CURRENT_CERT_VERSION {
    vi.logger.Info("Outdated certificate detected, regenerating")
    regenerateCertificate()
}
```

## Related Files

- [`pkg/vault/tls_certificate.go`](pkg/vault/tls_certificate.go) - Consolidated TLS generation
- [`pkg/vault/install.go`](pkg/vault/install.go:1371) - Installer skip logic (FIXED)
- [`pkg/vault/phase3_tls_cert.go`](pkg/vault/phase3_tls_cert.go) - Phase 3 TLS setup
- [`CONSOLIDATION_PLAN_V2.md`](pkg/vault/CONSOLIDATION_PLAN_V2.md) - Refactoring plan

---

**Bottom Line:** The fix works, but only applies to NEW installations or installations using `--force`. Existing installations need to use `--force` to regenerate certificates with proper SANs.
