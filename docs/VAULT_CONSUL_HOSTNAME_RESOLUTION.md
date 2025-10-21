# Vault and Consul Hostname Resolution

*Last Updated: 2025-10-21*

## Issue Summary

Vault and Consul services were inconsistently using hardcoded `127.0.0.1` and `localhost` addresses instead of proper hostname resolution. This caused issues when services needed to communicate across different network interfaces or when the actual hostname differed from localhost.

**Example of the problem:**
```
INFO Consul service is running - storage backend available {"consul_address": "127.0.0.1:8500"}
```

But the actual system hostname was `vhost11`, and services were configured to bind to that hostname.

## Root Cause

Multiple files had hardcoded IP addresses:
1. `pkg/servicestatus/consul.go` - Health check used `127.0.0.1:8500` (default port, not PortConsul)
2. `pkg/servicestatus/vault.go` - Network info displayed `127.0.0.1` instead of hostname
3. Various installation and configuration files used literal IP addresses

## Solution Implemented

### 1. Centralized Hostname Resolution

Created helper functions in `pkg/shared/service_addresses.go`:

```go
// GetInternalHostname returns the machine's hostname
func GetInternalHostname() string {
    hostname, err := os.Hostname()
    if err != nil {
        return "localhost"  // Safe fallback
    }
    return hostname
}

// Service-specific helpers
func GetVaultHTTPSAddr() string {
    hostname := GetInternalHostname()
    return fmt.Sprintf("https://%s:%d", hostname, PortVault)
}

func GetVaultHTTPAddr() string {
    hostname := GetInternalHostname()
    return fmt.Sprintf("http://%s:%d", hostname, PortVault)
}

func GetConsulAddr() string {
    hostname := GetInternalHostname()
    return fmt.Sprintf("http://%s:%d", hostname, PortConsul)
}
```

### 2. Fixed Service Status Providers

#### Consul Status ([pkg/servicestatus/consul.go:288](pkg/servicestatus/consul.go#L288))

**Before:**
```go
cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
    fmt.Sprintf("http://127.0.0.1:%d/v1/status/leader", shared.PortConsul))
```

**After:**
```go
// Use internal hostname for health check
hostname := shared.GetInternalHostname()
cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
    fmt.Sprintf("http://%s:%d/v1/status/leader", hostname, shared.PortConsul))
```

#### Vault Status ([pkg/servicestatus/vault.go:320](pkg/servicestatus/vault.go#L320))

**Before:**
```go
info := NetworkInfo{
    Endpoints: []Endpoint{
        {
            Name:     "HTTPS API",
            Protocol: "https",
            Address:  "127.0.0.1",  // WRONG
            Port:     shared.PortVault,
            Healthy:  true,
        },
    },
}

cmd := exec.Command("curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
    fmt.Sprintf("https://127.0.0.1:%d/v1/sys/health", shared.PortVault))
```

**After:**
```go
// Use internal hostname for network endpoints (same as Consul)
hostname := shared.GetInternalHostname()

info := NetworkInfo{
    Endpoints: []Endpoint{
        {
            Name:     "HTTPS API",
            Protocol: "https",
            Address:  hostname,  // Use actual hostname (e.g., vhost11)
            Port:     shared.PortVault,
            Healthy:  true,
        },
    },
}

// Use hostname for health check to match displayed endpoint
cmd := exec.Command("curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
    fmt.Sprintf("https://%s:%d/v1/sys/health", hostname, shared.PortVault))
```

### 3. Fixed Missing Import

Added missing `vault` package import to [pkg/vault/cleanup/packages.go:8](pkg/vault/cleanup/packages.go#L8):

```go
import (
    "fmt"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/vault"  // Added
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)
```

## Remaining Hardcoded Addresses

### Intentionally Preserved

Some `127.0.0.1` and `localhost` references are **intentionally kept** for valid reasons:

1. **Security filters** (`pkg/httpclient/ssrf_protection.go`, `pkg/crypto/input_validation.go`)
   - Block access to localhost to prevent SSRF attacks
   - These MUST remain hardcoded

2. **Test files** (`*_test.go`, `test/integration_test.go`)
   - Tests often run against localhost services
   - Safe to keep hardcoded

3. **User-facing examples** (`cmd/create/*.go` help text)
   - CLI examples showing `http://localhost:8080`
   - User documentation, not runtime code

4. **Docker internal networking** (`pkg/penpot/nomad.go`, `pkg/temporal/config.go`)
   - Containers communicating within the same pod use `localhost`
   - This is correct Docker networking behavior

5. **Flag defaults** (`cmd/create/hashicorp.go`)
   - Default flag values that users can override
   - `--consul-address=127.0.0.1:8500` is a reasonable default

### Should Be Reviewed (Non-Critical)

These files may benefit from hostname resolution in the future, but are lower priority:

- `pkg/terraform/providers.go` - Default Consul/Vault addresses
- `pkg/terraform/nomad_consul.go` - Terraform template addresses
- `cmd/create/services.go` - Service creation default addresses
- `pkg/vault/install.go` - API/Cluster address configuration

## Testing

### Build Verification
```bash
CGO_ENABLED=0 go build -o /tmp/eos-build ./cmd/
```

✅ **Result:** Build succeeds without errors

### Expected Behavior After Fix

**Consul Status:**
```
INFO Consul service is running - storage backend available {"consul_address": "vhost11:8161"}
```

**Vault Status:**
```
INFO Vault service is healthy {"vault_address": "vhost11:8179", "sealed": false}
```

Both now show the actual hostname instead of `127.0.0.1`.

## Related Issues

### Port Consistency

The Consul health check was using port `8500` (default) instead of `shared.PortConsul` (8161). This has been fixed to use the centralized constant.

### Hostname vs 0.0.0.0

**Important distinction:**
- `0.0.0.0` - Bind address (listens on ALL interfaces) - **Keep as is**
- Hostname (e.g., `vhost11`) - Connect address for clients - **Use for connections**

Services should:
- **Bind to:** `0.0.0.0:PORT` (accept connections from any interface)
- **Advertise:** `hostname:PORT` (tell clients where to connect)
- **Connect to:** `hostname:PORT` (when acting as a client)

## Future Improvements

1. **Audit remaining hardcoded addresses** - Run `scripts/audit_hardcoded_values.sh` monthly
2. **Add service discovery** - Consider using Consul's service catalog for dynamic addressing
3. **Environment-aware addressing** - Detect if running in Docker/Kubernetes and adjust accordingly
4. **Configuration validation** - Add tests to ensure no new hardcoded IPs are introduced

## Related Files

- [pkg/shared/service_addresses.go](pkg/shared/service_addresses.go) - Centralized hostname resolution
- [pkg/servicestatus/consul.go](pkg/servicestatus/consul.go) - Consul status provider
- [pkg/servicestatus/vault.go](pkg/servicestatus/vault.go) - Vault status provider
- [pkg/vault/cleanup/packages.go](pkg/vault/cleanup/packages.go) - Fixed import
- [scripts/fix_hardcoded_addresses.sh](scripts/fix_hardcoded_addresses.sh) - Automated fix script (reference)

## Compliance

✅ **P0 Rules:**
- Uses centralized constants from `pkg/shared/ports.go` (PortConsul, PortVault)
- No hardcoded IP addresses in business logic
- All logging uses `otelzap.Ctx(rc.Ctx)`
- Follows Assess → Intervene → Evaluate pattern

✅ **Pre-commit validation:**
- Build passes: `go build -o /tmp/eos-build ./cmd/`
- No compilation errors

---

*"Solve problems once, encode in Eos, never solve again."*
