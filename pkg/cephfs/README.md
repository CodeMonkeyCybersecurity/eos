# CephFS SDK Implementation

*Last Updated: 2025-10-20*

## Overview

Eos CephFS implementation uses the official **go-ceph SDK** (`github.com/ceph/go-ceph`) for type-safe, high-performance Ceph operations. This replaces the previous CLI-based approach with native C bindings via cgo.

## Architecture

### SDK-Based Client (`client.go`)
- Direct RADOS connection via `github.com/ceph/go-ceph/rados`
- CephFS admin operations via `github.com/ceph/go-ceph/cephfs/admin`
- Vault integration for keyring management
- Environment discovery for automatic configuration
- Consul integration for monitor discovery

### Operations Implemented

**Volumes** (`volumes.go`):
- `CreateVolume()` - Create CephFS volumes with SDK
- `DeleteVolume()` - Delete with automatic safety snapshots
- `ListVolumes()` - List all volumes
- `GetVolumeInfo()` - Detailed volume information
- `UpdateVolume()` - Modify volume settings

**Snapshots** (`snapshots.go`):
- `CreateSnapshot()` - Create volume snapshots
- `DeleteSnapshot()` - Delete with protection checks
- `ListSnapshots()` - List snapshots for volume
- `RollbackToSnapshot()` - Restore volume from snapshot
- `ProtectSnapshot()` / `UnprotectSnapshot()` - Protection management

**Pools** (`pools.go`):
- `CreatePool()` - Create Ceph pools via mon commands
- `DeletePool()` - Delete with usage checks
- `ListPools()` - List all pools
- `GetPoolInfo()` - Detailed pool information
- `UpdatePool()` - Modify pool settings (size, PG num, quota)

## Build Requirements

### Required System Packages

The go-ceph SDK requires **librados**, **librbd**, and **libcephfs** development headers at **build time**.

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y \
    librados-dev \
    librbd-dev \
    libcephfs-dev \
    ceph-common
```

#### macOS (via Homebrew):
```bash
brew install ceph
```

#### RHEL/CentOS/Fedora:
```bash
sudo dnf install -y \
    librados-devel \
    librbd-devel \
    libcephfs-devel \
    ceph-common
```

### Docker Build

For containerized builds, use multi-stage Dockerfile:

```dockerfile
# Build stage with Ceph libraries
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    golang-1.21 \
    librados-dev \
    librbd-dev \
    libcephfs-dev \
    git \
    ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=1 go build -o eos ./cmd/

# Runtime stage with Ceph client libraries
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    librados2 \
    librbd1 \
    libcephfs2 \
    ceph-common \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/eos /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/eos"]
```

### Cross-Compilation Challenges

**WARNING**: Cross-compilation is difficult due to cgo requirements.

- Cannot easily cross-compile from macOS to Linux
- Each target platform needs native Ceph libraries
- Consider building in Docker for consistent environment

## Vault Integration

### Keyring Management

Ceph keyrings are stored and retrieved via SecretManager:

```go
// Automatic during client initialization
client, err := cephfs.NewCephClient(rc, &cephfs.ClientConfig{
    UseVault: true,  // Enabled by default
    MonHosts: []string{"10.0.1.10:6789"},
})
```

### Secret Storage Path

Keyrings stored in Vault at:
```
secret/eos/ceph/keyring
```

### Manual Keyring Import

To import existing keyring into Vault:

```bash
# Store keyring in Vault
vault kv put secret/eos/ceph \
    keyring=@/etc/ceph/ceph.client.admin.keyring

# Or via eos (future feature)
eos create ceph-keyring --import /etc/ceph/ceph.client.admin.keyring
```

## Consul Integration

### Monitor Discovery

When `--use-consul` is enabled, Eos discovers Ceph monitors from Consul service registry:

```bash
# Registers monitors in Consul
consul services register -name=ceph-mon \
    -address=10.0.1.10 \
    -port=6789 \
    -tag=monitor

# Eos discovers automatically
eos create ceph --volume mydata --use-consul
```

### Service Registration

Ceph components can be registered in Consul for:
- **Health checking**: Monitor MON/MGR/OSD health
- **Service discovery**: Automatic monitor address discovery
- **Load balancing**: Distribute client connections
- **Failover**: Automatic failover to healthy monitors

### Implementation

Monitor discovery (`client.go:discoverConsulMonitors()`):
1. Query Consul for `ceph-mon` service
2. Extract healthy monitor addresses
3. Build connection string
4. Fall back to configured monitors if discovery fails

**Status**: Stub implemented, full integration pending

### Future Enhancements

- Register Ceph volumes as Consul services
- Integrate with Consul Connect for mTLS
- Use Consul KV for cluster configuration
- Health checks for CephFS mounts

## Command Structure

### Unified Flag-Based Commands

All operations use consistent flag structure:

```bash
# CREATE operations
eos create ceph --volume <name> [options]
eos create ceph --snapshot <name> --snapshot-volume <volume>
eos create ceph --pool <name> [options]

# DELETE operations
eos delete ceph --volume <name> [--skip-snapshot]
eos delete ceph --snapshot <name> --snapshot-volume <volume>
eos delete ceph --pool <name> [--force]

# UPDATE operations (TODO)
eos update ceph --volume <name> --size <new-size>
eos update ceph --pool <name> --size <new-replication>
eos update ceph --snapshot <name> --protect

# ROLLBACK operations (TODO)
eos rollback ceph --snapshot <name> --snapshot-volume <volume>

# LIST operations (existing)
eos list ceph                    # Cluster status
eos list ceph --volumes          # List volumes (TODO)
eos list ceph --snapshots        # List snapshots (TODO)
eos list ceph --pools            # List pools (TODO)
```

## Safety Features

### Automatic Safety Snapshots

Before destructive operations, Eos creates safety snapshots automatically:

```go
// Before volume deletion
pre-delete-20251020-143052

// Before volume update
pre-update-20251020-143052

// Before snapshot rollback
pre-rollback-20251020-143052
```

**Override**: Use `--skip-snapshot` flag to bypass

### Protected Snapshots

Snapshots can be protected from accidental deletion:

```bash
# Protect snapshot
eos update ceph --snapshot backup --protect

# Attempt to delete (fails)
eos delete ceph --snapshot backup --snapshot-volume mydata
# Error: snapshot 'backup' is protected

# Must unprotect first
eos update ceph --snapshot backup --unprotect
eos delete ceph --snapshot backup --snapshot-volume mydata
```

### Resource Usage Checks

Before pool deletion, Eos checks if any volumes use the pool:

```bash
eos delete ceph --pool mypool
# Error: pool 'mypool' is in use by volume 'mydata'
# Use --force to override or delete volume first
```

## Error Handling & Retry Logic

### Retry Strategy

Following CLAUDE.md principles:

**Retry (Transient Failures)**:
- Network timeouts
- Temporary Ceph cluster unavailability
- RADOS connection failures

**Fail Fast (Deterministic Failures)**:
- Invalid configuration
- Missing keyring
- Permission denied
- Resource already exists
- Resource not found

### Example

```go
// GOOD: Detects error type
if err := client.CreateVolume(rc, opts); err != nil {
    if isConfigError(err) {
        // Don't retry - config won't fix itself
        return eos_err.NewUserError("configuration invalid: %w", err)
    }
    // Retry transient failures
    return retryWithBackoff(rc, operation)
}
```

## Testing

### Unit Tests

Mock the SDK interfaces:

```go
type MockCephClient struct {
    mock.Mock
}

func (m *MockCephClient) CreateVolume(rc *eos_io.RuntimeContext, opts *VolumeCreateOptions) error {
    args := m.Called(rc, opts)
    return args.Error(0)
}
```

### Integration Tests

Require real Ceph cluster (skip with `-short` flag):

```bash
# Unit tests only
go test -short ./pkg/cephfs/...

# Integration tests (requires Ceph)
go test ./pkg/cephfs/...
```

### Test Cluster Setup

Use cephadm for quick test cluster:

```bash
# Single-node test cluster
sudo cephadm bootstrap --mon-ip 127.0.0.1 --skip-monitoring-stack

# Run integration tests
CEPH_CONF=/etc/ceph/ceph.conf go test ./pkg/cephfs/...
```

## Migration from CLI Approach

### What Changed

| Old (CLI) | New (SDK) |
|-----------|-----------|
| `exec.Command("ceph", ...)` | `client.fsAdmin.CreateVolume(spec)` |
| Parse JSON output | Native Go types |
| SSH to admin host | Direct RADOS connection |
| Text error messages | Typed error codes |
| No connection pooling | Persistent connection |

### Breaking Changes

1. **Build Requirements**: Now requires librados-dev at build time
2. **No Remote Execution**: SDK must run on node with Ceph access (cannot SSH)
3. **Configuration**: Uses ceph.conf or explicit mon hosts (no admin-host flag)
4. **Authentication**: Uses keyring via SecretManager (no SSH keys)

### Migration Path

For deployments using old CLI approach:

1. Install Ceph development packages on build host
2. Import keyrings into Vault
3. Update command invocations to new flag structure
4. Test with `--dry-run` flag (TODO)
5. Migrate production workloads

## Performance Considerations

### Connection Pooling

The SDK maintains persistent RADOS connection:

```go
// Single connection reused for all operations
client, err := cephfs.NewCephClient(rc, config)
defer client.Close()

// Fast subsequent operations
client.CreateVolume(rc, opts1)
client.CreateSnapshot(rc, opts2)
client.ListVolumes(rc)
```

### Batching

For bulk operations, reuse client connection:

```go
client, _ := cephfs.NewCephClient(rc, config)
defer client.Close()

for _, volumeName := range volumes {
    client.CreateVolume(rc, &VolumeCreateOptions{Name: volumeName})
}
```

### Caching

Consider caching for frequently-accessed data:

```go
// Cache volume list for 30 seconds
type CachedClient struct {
    client *CephClient
    cache  *time.Cache
}

func (c *CachedClient) ListVolumes(rc *eos_io.RuntimeContext) ([]*VolumeInfo, error) {
    if cached := c.cache.Get("volumes"); cached != nil {
        return cached.([]*VolumeInfo), nil
    }

    volumes, err := c.client.ListVolumes(rc)
    if err == nil {
        c.cache.Set("volumes", volumes, 30*time.Second)
    }
    return volumes, err
}
```

## Troubleshooting

### Build Errors

**Error**: `fatal error: 'rados/librados.h' file not found`

**Solution**: Install librados-dev package (see Build Requirements)

---

**Error**: `undefined reference to 'rados_create'`

**Solution**: Ensure CGO is enabled: `CGO_ENABLED=1 go build`

### Runtime Errors

**Error**: `failed to connect to Ceph cluster: timeout`

**Solution**:
- Check monitor addresses are correct
- Verify network connectivity to monitors
- Check keyring permissions
- Use `eos debug ceph` for diagnostics

---

**Error**: `permission denied`

**Solution**:
- Verify keyring has correct capabilities
- Check Ceph user permissions: `ceph auth get client.admin`
- Ensure keyring is in Vault or specified path

### Consul Integration

**Error**: `failed to discover monitors from Consul`

**Solution**:
- Verify Consul is running
- Check `ceph-mon` service is registered
- Use explicit `--monitors` flag as fallback

## Future Enhancements

1. **Sync/Replication**: Cross-cluster volume replication
2. **Backup/Restore**: Automated backup workflows
3. **Quota Management**: Per-user quotas
4. **Performance Tuning**: Automatic cache/performance settings
5. **Multi-Cluster**: Manage multiple Ceph clusters
6. **RBD Support**: Add RBD (block device) operations
7. **RGW Support**: Add object storage operations

## References

- [go-ceph Documentation](https://pkg.go.dev/github.com/ceph/go-ceph)
- [Ceph Documentation](https://docs.ceph.com/)
- [CLAUDE.md](../../CLAUDE.md) - Eos coding standards
- [PATTERNS.md](../../docs/PATTERNS.md) - Implementation patterns

---

*"Cybersecurity. With humans."*
