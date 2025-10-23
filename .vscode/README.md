# VS Code Configuration for Eos Development

*Last Updated: 2025-10-23*

## Overview

Eos uses CGO for Ceph (`pkg/cephfs`) and libvirt (`pkg/kvm`) integration. To enable development on macOS (where these C libraries don't exist), we use **stub files** with build tags.

## The Stub File Pattern

### How It Works

**Problem:** CGO packages require C libraries that only exist on Linux.

**Solution:** Dual implementation with build tags:

```
pkg/cephfs/
  ├── client.go            # Real implementation (//go:build !darwin)
  ├── client_stub.go       # macOS stub (//go:build darwin)
  ├── volumes.go           # Real implementation (//go:build !darwin)
  └── ... (other files)

pkg/kvm/
  ├── libvirt.go               # Real implementation (//go:build linux)
  ├── libvirt_stub_darwin.go   # macOS stub (//go:build darwin)
  ├── lifecycle.go             # Real implementation (//go:build linux)
  ├── lifecycle_stub_darwin.go # macOS stub (//go:build darwin)
  └── ... (19 stub files total)
```

**Result:**
- ✅ Code compiles on macOS for development
- ✅ gopls works for type checking and autocomplete
- ✅ Local linting works with golangci-lint
- ✅ CI/CD on Linux uses real implementations
- ✅ Production deploys use real CGO

### Build Tags Explained

**Real implementation files:**
```go
//go:build linux
// +build linux

package kvm

import "libvirt.org/go/libvirt"

func StartDomain(ctx context.Context, vmName string) error {
    // Real libvirt code
}
```

**macOS stub files:**
```go
//go:build darwin
// +build darwin

package kvm

import "fmt"

const errLibvirtMacOS = "libvirt operations not available on macOS - deploy to Linux to use KVM features"

func StartDomain(ctx context.Context, vmName string) error {
    return fmt.Errorf(errLibvirtMacOS)
}
```

**What Go sees:**
- On macOS: Only compiles `*_stub_darwin.go` files
- On Linux: Only compiles real implementation files
- Both provide the same API surface

## gopls Configuration

[settings.json](settings.json) configures gopls to understand CGO:

```json
{
  "gopls": {
    "build.buildFlags": [
      "-tags=libvirt,integration"
    ],
    "build.env": {
      "CGO_ENABLED": "1"
    }
  }
}
```

This tells gopls:
- CGO is enabled (even on macOS)
- Use the appropriate build tags
- Provides type checking and autocomplete for stub files

## Local Development Workflow

### 1. Development on macOS

```bash
# Edit files normally
vim pkg/cephfs/volumes.go

# Build (uses stub files automatically)
go build -o /tmp/eos-build ./cmd/

# Lint (uses stub files)
golangci-lint run ./pkg/cephfs/...

# Test (uses stub files, will error if trying real operations)
go test ./pkg/cephfs/...
```

### 2. Testing on Linux (vhost1)

```bash
# On vhost1 - pull latest code
cd /opt/eos && git pull

# Build with real CGO
CGO_ENABLED=1 go build -o /tmp/eos-build ./cmd/

# Lint with real CGO
CGO_ENABLED=1 golangci-lint run ./pkg/cephfs/... ./pkg/kvm/...

# Test with real implementations
CGO_ENABLED=1 go test ./pkg/cephfs/... ./pkg/kvm/...
```

### 3. CI/CD (GitHub Actions)

CI automatically uses Linux runners with real CGO:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Install Ceph dependencies
        run: sudo apt-get install -y libcephfs-dev librados-dev

      - name: Build and test
        run: make ci-cgo
```

## Linting

### Local Linting (macOS)

```bash
# Uses .golangci.yml configuration
make lint

# Or directly
golangci-lint run ./...
```

This works on macOS because it lints the stub files, which have no CGO dependencies.

### Remote Linting (Linux)

For full CGO validation before deployment:

```bash
# SSH to Linux server
ssh vhost1

# Navigate to Eos
cd /opt/eos

# Pull latest (or rsync from macOS)
git pull

# Lint with CGO
make lint-cgo
```

## Makefile Targets

See [../Makefile](../Makefile) for all targets:

```bash
make build          # Build on current platform
make test           # Test with stubs (macOS) or real (Linux)
make lint           # Lint with current platform's files
make lint-cgo       # Lint CGO packages specifically (Linux only)
make ci             # Full CI pipeline
make ci-cgo         # CGO-specific CI pipeline
```

## Creating New CGO Functionality

When adding new CGO functions, follow the stub pattern:

### 1. Real Implementation (Linux)

```go
//go:build linux
// pkg/kvm/new_feature.go

package kvm

import "libvirt.org/go/libvirt"

func NewFeature(ctx context.Context, vmName string) error {
    // Real implementation using libvirt
    conn, err := libvirt.NewConnect("qemu:///system")
    // ...
}
```

### 2. macOS Stub

```go
//go:build darwin
// pkg/kvm/new_feature_stub_darwin.go

package kvm

import (
    "context"
    "fmt"
)

func NewFeature(ctx context.Context, vmName string) error {
    return fmt.Errorf(errLibvirtMacOS)
}
```

### 3. Verify Build on Both Platforms

```bash
# On macOS
go build ./pkg/kvm

# On Linux (via SSH)
ssh vhost1 "cd /opt/eos && go build ./pkg/kvm"
```

## Stub Maintenance

**When to update stubs:**
1. When adding new exported functions
2. When changing function signatures
3. When adding new exported types

**How to check if stubs are out of sync:**
```bash
# On macOS - if build fails, stubs are missing
go build ./pkg/kvm

# Check for undefined functions
go test ./pkg/kvm 2>&1 | grep "undefined:"
```

**Automated stub validation:**
```bash
# Compare exported symbols between platforms
# (Future enhancement - could be added to CI)
go doc -all ./pkg/kvm | grep "^func"
```

## Troubleshooting

### Problem: "undefined: SomeFunction" on macOS

**Cause:** New function added to real implementation without stub.

**Solution:**
```bash
# Find missing function in real implementation
grep -r "func SomeFunction" pkg/kvm/*.go | grep -v "_stub"

# Create stub in appropriate *_stub_darwin.go file
```

### Problem: Build fails on Linux but passes on macOS

**Cause:** Real implementation has syntax/type errors that stub doesn't catch.

**Solution:**
```bash
# SSH to Linux and build there
ssh vhost1 "cd /opt/eos && CGO_ENABLED=1 go build ./pkg/kvm"

# Fix errors in real implementation files
```

### Problem: gopls shows errors for CGO imports

**Cause:** gopls configuration not loaded.

**Solution:**
1. Reload VS Code window: Cmd+Shift+P -> "Developer: Reload Window"
2. Check gopls settings: Cmd+Shift+P -> "Go: Locate Configured Go Tools"
3. Verify CGO_ENABLED=1 in [settings.json](settings.json)

## Summary

**Key Points:**
- ✅ Stub files enable macOS development for Linux-only CGO packages
- ✅ Build tags ensure correct files compile on each platform
- ✅ gopls configuration provides IDE support on macOS
- ✅ Same API surface on both platforms (stubs return errors)
- ✅ CI/CD on Linux validates real implementations
- ✅ No complex remote linting setup needed

**Development Flow:**
1. Edit code on macOS (stubs compile)
2. Commit and push to GitHub
3. SSH to Linux to test real implementation
4. CI/CD validates on Linux
5. Production deploys use real CGO

**Files:**
- [settings.json](settings.json) - gopls configuration
- [../.golangci.yml](../.golangci.yml) - Linter configuration
- [../Makefile](../Makefile) - Build and lint targets
- [../pkg/cephfs/*_stub.go](../pkg/cephfs/) - Ceph stubs (3 files)
- [../pkg/kvm/*_stub_darwin.go](../pkg/kvm/) - KVM stubs (19 files)

---

**Philosophy:** Stub files solve the real problem - enabling development on macOS while deploying to Linux - without complex workarounds or remote execution.
