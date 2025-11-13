# CGO Stub File Pattern for Cross-Platform Development

*Last Updated: 2025-10-23*

## Overview

Eos uses **stub files with build tags** to enable macOS development for Linux-only CGO packages (`pkg/cephfs`, `pkg/kvm`). This is the official Eos pattern for handling platform-specific code.

## Problem Statement

Eos integrates with:
- **Ceph** via `github.com/ceph/go-ceph` (requires libcephfs-dev, librados-dev)
- **libvirt** via `libvirt.org/go/libvirt` (requires libvirt-dev)

These C libraries only exist on Linux, making it impossible to:
- Compile CGO packages on macOS
- Run linters (golangci-lint, gopls) on macOS
- Get IDE autocomplete/type-checking on macOS

## Solution: Stub Files with Build Tags

**Concept:** Provide two implementations of the same API:
1. **Real implementation** (Linux only) - uses actual CGO libraries
2. **Stub implementation** (macOS/Darwin) - returns "not available" errors

**Mechanism:** Go build tags ensure the correct version compiles on each platform.

## File Structure

```
pkg/cephfs/
  ├── client.go                 # Real: //go:build !darwin
  ├── client_stub.go            # Stub: //go:build darwin
  ├── pools.go                  # Real: //go:build !darwin
  ├── pools_stub.go             # Stub: //go:build darwin
  ├── snapshots.go              # Real: //go:build !darwin
  └── snapshots_stub.go         # Stub: //go:build darwin

pkg/kvm/
  ├── libvirt.go                # Real: //go:build linux
  ├── libvirt_stub_darwin.go    # Stub: //go:build darwin
  ├── lifecycle.go              # Real: //go:build linux
  ├── lifecycle_stub_darwin.go  # Stub: //go:build darwin
  ├── network.go                # Real: //go:build linux
  ├── network_stub_darwin.go    # Stub: //go:build darwin
  └── ... (19 stub files total)
```

## Implementation Pattern

### Real Implementation (Linux)

```go
//go:build linux
// +build linux

// pkg/kvm/lifecycle.go
package kvm

import (
    "context"
    "libvirt.org/go/libvirt"
)

func StartDomain(ctx context.Context, vmName string) error {
    conn, err := libvirt.NewConnect("qemu:///system")
    if err != nil {
        return fmt.Errorf("failed to connect to libvirt: %w", err)
    }
    defer conn.Close()

    dom, err := conn.LookupDomainByName(vmName)
    if err != nil {
        return fmt.Errorf("failed to lookup domain %s: %w", vmName, err)
    }
    defer dom.Free()

    return dom.Create()
}
```

### Stub Implementation (macOS)

```go
//go:build darwin
// +build darwin

// pkg/kvm/lifecycle_stub_darwin.go
package kvm

import (
    "context"
    "fmt"
)

const errLibvirtMacOS = "libvirt operations not available on macOS - deploy to Linux to use KVM features"

func StartDomain(ctx context.Context, vmName string) error {
    return fmt.Errorf(errLibvirtMacOS)
}
```

### Key Elements

1. **Build tags** - `//go:build linux` vs `//go:build darwin`
2. **Same package** - Both files are in same package
3. **Same API** - Identical function signatures
4. **Error messages** - Stubs return descriptive errors
5. **Naming convention** - Stubs end in `_stub_darwin.go`

## Build Tag Rules

| Platform | Build Tag | Files Compiled | CGO Libraries |
|----------|-----------|----------------|---------------|
| Linux | `//go:build linux` | Real implementations | libvirt, ceph |
| macOS | `//go:build darwin` | Stub implementations | None |
| Windows | Not supported | N/A | N/A |

**CephFS uses `!darwin` instead of `linux`:**
```go
//go:build !darwin
// +build !darwin
```
This includes Linux + BSD + others. Both patterns are acceptable.

## Development Workflow

### On macOS (Development)

```bash
# 1. Edit real implementation files
vim pkg/cephfs/volumes.go

# 2. Build automatically uses stubs
go build -o /tmp/eos-build ./cmd/
# ✅ Compiles using stub files

# 3. Lint uses stubs
golangci-lint run ./pkg/cephfs/...
# ✅ Lints stub files (no CGO needed)

# 4. gopls provides IDE support
# ✅ Autocomplete, type-checking work
```

### On Linux (Testing/Production)

```bash
# 1. Pull latest code
cd /opt/eos && git pull

# 2. Build uses real implementations
CGO_ENABLED=1 go build -o /tmp/eos-build ./cmd/
# ✅ Compiles with actual CGO libraries

# 3. Lint real implementations
CGO_ENABLED=1 golangci-lint run ./pkg/cephfs/... ./pkg/kvm/...
# ✅ Catches real CGO errors

# 4. Test real implementations
CGO_ENABLED=1 go test ./pkg/cephfs/... ./pkg/kvm/...
# ✅ Tests actual Ceph/libvirt integration
```

## Creating New CGO Functions

### Step-by-Step Process

**1. Identify the function category**

Is it related to:
- Libvirt operations? → `pkg/kvm/libvirt_stub_darwin.go`
- VM lifecycle? → `pkg/kvm/lifecycle_stub_darwin.go`
- Snapshots? → `pkg/kvm/snapshot_stub_darwin.go`
- Ceph volumes? → `pkg/cephfs/volumes_stub.go`

**2. Write the real implementation (Linux)**

```go
//go:build linux
// pkg/kvm/new_feature.go

package kvm

import (
    "context"
    "fmt"
    "libvirt.org/go/libvirt"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NewFeature demonstrates a new libvirt feature
func NewFeature(rc *eos_io.RuntimeContext, vmName string, config *FeatureConfig) error {
    logger := otelzap.Ctx(rc.Ctx)

    // ASSESS
    logger.Info("Assessing VM for new feature", zap.String("vm", vmName))
    conn, err := libvirt.NewConnect("qemu:///system")
    if err != nil {
        return fmt.Errorf("failed to connect: %w", err)
    }
    defer conn.Close()

    // INTERVENE
    logger.Info("Applying new feature")
    // ... real implementation ...

    // EVALUATE
    logger.Info("Feature applied successfully")
    return nil
}
```

**3. Write the stub (macOS)**

```go
//go:build darwin
// pkg/kvm/new_feature_stub_darwin.go

package kvm

import (
    "fmt"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NewFeature stub for macOS
func NewFeature(rc *eos_io.RuntimeContext, vmName string, config *FeatureConfig) error {
    return fmt.Errorf(errLibvirtMacOS)
}
```

**4. Verify on both platforms**

```bash
# macOS - verify stub compiles
go build ./pkg/kvm

# Linux - verify real implementation compiles
ssh vhost1 "cd /opt/eos && CGO_ENABLED=1 go build ./pkg/kvm"
```

## Stub Maintenance

### When Stubs Become Out of Sync

**Symptoms:**
```bash
# On macOS
$ go build ./pkg/kvm
./pkg/kvm/some_file.go:42:5: undefined: NewFunction
```

**Cause:** Real implementation added new function, stub missing.

**Fix:**
1. Find the missing function in real files:
   ```bash
   grep -r "func NewFunction" pkg/kvm/*.go | grep -v "_stub"
   ```

2. Identify which stub file it belongs to:
   - Libvirt → `libvirt_stub_darwin.go`
   - Lifecycle → `lifecycle_stub_darwin.go`
   - etc.

3. Add stub implementation:
   ```go
   func NewFunction(ctx context.Context, vmName string) error {
       return fmt.Errorf(errLibvirtMacOS)
   }
   ```

### Validation Script (Future)

```bash
#!/usr/bin/env bash
# scripts/validate_stubs.sh - Validate stub coverage

# Extract all exported functions from real implementations
real_funcs=$(grep -r "^func [A-Z]" pkg/kvm/*.go | grep -v "_stub" | awk '{print $2}' | cut -d'(' -f1 | sort -u)

# Extract all exported functions from stubs
stub_funcs=$(grep -r "^func [A-Z]" pkg/kvm/*_stub_darwin.go | awk '{print $2}' | cut -d'(' -f1 | sort -u)

# Find missing stubs
missing=$(comm -23 <(echo "$real_funcs") <(echo "$stub_funcs"))

if [[ -n "$missing" ]]; then
    echo "[ERROR] Missing stubs for:"
    echo "$missing"
    exit 1
else
    echo "[SUCCESS] All functions have stubs"
fi
```

## IDE Configuration

### VS Code Setup

Create [.vscode/settings.json](.vscode/settings.json):

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
- Use appropriate build tags
- Provides type-checking for stub files

### GoLand Setup

File → Settings → Go → Build Tags & Vendoring:
```
Custom tags: libvirt,integration
OS: darwin
Arch: amd64
CGO enabled: true
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/test-cgo.yml
name: Test CGO Packages

on: [push, pull_request]

jobs:
  test-cgo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Ceph dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libcephfs-dev librados-dev libvirt-dev

      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
            sh -s -- -b $(go env GOPATH)/bin v1.61.0

      - name: Build with CGO
        run: CGO_ENABLED=1 go build -o /tmp/eos-build ./cmd/

      - name: Lint CGO packages
        run: CGO_ENABLED=1 golangci-lint run ./pkg/cephfs/... ./pkg/kvm/...

      - name: Test CGO packages
        run: CGO_ENABLED=1 go test -v ./pkg/cephfs/... ./pkg/kvm/...
```

## Comparison: Alternatives We Rejected

### ❌ Option 1: Docker-based Linting

**Idea:** Run linting inside Linux Docker container on macOS.

**Why rejected:**
- Slow (Docker overhead)
- Complex setup (volume mounts, networking)
- gopls can't work inside Docker
- No IDE integration

### ❌ Option 2: Remote SSH Linting

**Idea:** SSH to Linux server, run linting there, parse results.

**Why rejected:**
- Requires network connectivity
- Slow feedback loop
- Requires maintaining SSH scripts
- Doesn't help gopls

### ❌ Option 3: Build Tags Only (No Stubs)

**Idea:** Use `//go:build linux` on all CGO files, exclude completely on macOS.

**Why rejected:**
- Can't import the package on macOS
- gopls completely broken
- No type-checking available
- Can't write cmd/ that uses CGO packages

### ✅ Stub Files (Current Solution)

**Why chosen:**
- Fast (local compilation)
- gopls works perfectly
- IDE autocomplete/type-checking
- CI/CD validates real implementations
- Simple pattern (just add `_stub_darwin.go` files)

## Troubleshooting

### Problem: gopls shows "undefined: SomeType"

**Cause:** Stub file missing type definition.

**Solution:** Add type stub:
```go
//go:build darwin

package kvm

// SomeType stub for macOS
type SomeType struct {
    // Match real implementation's exported fields
    Name string
    ID   int
}
```

### Problem: "implicit assignment of unexported field in struct literal"

**Cause:** Real implementation has unexported fields, stub doesn't match.

**Solution:** Copy struct exactly from real implementation:
```go
type SomeType struct {
    Name       string  // exported
    ID         int     // exported
    unexported string  // MUST include unexported fields too!
}
```

### Problem: Build passes on macOS but fails on Linux

**Cause:** Stub API doesn't match real implementation.

**Solution:**
```bash
# SSH to Linux and verify
ssh vhost1 "cd /opt/eos && CGO_ENABLED=1 go build ./pkg/kvm"

# Look for signature mismatches
# Fix real implementation to match stub (or vice versa)
```

## Summary

**Stub File Pattern:**
- ✅ Enables cross-platform development
- ✅ Works with gopls and IDEs
- ✅ Simple, maintainable pattern
- ✅ CI/CD validates real implementations
- ✅ No network/Docker dependencies

**Key Rules:**
1. One stub file per real implementation file
2. Use `_stub_darwin.go` naming convention
3. Match API exactly (same signatures)
4. Return descriptive errors
5. Include type definitions in stubs
6. Test on both platforms before committing

**Files:**
- Real: `pkg/cephfs/client.go` (//go:build !darwin)
- Stub: `pkg/cephfs/client_stub.go` (//go:build darwin)
- Real: `pkg/kvm/libvirt.go` (//go:build linux)
- Stub: `pkg/kvm/libvirt_stub_darwin.go` (//go:build darwin)

---

**See Also:**
- [.vscode/README.md](../.vscode/README.md) - VS Code configuration
- [CLAUDE.md](../CLAUDE.md) - Eos development guidelines
- [Makefile](../Makefile) - Build targets (`make lint-cgo`)
