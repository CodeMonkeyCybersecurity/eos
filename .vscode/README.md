# VS Code Configuration for Eos CGO Development

*Last Updated: 2025-10-23*

## Problem Statement

Eos uses CGO for Ceph (`pkg/cephfs`) and libvirt (`pkg/kvm`) integration. These packages require C libraries that are only available on Linux, making it impossible to lint, build, or test them directly on macOS during development.

## Solution: Remote Linting via SSH

This VS Code configuration enables **remote linting** on your Linux server (`vhost1`) while developing locally on macOS. Errors are parsed and displayed in VS Code's Problems panel as if they were local.

---

## Setup Instructions

### 1. Prerequisites

**On macOS (your development machine):**
```bash
# Install fswatch for file watching (optional, for auto-lint)
brew install fswatch

# Ensure SSH key authentication to vhost1 is configured
ssh-copy-id vhost1  # If not already done
ssh vhost1 exit     # Test connection
```

**On vhost1 (your Linux server):**
```bash
# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0

# Verify installation
golangci-lint --version
```

### 2. VS Code Extensions (Optional but Recommended)

Install these extensions for the best experience:

- **Go** (golang.go) - Essential for Go development
- **Error Lens** (usernamehw.errorlens) - Shows errors inline in the editor
- **Run on Save** (emeraldwalk.runonsave) - Auto-lint on file save (already configured)

---

## Usage

### Method 1: Keyboard Shortcuts (Fastest)

| Shortcut | Action | Description |
|----------|--------|-------------|
| `Cmd+Shift+L` | Lint CGO packages remotely | Runs golangci-lint on vhost1 |
| `Cmd+Shift+B` | Build with CGO remotely | Tests `go build` on vhost1 |
| `Cmd+Shift+T` | Test CGO packages remotely | Runs `go test` on vhost1 |

**Example:**
1. Open `pkg/cephfs/client.go`
2. Make a change
3. Press `Cmd+Shift+L`
4. Errors appear in Problems panel (Cmd+Shift+M)

### Method 2: Command Palette

1. Press `Cmd+Shift+P`
2. Type "Run Task"
3. Select one of:
   - **Eos: Lint CGO Packages (Remote)**
   - **Eos: Build with CGO (Remote)**
   - **Eos: Go Vet CGO (Remote)**
   - **Eos: Test CGO Packages (Remote)**
   - **Eos: Full Pre-commit Check (Remote)**

### Method 3: Manual Script Execution

```bash
# Lint all CGO packages
./scripts/lint_cgo_remote.sh

# Lint specific package
./scripts/lint_cgo_remote.sh --package cephfs

# Watch mode (auto-lint on file changes)
./scripts/lint_cgo_remote.sh --watch

# Verbose output
./scripts/lint_cgo_remote.sh --verbose
```

### Method 4: Auto-lint on Save (Recommended)

Already configured in [settings.json](settings.json):

1. Edit any file in `pkg/cephfs/` or `pkg/kvm/`
2. Save the file (`Cmd+S`)
3. Script automatically runs on vhost1
4. Results appear in Problems panel

**Note:** Requires the "Run on Save" extension.

---

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ macOS (Development Machine)                                 │
│                                                              │
│  1. Edit pkg/cephfs/client.go                              │
│  2. Press Cmd+Shift+L                                       │
│  3. VS Code Task triggers                                   │
│     └─> ssh vhost1 "cd /opt/eos && lint CGO packages"     │
│                                                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ SSH
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ vhost1 (Linux Server)                                       │
│                                                              │
│  4. Pull latest code from GitHub (or rsync from macOS)     │
│  5. Run golangci-lint with CGO_ENABLED=1                   │
│  6. Parse errors into line-number format                    │
│  7. Return results to macOS                                 │
│                                                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ Results
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ macOS (VS Code Problems Panel)                              │
│                                                              │
│  ✗ pkg/cephfs/client.go:16:2                               │
│    shared redeclared in this block                          │
│                                                              │
│  ✗ pkg/cephfs/volumes.go:123:5                             │
│    undefined: CephContext                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Problem Matchers

VS Code uses **problem matchers** to parse error output and display it visually:

```json
{
  "owner": "go",
  "source": "golangci-lint",
  "pattern": {
    "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)\\s+\\((.*)\\)$",
    "file": 1,      // pkg/cephfs/client.go
    "line": 2,      // 16
    "column": 3,    // 2
    "severity": 4,  // error
    "message": 5,   // shared redeclared
    "code": 6       // typecheck
  }
}
```

This parses golangci-lint output:
```
pkg/cephfs/client.go:16:2: error: shared redeclared in this block (typecheck)
```

Into a clickable error in VS Code's Problems panel.

---

## Files

| File | Purpose |
|------|---------|
| [tasks.json](tasks.json) | VS Code task definitions for remote linting |
| [settings.json](settings.json) | Auto-lint on save configuration |
| [keybindings.json](keybindings.json) | Keyboard shortcuts for tasks |
| [../scripts/lint_cgo_remote.sh](../scripts/lint_cgo_remote.sh) | Shell script that does the actual remote linting |
| [../.golangci.yml](../.golangci.yml) | golangci-lint configuration with CGO support |
| [../Makefile](../Makefile) | Make targets for linting and building |

---

## Troubleshooting

### Problem: "Cannot connect to remote host: vhost1"

**Solution:**
```bash
# Test SSH connection
ssh vhost1 exit

# If it asks for a password, set up key authentication
ssh-copy-id vhost1

# Add to ~/.ssh/config for convenience:
cat >> ~/.ssh/config <<EOF
Host vhost1
  HostName vhost1.local  # Or IP address
  User henry
  IdentityFile ~/.ssh/id_ed25519
  ServerAliveInterval 60
EOF
```

### Problem: "golangci-lint not found on remote"

**Solution:**
```bash
# Install on vhost1
ssh vhost1
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0

# Or use the automated task
# Cmd+Shift+P -> Run Task -> "Eos: Install golangci-lint (Remote)"
```

### Problem: "Code not syncing to remote"

**Solution:**

The script tries two methods:
1. **rsync** (fast, efficient) - preferred
2. **git pull** (fallback) - requires committing changes

If using git pull method:
```bash
# On macOS - commit and push your changes first
git add .
git commit -m "WIP: Testing CGO changes"
git push
```

If using rsync method (recommended):
```bash
# Install rsync on macOS if not present
brew install rsync

# rsync will automatically sync your local uncommitted changes
```

### Problem: Errors not appearing in Problems panel

**Check:**
1. Open Problems panel: `Cmd+Shift+M`
2. Check Task output: View -> Output -> Select "Tasks - Eos: Lint CGO Packages"
3. Verify problem matcher is working:
   ```bash
   # Run manually to see raw output
   ssh vhost1 "cd /opt/eos && golangci-lint run ./pkg/cephfs/..."
   ```

### Problem: Too many false positives

**Solution:**

Edit [../.golangci.yml](../.golangci.yml) to disable specific linters:

```yaml
linters:
  disable:
    - gocritic  # Too noisy for your taste
    - revive    # Style linter
```

Or exclude specific paths:
```yaml
issues:
  exclude-rules:
    - path: pkg/cephfs/
      linters:
        - gosec
      text: "G304"  # File path from variable
```

---

## Advanced: Watch Mode

For continuous linting during active development:

```bash
# Terminal 1: Start watch mode
./scripts/lint_cgo_remote.sh --watch

# Terminal 2: Edit files normally
# Every time you save, linting runs automatically
```

**Watch mode:**
- Monitors `pkg/cephfs/` and `pkg/kvm/` for changes
- Debounces rapid changes (1-second delay)
- Syncs code to vhost1
- Runs full lint cycle (vet + golangci-lint + build)
- Displays results in terminal

---

## Integration with Pre-commit Hooks

To enforce linting before committing:

```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit <<'EOF'
#!/usr/bin/env bash
# Run CGO linting before commit
./scripts/lint_cgo_remote.sh
EOF

chmod +x .git/hooks/pre-commit
```

Now every commit will:
1. Sync code to vhost1
2. Run golangci-lint
3. Run go vet
4. Test build
5. Block commit if errors found

---

## CI/CD Integration

For GitHub Actions or GitLab CI:

```yaml
# .github/workflows/lint-cgo.yml
name: Lint CGO Packages

on: [push, pull_request]

jobs:
  lint-cgo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Ceph dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libcephfs-dev librados-dev

      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0

      - name: Lint CGO packages
        run: |
          make lint-cgo
```

---

## Performance Tips

### Speed up rsync
```bash
# Add to ~/.ssh/config
Host vhost1
  Compression yes
  ControlMaster auto
  ControlPath ~/.ssh/control-%r@%h:%p
  ControlPersist 10m
```

This enables SSH connection multiplexing, making repeated SSH commands much faster.

### Reduce linting scope

Lint only changed files:
```bash
# Get list of changed Go files
git diff --name-only | grep '\.go$' | grep -E '(cephfs|kvm)'

# Lint only those files
./scripts/lint_cgo_remote.sh --package cephfs
```

---

## Summary

| Action | Command | Keybinding |
|--------|---------|------------|
| **Quick lint** | `Cmd+Shift+L` | Fastest for spot-checking |
| **Build test** | `Cmd+Shift+B` | Verify compile-time errors |
| **Full check** | `make pre-commit-cgo` | Before committing |
| **Watch mode** | `./scripts/lint_cgo_remote.sh -w` | Active development |
| **Manual** | `./scripts/lint_cgo_remote.sh` | One-off checks |

**Recommended workflow:**
1. Edit files locally on macOS
2. Save → auto-lint triggers
3. Fix errors in Problems panel
4. Commit when all green
5. CI/CD validates on Linux

---

## Questions?

- **Where is the remote code?** `/opt/eos` on vhost1
- **How often does it sync?** Every lint run (rsync is fast)
- **Does it commit my changes?** No, only syncs locally
- **Can I use a different server?** Set `EOS_REMOTE_HOST=other-server`
- **What if vhost1 is offline?** Linting will fail gracefully with error message

---

**Related Documentation:**
- [Eos CLAUDE.md](../CLAUDE.md) - P0 rules for constants and architecture
- [golangci-lint config](../.golangci.yml) - Linter configuration
- [Makefile](../Makefile) - Build and lint targets
