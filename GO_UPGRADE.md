# Upgrading Go to 1.25+

**Last Updated**: 2025-01-28

This document provides instructions for manually upgrading Go to version 1.25+ to run Eos tests and build the project.

---

## Why Go 1.25+ is Required

Several Eos dependencies require Go 1.25 or later:
- `github.com/hashicorp/consul/api@v1.33.0` - requires Go 1.25.3
- `github.com/go-json-experiment/json@v0.0.0-20251027170946-4849db3c2f7e` - requires Go 1.25
- Other transitive dependencies

**Current System**: Go 1.24.7
**Required**: Go 1.25.0 or later

---

## Option 1: Manual Installation (Recommended)

### Step 1: Download Go 1.25.0

Download from official Go website (if direct download is available):

```bash
# Download Go 1.25.0 for Linux (replace with your platform)
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz -O /tmp/go1.25.0.linux-amd64.tar.gz

# Or use curl
curl -L https://go.dev/dl/go1.25.0.linux-amd64.tar.gz -o /tmp/go1.25.0.linux-amd64.tar.gz
```

**Alternative Download Locations** (if primary is blocked):
- Go mirrors: https://golang.google.cn/dl/ (China mirror)
- GitHub releases: https://github.com/golang/go/releases

### Step 2: Verify Download (Optional but Recommended)

```bash
# Download checksum
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz.sha256 -O /tmp/go1.25.0.sha256

# Verify checksum
cd /tmp
sha256sum -c go1.25.0.sha256
# Should output: go1.25.0.linux-amd64.tar.gz: OK
```

### Step 3: Install Go 1.25.0

```bash
# Remove old Go installation (if you want to replace)
sudo rm -rf /usr/local/go

# Extract new Go version
sudo tar -C /usr/local -xzf /tmp/go1.25.0.linux-amd64.tar.gz

# Verify installation
/usr/local/go/bin/go version
# Should output: go version go1.25.0 linux/amd64
```

### Step 4: Update PATH (if needed)

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH=/usr/local/go/bin:$PATH

# Reload shell configuration
source ~/.bashrc

# Verify go is in PATH
which go
go version
```

---

## Option 2: Using Go Version Manager (gvm)

If you have `gvm` (Go Version Manager) installed:

```bash
# Install Go 1.25.0
gvm install go1.25.0

# Use Go 1.25.0
gvm use go1.25.0 --default

# Verify
go version
```

---

## Option 3: Using asdf Version Manager

If you have `asdf` installed:

```bash
# Add Go plugin
asdf plugin add golang

# Install Go 1.25.0
asdf install golang 1.25.0

# Set global version
asdf global golang 1.25.0

# Verify
go version
```

---

## Option 4: Download from Alternative Source

If official Go website is blocked, try these alternatives:

### Using a Proxy or VPN

```bash
# Set HTTP proxy (if available)
export http_proxy=http://your-proxy:port
export https_proxy=http://your-proxy:port

# Then download as normal
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
```

### Download via Git (if GitHub is accessible)

```bash
# Clone Go source
git clone https://github.com/golang/go.git /tmp/go-source
cd /tmp/go-source
git checkout go1.25.0

# Build from source (requires Go 1.20+ already installed)
cd src
./all.bash

# Install
sudo cp -r /tmp/go-source /usr/local/go-1.25.0
sudo ln -sf /usr/local/go-1.25.0 /usr/local/go
```

---

## Option 5: Package Manager (if available)

### Ubuntu/Debian with PPA

```bash
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-1.25

# Update alternatives
sudo update-alternatives --install /usr/bin/go go /usr/lib/go-1.25/bin/go 1
```

### Homebrew (macOS/Linux)

```bash
brew install go@1.25
```

### DNF/YUM (Fedora/RHEL)

```bash
# May not have Go 1.25 yet, check availability
sudo dnf install golang
```

---

## Verification Steps

After installation, verify everything works:

```bash
# Check Go version
go version
# Should show: go version go1.25.0 (or later) linux/amd64

# Check Eos can build
cd /home/user/eos
go build -o /tmp/eos-build ./cmd/

# Run tests
go test -v ./pkg/vault

# Run integration tests (if Vault cluster available)
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN_TEST="your_test_token"
export EOS_TEST_ENVIRONMENT="true"
go test -v -tags=integration ./pkg/vault
```

---

## Troubleshooting

### Issue: "go: downloading go1.25.3 failed"

**Problem**: Go is trying to auto-download toolchain but network is blocked

**Solution**:
```bash
# Disable automatic toolchain download
export GOTOOLCHAIN=local

# Or set in go.env
go env -w GOTOOLCHAIN=local

# Then use your manually installed Go
go version
```

### Issue: "permission denied" when installing

**Problem**: Need sudo/root privileges

**Solution**:
```bash
# Install to user directory instead
mkdir -p ~/go-1.25.0
tar -C ~/go-1.25.0 --strip-components=1 -xzf go1.25.0.linux-amd64.tar.gz

# Update PATH
export PATH=~/go-1.25.0/bin:$PATH

# Make permanent
echo 'export PATH=~/go-1.25.0/bin:$PATH' >> ~/.bashrc
```

### Issue: Multiple Go versions conflict

**Problem**: System has multiple Go installations

**Solution**:
```bash
# Find all Go installations
which -a go

# Use specific version
/usr/local/go/bin/go version

# Or update PATH to prefer new version
export PATH=/usr/local/go/bin:$PATH
```

### Issue: Dependencies still fail with "requires go >= 1.25"

**Problem**: Old go.sum or module cache

**Solution**:
```bash
# Clean module cache
go clean -modcache

# Remove go.sum and regenerate
rm go.sum
go mod tidy

# Verify modules
go mod verify
```

---

## Network-Restricted Environment Workarounds

If you're in a highly restricted network environment:

### Method 1: Download on Different Machine

1. On machine with internet access:
   ```bash
   wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
   ```

2. Transfer file to restricted machine:
   ```bash
   # Via USB drive, SCP, or internal file sharing
   scp go1.25.0.linux-amd64.tar.gz user@restricted-machine:/tmp/
   ```

3. Install on restricted machine:
   ```bash
   sudo tar -C /usr/local -xzf /tmp/go1.25.0.linux-amd64.tar.gz
   ```

### Method 2: Use Internal Mirror

If your organization has an internal mirror:

```bash
# Download from internal mirror
wget http://internal-mirror/go/go1.25.0.linux-amd64.tar.gz

# Or configure Go proxy
go env -w GOPROXY=http://internal-goproxy:8080
```

### Method 3: Pre-vendored Dependencies

```bash
# On machine with internet, vendor dependencies
go mod vendor

# Commit vendor/ directory
git add vendor/
git commit -m "vendor: add dependencies for Go 1.25"

# On restricted machine, use vendored deps
go build -mod=vendor
```

---

## Current Status

**Environment**: Go 1.24.7 installed
**Required**: Go 1.25.0+
**Blocking**: Network restrictions prevent automatic download

**Recommendation**: Follow **Option 1 (Manual Installation)** or **Method 1 (Download on Different Machine)** for network-restricted environments.

---

## After Upgrading

Once Go 1.25+ is installed:

```bash
# Navigate to Eos directory
cd /home/user/eos

# Update dependencies
go mod tidy

# Build project
go build -o /tmp/eos-build ./cmd/

# Run tests
go test -v ./pkg/...

# Run integration tests
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN_TEST="your_token"
export EOS_TEST_ENVIRONMENT="true"
go test -v -tags=integration ./pkg/vault
```

---

## Additional Resources

- **Official Go Downloads**: https://go.dev/dl/
- **Go Installation Guide**: https://go.dev/doc/install
- **Go Release Notes**: https://go.dev/doc/devel/release
- **Eos Testing Guide**: [TESTING.md](TESTING.md)

---

## Support

If you encounter issues not covered here:

1. Check Go installation: `go version`
2. Check environment: `go env`
3. Check module status: `go mod verify`
4. Check network: `curl -I https://go.dev`
5. See [TESTING.md](TESTING.md) for test-specific issues

---

*Code Monkey Cybersecurity - "Cybersecurity. With humans."*
