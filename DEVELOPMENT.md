# Eos Development Guide

*Last Updated: 2025-11-07*

Quick start guide for developers contributing to Eos - A Go-based CLI for Ubuntu server administration.

---

## 🚀 Quick Setup (5 Minutes)

### 1. Clone and Install Hooks

```bash
# Clone repository
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

# Install git hooks (REQUIRED)
./scripts/install-git-hooks.sh
```

This installs:
- **Pre-commit hook**: Fast validation (2-5 seconds)
- **Commit-msg hook**: Enforces Conventional Commits
- **Pre-push hook**: Comprehensive validation before pushing

### 2. Install Required Tools

```bash
# golangci-lint (P0 - REQUIRED by CLAUDE.md)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# gitleaks (RECOMMENDED for secret scanning)
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_*.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_*

# Verify installations
golangci-lint version
gitleaks version
```

### 3. Verify Setup

```bash
# Build the project
go build -o /tmp/eos-build ./cmd/

# Run linter
golangci-lint run

# Run tests
go test -v ./pkg/...

# All passing? You're ready to develop! ✅
```

---

## 📋 Development Workflow

### Standard Workflow

```
1. Create feature branch
   git checkout -b feat/your-feature

2. Make changes, commit frequently
   git add .
   git commit -m "feat(scope): description"
   # Pre-commit hook validates (2-5 sec)
   # Commit-msg hook validates format

3. Push to remote
   git push origin feat/your-feature
   # Pre-push hook validates (1-2 min)

4. Create pull request
   # CI/CD runs full validation
```

### Commit Message Format

**We use [Conventional Commits](https://www.conventionalcommits.org/):**

```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

**Valid types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style (formatting, semicolons)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding/updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Other changes (release, tooling)
- `revert`: Revert previous commit

**Optional scopes:**
- `vault`, `consul`, `nomad`, `bionicgpt`, `wazuh`, `claude`, etc.

**Examples:**
```bash
git commit -m "feat(vault): add automatic token rotation"
git commit -m "fix: resolve build errors in pkg/bionicgpt"
git commit -m "docs(claude): update shift-left strategy"
git commit -m "refactor(nomad)!: change job API (BREAKING)"
```

**Breaking changes:** Add `!` after type/scope

---

## 🔍 Validation Layers

Your code goes through **4 defensive layers**:

### Layer 1: AI Pre-Commit Check (If Using AI)

AI assistants must run before marking complete:
```bash
go build -o /tmp/eos-build ./cmd/
golangci-lint run
go test -v ./pkg/...
```

### Layer 2: Git Pre-Commit Hook (Automatic)

Runs on `git commit` (2-5 seconds):
- ✅ Full project build
- ✅ `go vet` on staged files
- ✅ `gofmt` on staged files
- ✅ `golangci-lint` on staged files
- ✅ `gitleaks` secret scanning
- ✅ Tests on affected packages

**Bypass** (not recommended): `git commit --no-verify`

### Layer 2.5: Git Pre-Push Hook (Automatic)

Runs on `git push` (1-2 minutes):
- ✅ Full test suite with race detection
- ✅ Multi-platform builds (linux/amd64, linux/arm64)
- ✅ Coverage analysis (warns below 70%)
- ✅ Full repository linting

**Bypass** (not recommended): `git push --no-verify`

### Layer 3: CI/CD Pipeline (Automatic)

Runs on every PR and push to main:
- ✅ 16 GitHub Actions workflows
- ✅ Quality, testing, security workflows
- ✅ Cannot be bypassed

---

## 🛠️ Common Tasks

### Running Tests

```bash
# Quick tests (pre-commit)
go test -short ./pkg/...

# Full test suite
go test -v ./pkg/...

# With race detection
go test -v -race ./pkg/...

# Specific package
go test -v ./pkg/vault/...

# With coverage
go test -cover -coverprofile=coverage.out ./pkg/...
go tool cover -html=coverage.out
```

### Running Linters

```bash
# golangci-lint (comprehensive - 60+ linters)
golangci-lint run

# On specific files
golangci-lint run pkg/vault/client.go

# With verbose output
golangci-lint run -v

# go vet (standard)
go vet ./...

# gofmt (formatting)
gofmt -l .
gofmt -w .  # Fix formatting
```

### Secret Scanning

```bash
# Scan for secrets (gitleaks)
gitleaks detect --config=.gitleaks.toml

# Scan specific files
gitleaks protect --staged

# Scan entire repository
gitleaks detect --no-git
```

### Building

```bash
# Development build
go build -o /tmp/eos ./cmd/

# Multi-platform builds
GOOS=linux GOARCH=amd64 go build -o eos-linux-amd64 ./cmd/
GOOS=linux GOARCH=arm64 go build -o eos-linux-arm64 ./cmd/
```

---

## 📖 Code Standards

### Architecture

**CRITICAL RULE**: Business logic in `pkg/`, orchestration ONLY in `cmd/`

```go
// ✅ GOOD: cmd/create/vault.go (orchestration)
func runVaultCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
    config := parseFlags(cmd)
    return vault.Create(rc, config)  // Delegate to pkg/
}

// ❌ BAD: Business logic in cmd/
func runVaultCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
    // Don't put file operations, loops, complex logic here!
}
```

### Logging

**NEVER use `fmt.Println`** - Always use structured logging:

```go
logger := otelzap.Ctx(rc.Ctx)
logger.Info("Operation complete", zap.String("service", "vault"))
logger.Warn("Deprecated feature", zap.String("feature", "old-api"))
logger.Error("Operation failed", zap.Error(err))
```

### Error Handling

```go
// ✅ GOOD: Context + remediation
if err != nil {
    return fmt.Errorf("failed to initialize Vault: %w\n"+
        "Ensure Vault is running: systemctl status vault", err)
}

// ❌ BAD: Generic error
if err != nil {
    return fmt.Errorf("error: %w", err)
}
```

### Constants (P0 - CRITICAL)

**NEVER hardcode values:**

```go
// ❌ BAD
os.MkdirAll("/etc/vault.d", 0755)

// ✅ GOOD
os.MkdirAll(vault.VaultConfigDir, vault.VaultDirPerm)
```

Define constants in:
- `pkg/[service]/constants.go` (service-specific)
- `pkg/shared/ports.go` (port numbers)
- `pkg/shared/paths.go` (common paths)

---

## 🐛 Troubleshooting

### Pre-Commit Hook Slow

**Symptom**: Hook takes >10 seconds

**Solution**: Hook only checks staged files. If slow:
1. Check network connectivity (Go may download toolchain)
2. Verify golangci-lint is installed locally
3. Run `golangci-lint cache clean`

### Commit Message Rejected

**Symptom**: `✗ Commit message validation FAILED`

**Solution**: Use Conventional Commits format:
```bash
# Wrong
git commit -m "updated vault client"

# Right
git commit -m "refactor(vault): update client API"
```

### Secret Detected by gitleaks

**Symptom**: `✗ Potential secrets detected!`

**Solution**:
1. Remove the secret from staged files
2. Use environment variables or Vault instead
3. Update `.gitleaks.toml` if false positive

### golangci-lint Errors

**Symptom**: Linter reports issues

**Solution**:
1. Read the error message carefully
2. Fix the issue (don't bypass)
3. If false positive, add to `.golangci.yml` exclusions
4. Reference: https://golangci-lint.run/usage/linters/

---

## 📚 Additional Resources

- **Project Patterns**: See [CLAUDE.md](./CLAUDE.md) for detailed patterns
- **Roadmap**: See [ROADMAP.md](./ROADMAP.md) for planned features
- **Conventional Commits**: https://www.conventionalcommits.org/
- **golangci-lint**: https://golangci-lint.run/
- **gitleaks**: https://github.com/gitleaks/gitleaks

---

## 🎯 Quick Reference

```bash
# Setup
./scripts/install-git-hooks.sh

# Development
go build -o /tmp/eos ./cmd/
go test -v ./pkg/...
golangci-lint run

# Pre-commit (automatic)
git commit -m "feat: description"

# Pre-push (automatic)
git push origin branch-name

# Bypass (not recommended)
git commit --no-verify
git push --no-verify
```

---

## 🤝 Getting Help

- Check [CLAUDE.md](./CLAUDE.md) for development standards
- Review existing code patterns in `pkg/`
- Ask in team chat or create GitHub issue
- Reference: https://docs.claude.com/en/docs/claude-code/

---

**Philosophy**: "Technology serves humans, not the other way around" - Code Monkey Cybersecurity

*Cybersecurity. With humans.*
