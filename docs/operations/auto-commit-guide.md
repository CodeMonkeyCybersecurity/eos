# EOS Auto-Commit Guide

*Last Updated: 2025-01-14*

## Overview

The EOS auto-commit feature provides intelligent, safe automation for git commits. It addresses the common need to quickly commit changes without crafting custom commit messages each time, while maintaining code quality and security.

## Features

### 🛡️ **Safety First**
- **Secret Detection**: Scans for API keys, passwords, and private keys
- **File Size Checks**: Prevents committing large files (>50MB by default)
- **Artifact Detection**: Warns about build artifacts and temporary files
- **Branch Protection**: Extra confirmation for main/master branches
- **Conflict Detection**: Prevents commits when merge conflicts exist

### 🧠 **Smart Commit Messages**
- **Context-Aware**: Analyzes file changes to generate meaningful messages
- **Package Detection**: Identifies affected Go packages
- **Change Classification**: Distinguishes between tests, docs, config, and code changes
- **Statistics**: Includes file counts and line changes
- **Consistent Format**: Follows project conventions with automatic footers

### ⚙️ **Flexible Configuration**
- **Multiple Interfaces**: Native Go command, shell script, and configuration files
- **Customizable Patterns**: Configure secret detection and exclusion rules
- **Behavior Controls**: Auto-push, confirmations, and verification options
- **Template System**: Custom message templates for different change types

## Usage Methods

### 1. **Native EOS Command** (Recommended)

```bash
# Basic auto-commit with smart message generation
eos self git commit

# Skip safety checks and confirmation
eos self git commit --force

# Use custom message
eos self git commit -m "Custom commit message"

# Auto-push after commit
eos self git commit --push

# Show what would be committed without actually committing
eos self git commit --dry-run

# Skip pre-commit hooks (dangerous!)
eos self git commit --no-verify
```

### 2. **Shell Script** (Simple Alternative)

```bash
# Basic usage
./scripts/auto-commit.sh

# With custom message
./scripts/auto-commit.sh "Custom commit message"

# Environment variables
FORCE=true ./scripts/auto-commit.sh          # Skip confirmations
PUSH=true ./scripts/auto-commit.sh           # Auto-push
DRY_RUN=true ./scripts/auto-commit.sh        # Dry run
```

### 3. **Configuration File**

Customize behavior by editing `/opt/eos/assets/config/auto-commit.yaml`:

```yaml
defaults:
  auto_confirm: true    # Skip confirmation prompts
  auto_push: true      # Auto-push after commit
  show_diff: true      # Show diff before committing

safety:
  max_file_size: 100   # Increase file size limit to 100MB
  
message_generation:
  smart_messages: true # Enable intelligent message generation
  use_emoji: true     # Include emoji in messages
```

## Safety Features Explained

### **Secret Detection**
The system scans for common patterns:
- Password fields: `password = "secret123"`
- API keys: `api_key = "abc123"`
- Private keys: `-----BEGIN PRIVATE KEY-----`
- Database URLs with credentials
- AWS/GitHub tokens

### **File Size Protection**
- Default limit: 50MB per file
- Configurable in `auto-commit.yaml`
- Prevents accidental commits of large binaries

### **Artifact Detection**
Warns about common build artifacts:
- Log files (*.log)
- Temporary files (*.tmp, *.swp)
- Binary files (*.exe, *.dll)
- Dependencies (node_modules/, vendor/)

### **Branch Protection**
- Warns when committing to main/master/production branches
- Requires explicit confirmation
- Can be overridden with `--force`

## Smart Message Generation

### **Analysis Process**
1. **File Classification**: Categorizes changes by type and location
2. **Package Detection**: Identifies affected Go packages
3. **Change Quantification**: Counts lines added/removed
4. **Pattern Recognition**: Detects tests, docs, config changes
5. **Message Construction**: Builds descriptive commit message

### **Message Examples**

| Change Type | Generated Message |
|-------------|-------------------|
| New tests | `Add tests for security package` |
| Documentation | `Update documentation for backup package` |
| Configuration | `Configure logging and monitoring` |
| Mixed changes | `Update multiple packages (5 files, +123/-45 lines)` |
| New files | `Add new authentication module` |

### **Message Format**
```
<Primary Action> <Subject>

<Optional Details>
- Modified X file(s)
- +additions/-deletions lines
- Package-specific notes

 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

## Common Workflows

### **Daily Development**
```bash
# Quick commit with smart message
eos self git commit

# Review and push
eos self git commit --push
```

### **Feature Development**
```bash
# Commit specific changes with custom message
git add specific/files
eos self git commit -m "Implement user authentication"

# Auto-commit all changes
eos self git commit --force --push
```

### **Safe Commits**
```bash
# Review before committing
eos self git commit --dry-run
git diff --stat
eos self git commit
```

## Troubleshooting

### **Common Issues**

1. **"Not in EOS project root"**
   - Solution: Run from `/opt/eos` directory
   - Check: `pwd` should show EOS project root

2. **"Potential secrets detected"**
   - Review flagged files for sensitive data
   - Use `--force` only if false positive
   - Update `.gitignore` for sensitive files

3. **"Large files detected"**
   - Check file sizes with `du -sh suspicious_file`
   - Use Git LFS for legitimate large files
   - Clean up unnecessary large files

4. **Permission denied**
   - Ensure git is configured: `git config user.name` and `git config user.email`
   - Check repository permissions

### **Override Safety Checks**
```bash
# Skip all safety checks (use cautiously)
eos self git commit --force --no-verify

# Custom exclusions
echo "large_file.bin" >> .gitignore
eos self git commit
```

## Configuration Reference

### **Complete Configuration File**
```yaml
# /opt/eos/assets/config/auto-commit.yaml

safety:
  scan_secrets: true
  max_file_size: 50
  check_artifacts: true
  protected_branches: [main, master, production]
  exclude_patterns: ["*.log", "*.tmp", "node_modules/"]

secret_patterns:
  - '(?i)(password|passwd|pwd)\s*[:=]\s*[''\"]\w+[''\""]'
  # ... more patterns

message_generation:
  smart_messages: true
  include_stats: true
  include_packages: true
  templates:
    test_changes: "Add/update tests for {packages}"
    doc_changes: "Update documentation for {packages}"

defaults:
  auto_confirm: false
  auto_push: false
  skip_verify: false
  show_diff: true

integration:
  enable_hooks: true
  pre_commit_commands: ["go fmt ./...", "go vet ./..."]

preferences:
  message_style: "conventional"
  max_message_length: 50
  use_emoji: true
```

## Best Practices

### **When to Use Auto-Commit**
**Good for:**
- Daily development commits
- Work-in-progress saves
- Small bug fixes
- Documentation updates
- Configuration changes

❌ **Avoid for:**
- Release commits (use manual messages)
- Major feature completions
- Merge commits
- Commits that need detailed explanations

### **Security Best Practices**
1. **Never use `--force` without reviewing changes**
2. **Keep secrets in environment variables or secure stores**
3. **Use `.gitignore` for sensitive files**
4. **Regularly audit commit history for leaked secrets**
5. **Use `--dry-run` when uncertain**

### **Workflow Integration**
```bash
# Development cycle
eos self git commit --dry-run  # Review
eos self git commit            # Commit
git push                       # Push manually

# CI/CD integration
eos self git commit --force --push  # Automated commits
```

## Advanced Usage

### **Custom Templates**
Edit `auto-commit.yaml` to customize message templates:
```yaml
message_generation:
  templates:
    test_changes: "🧪 Test updates for {packages}"
    doc_changes: "📚 Documentation improvements"
    config_changes: "⚙️ Configuration updates"
    security_fix: "🔒 Security improvements"
```

### **Git Hooks Integration**
```bash
# Pre-commit hook example
#!/bin/bash
eos self git commit --dry-run
if [ $? -ne 0 ]; then
    echo "Auto-commit safety checks failed"
    exit 1
fi
```

### **Batch Operations**
```bash
# Commit multiple feature branches
for branch in feature/*; do
    git checkout "$branch"
    eos self git commit --force
done
```

## Support and Feedback

- **Issues**: Report bugs and feature requests at [GitHub Issues](https://github.com/CodeMonkeyCybersecurity/eos/issues)
- **Documentation**: Latest docs at [EOS Wiki](https://wiki.cybermonkey.net.au)
- **Contact**: main@cybermonkey.net.au

---

*This feature is designed to enhance productivity while maintaining code quality and security. Use responsibly and always review important commits manually.*