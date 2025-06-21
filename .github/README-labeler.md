# GitHub Labels and Auto-Labeling

This directory contains configuration for automatic pull request labeling based on changed files.

## Current Setup

- **Active**: `label-simple.yml` - Shell-based labeler that works without label creation permissions
- **Disabled**: `label.yml` - Actions-based labeler (requires labels to exist first)
- **Configuration**: `labeler.yml` - Label mapping rules

## Quick Setup

### Option 1: Use Simple Labeler (Recommended)
The `label-simple.yml` workflow is already active and will:
- Automatically label PRs based on changed files
- Work even if repository labels don't exist
- Show warnings for missing labels but won't fail

### Option 2: Full Labeler Setup
1. Create repository labels first:
   ```bash
   ./scripts/setup-github-labels.sh
   ```

2. Enable the full labeler:
   - Edit `.github/workflows/label.yml`
   - Uncomment the `pull_request` trigger
   - Disable `label-simple.yml` if desired

## Label Categories

Based on `.github/labeler.yml`, PRs are automatically labeled for:

### Package Changes
- `pkg-vault` - HashiCorp Vault integration
- `pkg-crypto` - Cryptographic functions  
- `pkg-container` - Docker/container management
- `pkg-hecate` - Hecate reverse proxy/mail server
- `pkg-delphi` - Delphi monitoring platform
- `pkg-ldap` - LDAP directory services
- `pkg-other` - Other package changes

### Infrastructure
- `cli` - CLI commands and main interface
- `ansible` - Ansible playbooks
- `scripts` - Shell scripts and utilities
- `ci` - GitHub Actions workflows
- `dependencies` - Go modules, Dockerfile changes

### Documentation
- `documentation` - README, docs, markdown files
- `policies` - OPA/CUE policy definitions
- `sql` - Database schemas

## Troubleshooting

### Labels not being applied
1. Check workflow runs in GitHub Actions
2. Ensure PR has file changes that match label rules
3. For full labeler: verify labels exist in repository

### Permission errors
1. Use simple labeler (already configured)
2. Or create labels first with setup script
3. Ensure GitHub token has appropriate permissions

### Adding new labels
1. Update `.github/labeler.yml` with new file patterns
2. Update `scripts/setup-github-labels.sh` with new labels
3. Update `label-simple.yml` logic if using simple labeler

## Manual Label Management

Create all labels at once:
```bash
./scripts/setup-github-labels.sh [owner/repo]
```

The script creates labels with:
- Descriptive names matching file patterns
- Appropriate colors and descriptions
- Emoji prefixes for visual identification