# Wazuh Version Management

> ** Documentation has been moved inline with the code for better maintainability.**
> 
> The comprehensive documentation for the Wazuh Version Management system is now embedded directly in the Go source files where the functionality is implemented. This ensures the documentation stays current with code changes and is immediately available to developers.

## Quick Reference

For detailed documentation, see the inline comments in these files:

- **Core System**: `pkg/wazuh_mssp/version/manager.go` - Architecture, caching, GitHub API integration
- **CLI Commands**: 
  - `cmd/read/wazuh_version.go` - View version information and check for updates
  - `cmd/update/wazuh_version.go` - Update configuration and perform version updates
  - `cmd/create/wazuh_version_config.go` - Create initial configuration with templates
- **Integration**: `pkg/wazuh_mssp/install.go` - How version management integrates with Wazuh deployments

## Quick Start

```bash
# Create configuration from template
eos create wazuh-version-config --template production

# Set current version
eos update wazuh-version --current 4.13.0

# Check for updates
eos read wazuh-version --check-update
```

## Templates Available

- **production**: Conservative (manual updates, approval required)
- **staging**: Moderate (patch auto-updates, maintenance windows)  
- **development**: Aggressive (latest versions, auto-updates)

## Command Examples

```bash
# View current status
eos read wazuh-version

# Update to latest (respects policy)
eos update wazuh-version --latest

# Force update ignoring policy
eos update wazuh-version --latest --force
```

---

> ** For comprehensive documentation, examples, troubleshooting, and advanced configuration options, see the inline documentation in the source files listed above.**
