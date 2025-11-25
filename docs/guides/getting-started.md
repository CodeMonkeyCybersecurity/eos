# Getting Started

This guide gives you the quickest path to a working Eos install and your first commands.

## Prerequisites
- Ubuntu 24.04+ (tested on 22.04/24.04)
- Root/sudo access
- Git and Go 1.25+

## Install Eos
1. Follow the detailed steps in [installation.md](installation.md) or run:
   ```bash
   sudo -i
   cd /opt
   git clone https://github.com/CodeMonkeyCybersecurity/eos.git
   cd eos
   ./install.sh
   ```
2. Verify the CLI is available:
   ```bash
   eos --help
   ```

## First commands
```bash
# Discover available services
eos list services

# Provision the HashiCorp control plane (aligns with the preferred infrastructure outline)
eos create vault
eos create consul
eos create nomad

# Run diagnostics when testing
eos debug vault
```

## Next steps
- Learn the CLI layout in [architecture/command-structure.md](../architecture/command-structure.md).
- Review common tasks in [common-workflows.md](common-workflows.md).
- Capture open questions as ADRs using the [template](../adr/ADR-0001-template.md).
