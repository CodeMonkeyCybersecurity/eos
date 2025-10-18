# Eos - Ubuntu Server Administration Made Simple

*Last Updated: 2025-01-19*

**Eos** is a powerful Go-based CLI tool that simplifies Ubuntu server administration through automation, orchestration, and security hardening. Built by Code Monkey Cybersecurity, Eos transforms complex server management tasks into simple commands.

## Overview

Eos provides a comprehensive suite of tools for:
- **Infrastructure Automation**: Deploy and manage services like Kubernetes, Docker, Nomad, and OpenStack
- **Security Hardening**: Implement fail2ban, LDAP, Vault secrets management, and security monitoring
- **Service Orchestration**: Manage web services, databases, reverse proxies, and monitoring systems
- **System Administration**: Handle backups, user management, and system maintenance

## Key Features

- **Verb-First Architecture**: Intuitive command structure (`eos create`, `eos read`, `eos update`)
- **Built-in Safety**: Assess → Intervene → Evaluate pattern ensures reliable operations
- **Interactive Prompts**: User-friendly prompts for missing configuration
- **Comprehensive Logging**: Structured logging with OpenTelemetry integration
- **Error Recovery**: Intelligent error handling with clear, actionable messages

## Quick Start

### Prerequisites
- Ubuntu 20.04+ (primary target)
- Go 1.21 or higher
- Root/sudo access for system operations

### Installation

#### Ubuntu/Debian
```bash
# Clone the repository
sudo -i
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

# Install Go if needed
apt update && apt install golang -y

# Build and install
go mod tidy
go build -o eos .
sudo cp eos /usr/local/bin/

# Or use the install script
./install.sh
```

#### RHEL/CentOS
```bash
sudo -i
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

yum update && yum install golang -y
go mod tidy
go build -o eos .
sudo cp eos /usr/local/bin/
```

#### macOS
```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew update && brew install go

# Clone and build
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
go mod tidy
go build -o eos .
sudo cp eos /usr/local/bin/
```

## Usage Examples

### Create Infrastructure
```bash
# Deploy Kubernetes cluster
eos create k3s --cluster-name=production

# Set up HashiCorp Vault
eos create vault --auto-unseal

# Install monitoring stack
eos create monitoring --prometheus --grafana

# Deploy reverse proxy
eos create hecate --domain=example.com
```

### Read System State
```bash
# Check service status
eos read status --service=nginx

# View system metrics
eos read metrics --format=json

# Inspect logs
eos read logs --service=docker --tail=100
```

### Update Configuration
```bash
# Manage users
eos update users --add-user=john --groups=sudo,docker

# Update system packages
eos update system --packages --security-only

# Rotate secrets
eos update vault rotate-secrets
```

### List Resources
```bash
# List all services
eos list services

# Show containers
eos list containers --all

# Display users
eos list users --system
```

## Available Commands

### Infrastructure & Services
- `eos create k3s` - Lightweight Kubernetes
- `eos create nomad` - HashiCorp Nomad orchestrator
- `eos create consul` - Service mesh and discovery
- `eos create vault` - Secrets management
- `eos create docker` - Container runtime
- `eos create openstack` - Private cloud platform

### Security & Monitoring
- `eos create fail2ban` - Intrusion prevention
- `eos create osquery` - System monitoring
- `eos create wazuh` - Security monitoring platform
- `eos create hecate` - Reverse proxy with security features
- `eos create ldap` - Directory services
- `eos create zabbix` - Infrastructure monitoring

### Development Tools
- `eos create ` - Configuration management
- `eos create terraform` - Infrastructure as Code
- `eos create ansible` - Automation platform
- `eos create gitlab` - Version control platform

### System Management
- `eos backup create` - System backups
- `eos self update` - Update Eos itself
- `eos self git commit` - Commit Eos changes

## Architecture

Eos follows a modular architecture:

```
cmd/                    # Command definitions (verb-first structure)
├── create/            # Creation commands
├── read/              # Read/inspection commands
├── update/            # Modification commands
├── delete/            # Deletion commands
├── list/              # Listing commands
└── self/              # Eos self-management

pkg/                    # Business logic packages
├── eos_cli/           # CLI utilities
├── eos_io/            # I/O and runtime context
├── eos_err/           # Error handling
└── [feature]/         # Feature-specific logic
```

## Development

### Testing
```bash
# Run all tests
go test -v ./pkg/...

# Check code quality
golangci-lint run

# Build verification
go build -o /tmp/eos-build ./cmd/
```

### Contributing
All code must follow the Assess → Intervene → Evaluate pattern and use structured logging. See [CLAUDE.md](./CLAUDE.md) for detailed development guidelines.

## Documentation

- **Knowledge Base**: [Athena Wiki](https://wiki.cybermonkey.net.au)
- **Architecture**: See [STACK.md](./STACK.md) for design principles
- **Development**: See [CLAUDE.md](./CLAUDE.md) for coding standards

## Support

- **Email**: main@cybermonkey.net.au
- **Website**: [cybermonkey.net.au](https://cybermonkey.net.au)
- **GitHub Issues**: [Report bugs or request features](https://github.com/CodeMonkeyCybersecurity/eos/issues)

## Social Media

- [Facebook](https://www.facebook.com/codemonkeycyber)
- [X/Twitter](https://x.com/codemonkeycyber)
- [LinkedIn](https://www.linkedin.com/company/codemonkeycyber)
- [YouTube](https://www.youtube.com/@CodeMonkeyCybersecurity)

```bash
#     ___         _       __  __          _
#    / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
#   | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
#    \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
#                  / __|  _| |__  ___ _ _         |__/
#                 | (_| || | '_ \/ -_) '_|
#                  \___\__, |_.__/\___|_|
#                      |__/
```

---

© 2025 [Code Monkey Cybersecurity](https://cybermonkey.net.au/). ABN: 77 177 673 061. All rights reserved.