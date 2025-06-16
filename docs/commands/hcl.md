# HCL Command Documentation

## Overview

The `eos create hcl` command installs HashiCorp tools using their official APT repository. This ensures you get the latest stable versions with proper package management and security verification.

## Supported Tools

- **terraform** - Infrastructure as Code tool
- **vault** - Secrets management
- **consul** - Service discovery and configuration
- **nomad** - Workload orchestration
- **packer** - Machine image builder (includes QEMU plugin)

## Usage

### Install Individual Tools

```bash
# Install specific tools
eos create hcl terraform
eos create hcl vault
eos create hcl consul
eos create hcl nomad
eos create hcl packer

# Install all tools at once
eos create hcl all
```

### Direct Commands

You can also use direct commands for each tool:

```bash
eos create terraform
eos create vault
eos create consul
eos create nomad
eos create packer
```

## Special Features

### Packer QEMU Plugin

When installing Packer, the system automatically installs the Packer QEMU plugin (`github.com/hashicorp/qemu`). This plugin is essential for:

- KVM/QEMU virtualization workflows
- Cloud-init VM provisioning
- Building machine images for virtualization platforms

### Security Features

- **GPG Verification**: Downloads and verifies HashiCorp's official GPG key
- **Official Repository**: Uses HashiCorp's official APT repository
- **Fingerprint Validation**: Verifies GPG key fingerprint contains "HashiCorp Security"

## Installation Process

1. **Prerequisites**: Installs required packages (`gnupg`, `software-properties-common`, `curl`)
2. **GPG Key**: Downloads and installs HashiCorp's GPG key
3. **Repository**: Adds HashiCorp APT repository to system sources
4. **Package Installation**: Installs the requested tool(s)
5. **Verification**: Verifies installation by running `<tool> -help`
6. **Plugin Installation**: For Packer, installs QEMU plugin

## Error Handling

- Individual tool failures don't stop batch installations
- Plugin installation failures are logged as warnings
- GPG verification failures stop the installation process
- Detailed error messages help with troubleshooting

## Examples

```bash
# Install Terraform for infrastructure management
eos create hcl terraform

# Install Packer with QEMU plugin for VM image building
eos create hcl packer

# Install all HashiCorp tools for complete workflow
eos create hcl all
```

## Requirements

- Ubuntu/Debian-based system
- Internet connection for downloading packages
- Sudo privileges for system package installation