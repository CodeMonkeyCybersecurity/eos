# Installation

Use this guide to install Eos on Ubuntu and align with the preferred infrastructure stack (Vault, Consul, Nomad, Ceph, K3s, KVM).

## Requirements
- Ubuntu 24.04+ (also tested on 22.04)
- Root or sudo privileges
- Git
- Go 1.25+ (for local builds; not required when using the install script)

## Install from source
```bash
sudo -i
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
./install.sh
```

The installer builds the binary, installs it to `/usr/local/bin/eos`, and prepares runtime directories such as `/etc/eos` and `/var/log/eos`.

## Verify
```bash
eos --help
eos list services
```

## Upgrades
- Pull latest changes and rerun `./install.sh`.
- Re-run `eos --help` to confirm the binary version and rebuilt command list.

## Notes for production
- Ensure outbound network access for package installs during the first run.
- Map hosts to roles (bastion, control plane, storage, workload) before running create/update commands.
- Record deviations from the default hardening profiles in an ADR for traceability.
