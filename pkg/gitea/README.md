# pkg/gitea

*Last Updated: 2025-12-07*

SSH-based authentication and configuration for self-hosted Gitea instances.

## Overview

This package provides functionality to:
- Configure SSH access to self-hosted Gitea instances
- Generate and manage SSH key pairs for authentication
- Update `~/.ssh/config` for easy git operations
- Store instance configurations for multiple Gitea servers

## Usage

### Command Line

```bash
# Interactive setup (prompts for all values)
eos create gitea

# Specify all options via flags
eos create gitea --name vhost7 --host vhost7 --http-port 8167 --ssh-port 2222

# Include organization
eos create gitea --name prod-gitea --host git.example.com --org mycompany

# List configured instances
eos create gitea --list

# Test SSH connection
eos create gitea --test
```

### After Setup

1. Add the generated public key to Gitea:
   - Go to Gitea web UI -> Profile -> Settings -> SSH/GPG Keys
   - Add the contents of `~/.ssh/gitea/<instance>.pub`

2. Create your repository in Gitea

3. Add the remote to your local git repo:
   ```bash
   git remote add origin git@gitea-<instance>:<org>/<repo>.git
   git push -u origin main
   ```

## Configuration Storage

Configuration is stored in `~/.eos/gitea/config.yaml`:

```yaml
instances:
  - name: vhost7
    hostname: vhost7
    http_port: 8167
    ssh_port: 2222
    ssh_key_path: /home/user/.ssh/gitea/gitea-vhost7
    ssh_config_host: gitea-vhost7
    organization: cybermonkey
default_instance: vhost7
```

## SSH Config Entry

The package adds entries to `~/.ssh/config`:

```
# Gitea instance: vhost7
# Added by 'eos create gitea'
Host gitea-vhost7
    HostName vhost7
    Port 2222
    User git
    IdentityFile ~/.ssh/gitea/gitea-vhost7
    IdentitiesOnly yes
```

## Package Structure

- `types.go` - Configuration types and constants
- `config.go` - Configuration storage and retrieval
- `ssh.go` - SSH key generation and config management
- `git.go` - Git remote configuration
- `install.go` - Main setup orchestration
