# pkg/remotecode

Remote IDE development configuration for Eos.

## Purpose

This package configures SSH and firewall settings to enable seamless remote IDE development. It solves common issues encountered when using:

- **Windsurf** (Codeium's AI IDE)
- **Claude Code** (Anthropic's AI coding assistant)
- **VS Code Remote SSH**
- **Cursor**
- **JetBrains Gateway**

## Common Problems Solved

### "Too many logins" Error

IDEs open multiple SSH sessions per window (for terminal, language server, file operations, etc.). The default SSH `MaxSessions=10` is insufficient.

**Solution**: Increases `MaxSessions` to 20 (supports ~4 IDE windows with headroom).

### IDE Disconnections During Idle

By default, SSH has no keepalive mechanism. Long-running IDE sessions disconnect after periods of inactivity.

**Solution**: Enables `ClientAliveInterval=60` to send keepalives every minute.

### Connection Drops During Network Blips

Brief network interruptions cause immediate disconnection with default settings.

**Solution**: Sets `ClientAliveCountMax=3` to allow 3 minutes of network issues before disconnecting.

### Port Forwarding Disabled

Some hardened SSH configs disable TCP forwarding, breaking IDE debugging features.

**Solution**: Enables `AllowTcpForwarding=yes` for port forwarding and `AllowAgentForwarding=yes` for SSH key passthrough.

## Usage

```bash
# Basic setup (recommended)
sudo eos create code

# Specify user explicitly
sudo eos create code --user henry

# Preview changes without applying
sudo eos create code --dry-run

# Custom session limit for heavy IDE usage
sudo eos create code --max-sessions 30

# Skip firewall configuration
sudo eos create code --skip-firewall

# Allow SSH from additional networks
sudo eos create code --allowed-networks 203.0.113.0/24
```

## Files

- `types.go` - Configuration types and constants
- `ssh.go` - SSH configuration modification logic
- `firewall.go` - UFW firewall configuration
- `install.go` - Main installation orchestration
- `verify.go` - Post-installation verification

## Architecture

Follows Eos patterns:

1. **ASSESS** - Check prerequisites, read current SSH config
2. **INTERVENE** - Create backup, apply changes, configure firewall
3. **EVALUATE** - Verify config, restart SSH, display results

## Safety

- Creates timestamped backup before modifying SSH config
- Validates SSH config with `sshd -t` before restart
- Restores backup automatically if validation fails
- Ensures SSH port is allowed in firewall before enabling UFW
- Uses structured logging throughout

## SSH Settings Applied

| Setting | Default | Eos Value | Reason |
|---------|---------|-----------|--------|
| MaxSessions | 10 | 20 | IDE tools need multiple sessions |
| ClientAliveInterval | 0 | 60 | Prevents idle disconnection |
| ClientAliveCountMax | 3 | 3 | Tolerates brief network issues |
| AllowTcpForwarding | yes | yes | Required for IDE port forwarding |
| AllowAgentForwarding | yes | yes | Enables git operations with local keys |

## Firewall Rules

Allows SSH (port 22) from:

- `100.64.0.0/10` - Tailscale CGNAT range
- `192.168.0.0/16` - Common LAN (class C)
- `10.0.0.0/8` - Private network (class A)
- `172.16.0.0/12` - Docker/K8s networks (class B)
- Additional user-specified networks

## Troubleshooting

### Still getting "too many logins"

```bash
# Check current MaxSessions
sudo sshd -T | grep maxsessions

# Kill stale IDE server processes
pkill -u $(whoami) -f 'windsurf-server|code-server|vscode-server'

# Increase MaxSessions further
sudo eos create code --max-sessions 30
```

### IDE not connecting

```bash
# Check SSH is running
sudo systemctl status sshd

# Check SSH port is listening
ss -tlnp | grep 22

# Check firewall
sudo ufw status

# View SSH logs
sudo journalctl -u ssh -f
```

### Changes not taking effect

```bash
# Verify config was written
grep MaxSessions /etc/ssh/sshd_config

# Restart SSH manually
sudo systemctl restart sshd
```

## Related Commands

- `eos create dev-environment` - Full development environment with code-server
- `eos debug ssh` - SSH diagnostics and troubleshooting
