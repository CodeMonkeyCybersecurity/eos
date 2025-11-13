# Ubuntu Security Hardening Package

*Last Updated: 2025-01-14*

This package provides comprehensive security hardening for Ubuntu systems through the `eos secure ubuntu` command.

## Features

### 1. **System Auditing (auditd)**
- Monitors unauthorized file access attempts
- Tracks sudo usage and privilege escalation
- Monitors changes to critical system files (/etc/passwd, /etc/shadow, etc.)
- Tracks SSH configuration changes
- Monitors kernel module loading
- Tracks cron job modifications

### 2. **OS Instrumentation (osquery)**
- SQL-based OS monitoring and analysis
- Tracks system information, open sockets, logged-in users
- Monitors crontab changes and kernel modules
- Configurable query scheduling for continuous monitoring

### 3. **File Integrity Monitoring (AIDE)**
- Advanced Intrusion Detection Environment
- Baseline creation for system files
- Daily integrity checks via cron
- Email reports for detected changes

### 4. **Security Auditing (Lynis)**
- Comprehensive security auditing tool
- System hardening suggestions
- Compliance checking capabilities
- Regular security assessments

### 5. **Service Management (needrestart)**
- Automatic detection of services requiring restart
- Configured for automatic restart mode
- Ensures security updates are fully applied

### 6. **Brute Force Protection (fail2ban)**
- SSH brute force protection
- DDoS protection for SSH
- Configurable ban times and retry limits
- Extensible for other services

### 7. **Automatic Security Updates**
- Unattended upgrades for security patches
- Configurable update schedule
- Automatic removal of unused packages
- Email notifications for update status

### 8. **Backup Solution (restic)**
- Efficient deduplication backup tool
- Configurable backup paths
- Automated snapshot retention policies
- Secure password-based encryption

### 9. **System Hardening**
- Disables rare network protocols (DCCP, SCTP, RDS, TIPC)
- Kernel security parameters via sysctl
- IP spoofing protection
- SYN flood protection
- Secure file permissions on sensitive files
- Core dump restrictions
- ASLR (Address Space Layout Randomization) enabled

### 10. **Security Reporting**
- Custom security report script (`/usr/local/bin/security-report`)
- Shows failed login attempts
- Lists current sessions and listening ports
- Displays recent system file modifications
- Shows disk usage and failed services
- Integrates audit and fail2ban status

## Usage

```bash
# Run the security hardening (requires root)
sudo eos secure ubuntu
```

## Post-Installation Steps

After running the command, you should:

1. **Configure Restic Backup**:
   - Edit `/usr/local/bin/restic-backup`
   - Set your backup repository location
   - Update the password in `/root/.restic-password`
   - Schedule regular backups via cron

2. **Review Audit Rules**:
   - Check `/etc/audit/rules.d/hardening.rules`
   - Add custom rules for your specific needs

3. **Run Security Audit**:
   - Execute `lynis audit system` for recommendations
   - Review and implement suggested improvements

4. **Configure Email Notifications**:
   - Update fail2ban email settings in `/etc/fail2ban/jail.local`
   - Configure unattended-upgrades email in `/etc/apt/apt.conf.d/50unattended-upgrades`

5. **Test Security**:
   - Run `security-report` to see current security status
   - Monitor `/var/log/osquery/` for system activity
   - Check fail2ban status with `fail2ban-client status`

## System Requirements

- Ubuntu 24.04 (recommended) or compatible version
- Root or sudo privileges
- Internet connection for package downloads
- Sufficient disk space for logs and backups

## Security Considerations

- The script applies comprehensive hardening but should be tested in a non-production environment first
- Some hardening measures may affect system functionality (e.g., disabled network protocols)
- Review all configuration files before production deployment
- Regularly update and patch all security tools
- Monitor logs and alerts for security events

## Troubleshooting

- **Service failures**: Check systemctl status for individual services
- **Audit issues**: Verify auditd rules with `auditctl -l`
- **Update problems**: Check `/var/log/unattended-upgrades/` logs
- **Backup failures**: Test restic commands manually before automation