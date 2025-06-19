package ubuntu.hardening

import rego.v1

# Ubuntu System Hardening Security Policies
# Comprehensive security enforcement for hardened Ubuntu systems

# Required security tools and their minimum versions
required_security_tools := {
    "auditd": {
        "min_version": "3.0",
        "required": true,
        "service_enabled": true,
        "config_validation": true
    },
    "aide": {
        "min_version": "0.17",
        "required": true,
        "database_initialized": true,
        "daily_checks": true
    },
    "fail2ban": {
        "min_version": "0.11",
        "required": true,
        "service_enabled": true,
        "ssh_protection": true
    },
    "lynis": {
        "min_version": "3.0",
        "required": true,
        "monthly_audits": true,
        "score_threshold": 75
    },
    "osquery": {
        "min_version": "5.0",
        "required": true,
        "service_enabled": true,
        "fleet_enrolled": false
    },
    "restic": {
        "min_version": "0.14",
        "required": true,
        "backup_configured": true,
        "encryption_enabled": true
    }
}

# Kernel security parameters that must be set
required_kernel_params := {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.send_redirects": "0", 
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.secure_redirects": "0",
    "net.ipv4.conf.default.secure_redirects": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syncookies": "1",
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "kernel.yama.ptrace_scope": "2",
    "fs.suid_dumpable": "0",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1"
}

# Network protocols that must be disabled
disabled_protocols := {
    "dccp",
    "sctp", 
    "rds",
    "tipc"
}

# Critical file permissions that must be enforced
critical_file_permissions := {
    "/etc/passwd": "644",
    "/etc/group": "644", 
    "/etc/shadow": "600",
    "/etc/gshadow": "600",
    "/etc/ssh/sshd_config": "600",
    "/etc/sudoers": "440",
    "/var/log/auth.log": "640",
    "/var/log/syslog": "640",
    "/boot/grub/grub.cfg": "600"
}

# SSH hardening requirements
ssh_hardening_config := {
    "Protocol": "2",
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no", 
    "PubkeyAuthentication": "yes",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "MaxAuthTries": "3",
    "ClientAliveInterval": "300",
    "ClientAliveCountMax": "0",
    "LoginGraceTime": "60",
    "Banner": "/etc/issue.net",
    "AllowUsers": "eos",
    "DenyUsers": "root"
}

# Systemd services that should be disabled for security
disabled_services := {
    "telnet",
    "rsh", 
    "rlogin",
    "vsftpd",
    "xinetd",
    "cups",
    "avahi-daemon",
    "bluetooth"
}

# Audit rules that must be configured
required_audit_rules := {
    "time_changes": "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
    "user_emulation": "-a always,exit -F arch=b64 -S personality -k user-emulation", 
    "system_locale": "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale",
    "mac_policy": "-w /etc/apparmor/ -p wa -k MAC-policy",
    "login_logout": "-w /var/log/faillog -p wa -k logins",
    "session_initiation": "-w /var/run/utmp -p wa -k session",
    "permission_modification": "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
    "unsuccessful_file_access": "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
    "privileged_commands": "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-sudo"
}

# Check if all security tools are properly installed and configured
security_tools_compliant if {
    every tool_name, tool_config in required_security_tools {
        tool_installed(tool_name, tool_config)
        tool_configured(tool_name, tool_config)
    }
}

# Verify tool installation and version
tool_installed(tool_name, tool_config) if {
    tool_name in input.system.installed_packages
    input.system.package_versions[tool_name] >= tool_config.min_version
}

# Verify tool configuration  
tool_configured(tool_name, tool_config) if {
    tool_config.service_enabled == false
} else if {
    tool_config.service_enabled == true
    input.system.enabled_services[tool_name] == true
}

# Check kernel security parameters
kernel_params_compliant if {
    every param_name, param_value in required_kernel_params {
        input.system.kernel_params[param_name] == param_value
    }
}

# Verify disabled network protocols
protocols_disabled if {
    every protocol in disabled_protocols {
        not protocol in input.system.loaded_modules
    }
}

# Check critical file permissions
file_permissions_compliant if {
    every file_path, required_perm in critical_file_permissions {
        input.system.file_permissions[file_path] == required_perm
    }
}

# Verify SSH hardening configuration
ssh_hardening_compliant if {
    every config_key, config_value in ssh_hardening_config {
        input.system.ssh_config[config_key] == config_value
    }
}

# Check that insecure services are disabled
insecure_services_disabled if {
    every service in disabled_services {
        not service in input.system.enabled_services
    }
}

# Verify audit rules are configured
audit_rules_compliant if {
    every rule_name, rule_content in required_audit_rules {
        rule_name in input.system.audit_rules
        input.system.audit_rules[rule_name] == rule_content
    }
}

# Check automatic security updates
auto_updates_enabled if {
    input.system.unattended_upgrades.enabled == true
    input.system.unattended_upgrades.security_only == true
    input.system.unattended_upgrades.auto_reboot == false
}

# Verify backup system is configured
backup_system_compliant if {
    "restic" in input.system.installed_packages
    input.system.backup_config.encryption_enabled == true
    input.system.backup_config.scheduled == true
    input.system.backup_config.retention_policy != ""
}

# Overall system hardening compliance
system_hardening_compliant if {
    security_tools_compliant
    kernel_params_compliant  
    protocols_disabled
    file_permissions_compliant
    ssh_hardening_compliant
    insecure_services_disabled
    audit_rules_compliant
    auto_updates_enabled
    backup_system_compliant
}

# Generate detailed compliance report
hardening_compliance_report := {
    "overall_compliant": system_hardening_compliant,
    "security_tools": security_tools_status,
    "kernel_security": kernel_security_status,
    "network_security": network_security_status, 
    "file_security": file_security_status,
    "ssh_security": ssh_security_status,
    "service_security": service_security_status,
    "audit_security": audit_security_status,
    "backup_security": backup_security_status,
    "recommendations": hardening_recommendations,
    "security_score": hardening_security_score
}

# Detailed status for each category
security_tools_status := {
    "compliant": security_tools_compliant,
    "missing_tools": [tool | tool := required_security_tools[_]; not tool_installed(tool, required_security_tools[tool])],
    "misconfigured_tools": [tool | tool := required_security_tools[_]; tool_installed(tool, required_security_tools[tool]); not tool_configured(tool, required_security_tools[tool])]
}

kernel_security_status := {
    "compliant": kernel_params_compliant,
    "incorrect_params": [param | param := required_kernel_params[_]; input.system.kernel_params[param] != required_kernel_params[param]]
}

network_security_status := {
    "compliant": protocols_disabled,
    "enabled_protocols": [proto | proto := disabled_protocols[_]; proto in input.system.loaded_modules]
}

file_security_status := {
    "compliant": file_permissions_compliant,
    "incorrect_permissions": [file | file := critical_file_permissions[_]; input.system.file_permissions[file] != critical_file_permissions[file]]
}

ssh_security_status := {
    "compliant": ssh_hardening_compliant,
    "incorrect_config": [config | config := ssh_hardening_config[_]; input.system.ssh_config[config] != ssh_hardening_config[config]]
}

service_security_status := {
    "compliant": insecure_services_disabled,
    "enabled_insecure_services": [svc | svc := disabled_services[_]; svc in input.system.enabled_services]
}

audit_security_status := {
    "compliant": audit_rules_compliant, 
    "missing_rules": [rule | rule := required_audit_rules[_]; not rule in input.system.audit_rules]
}

backup_security_status := {
    "compliant": backup_system_compliant,
    "issues": backup_issues
}

backup_issues contains "Backup not configured" if {
    not input.system.backup_config.scheduled
}

backup_issues contains "Encryption not enabled" if {
    not input.system.backup_config.encryption_enabled
}

# Security recommendations
hardening_recommendations contains "Install missing security tools" if {
    not security_tools_compliant
}

hardening_recommendations contains "Configure kernel security parameters" if {
    not kernel_params_compliant
}

hardening_recommendations contains "Disable insecure network protocols" if {
    not protocols_disabled
}

hardening_recommendations contains "Fix critical file permissions" if {
    not file_permissions_compliant
}

hardening_recommendations contains "Harden SSH configuration" if {
    not ssh_hardening_compliant
}

hardening_recommendations contains "Disable insecure services" if {
    not insecure_services_disabled
}

hardening_recommendations contains "Configure audit rules" if {
    not audit_rules_compliant
}

hardening_recommendations contains "Enable automatic security updates" if {
    not auto_updates_enabled
}

hardening_recommendations contains "Configure backup system" if {
    not backup_system_compliant
}

# Calculate security score (0-100)
hardening_security_score := score if {
    components := [
        {10: security_tools_compliant},
        {15: kernel_params_compliant},
        {10: protocols_disabled},
        {15: file_permissions_compliant}, 
        {15: ssh_hardening_compliant},
        {10: insecure_services_disabled},
        {10: audit_rules_compliant},
        {10: auto_updates_enabled},
        {5: backup_system_compliant}
    ]
    
    earned_points := sum([points | component := components[_]; points := [p | p := component[_]; component[p] == true][0]; points != null])
    score := earned_points
}

# Allow if system meets hardening requirements
allow if {
    system_hardening_compliant
    hardening_security_score >= 80
}

# Deny with specific reasons
deny contains reason if {
    not security_tools_compliant
    reason := "Required security tools not properly installed or configured"
}

deny contains reason if {
    not kernel_params_compliant
    reason := "Kernel security parameters not properly configured"
}

deny contains reason if {
    not file_permissions_compliant
    reason := "Critical file permissions not properly set"
}

deny contains reason if {
    not ssh_hardening_compliant
    reason := "SSH service not properly hardened"
}

deny contains reason if {
    hardening_security_score < 80
    reason := sprintf("System hardening score too low: %d/100", [hardening_security_score])
}