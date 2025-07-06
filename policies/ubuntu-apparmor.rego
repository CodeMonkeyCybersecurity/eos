package ubuntu.apparmor

import rego.v1

# Ubuntu AppArmor Security Policies
# This policy defines mandatory AppArmor profiles and enforcement rules

# Default AppArmor profiles that must be enabled
required_profiles := {
    "usr.bin.firefox",
    "usr.bin.thunderbird", 
    "usr.bin.evince",
    "usr.bin.man",
    "usr.sbin.cups-browsed",
    "usr.sbin.cupsd",
    "usr.sbin.tcpdump",
    "/usr/local/bin/eos"
}

# Custom Eos profiles that must be created
eos_profiles := {
    "eos-cli": {
        "path": "/usr/local/bin/eos",
        "mode": "enforce",
        "capabilities": ["dac_override", "setuid", "setgid", "sys_admin"],
        "network": "inet",
        "file_rules": [
            "/var/lib/eos/** rwk,",
            "/etc/eos/** r,",
            "/var/log/eos/** w,",
            "/run/eos/** rwk,",
            "/tmp/eos-* rwk,",
            "/proc/sys/kernel/** r,",
            "/sys/kernel/security/apparmor/** r,"
        ]
    },
    "eos-vault-agent": {
        "path": "/usr/bin/vault",
        "mode": "enforce", 
        "capabilities": ["net_admin"],
        "network": "inet",
        "file_rules": [
            "/var/lib/eos/secrets/** rwk,",
            "/run/eos/vault-agent.sock rw,",
            "/etc/vault-agent.hcl r,",
            "/var/log/vault-agent.log w,"
        ]
    },
    "eos-backup": {
        "path": "/usr/local/bin/eos-backup",
        "mode": "enforce",
        "capabilities": ["dac_override"],
        "file_rules": [
            "/var/lib/eos/** r,",
            "/etc/eos/** r,",
            "/var/log/eos/** r,",
            "/home/*/.eos/** r,",
            "/tmp/eos-backup-* rwk,"
        ]
    }
}

# Security enforcement levels
enforcement_levels := {
    "strict": {
        "default_mode": "enforce",
        "allow_complain": false,
        "require_signatures": true,
        "auto_reload": true
    },
    "standard": {
        "default_mode": "enforce", 
        "allow_complain": true,
        "require_signatures": false,
        "auto_reload": true
    },
    "development": {
        "default_mode": "complain",
        "allow_complain": true,
        "require_signatures": false,
        "auto_reload": false
    }
}

# Critical system profiles that must never be disabled
critical_profiles := {
    "/usr/local/bin/eos",
    "/usr/bin/sudo",
    "/usr/sbin/sshd",
    "/usr/bin/passwd"
}

# AppArmor violations that trigger immediate alerts
violation_triggers := {
    "denied_exec": {
        "severity": "critical",
        "alert": true,
        "auto_block": true
    },
    "denied_capability": {
        "severity": "high", 
        "alert": true,
        "auto_block": false
    },
    "denied_network": {
        "severity": "medium",
        "alert": true,
        "auto_block": false
    },
    "denied_file": {
        "severity": "low",
        "alert": false,
        "auto_block": false
    }
}

# Check if AppArmor is properly configured
apparmor_properly_configured if {
    input.apparmor.enabled == true
    input.apparmor.mode == "enforce"
    count(missing_required_profiles) == 0
}

# Find missing required profiles
missing_required_profiles := required_profiles - {profile | 
    profile := input.apparmor.loaded_profiles[_]
}

# Validate Eos custom profiles
validate_eos_profiles if {
    every profile_name, profile_config in eos_profiles {
        profile_name in input.apparmor.loaded_profiles
        input.apparmor.profiles[profile_name].mode == profile_config.mode
    }
}

# Check enforcement level compliance
enforcement_compliant(level) if {
    config := enforcement_levels[level]
    input.apparmor.default_mode == config.default_mode
    config.require_signatures == false; input.apparmor.signatures_required == config.require_signatures
}

# Detect critical profile violations
critical_violation if {
    some profile in critical_profiles
    profile in input.apparmor.violations[_].profile
    input.apparmor.violations[_].type == "denied_exec"
}

# Generate AppArmor compliance report
compliance_report := {
    "status": "compliant" if apparmor_properly_configured else "non_compliant",
    "missing_profiles": missing_required_profiles,
    "eos_profiles_valid": validate_eos_profiles,
    "critical_violations": count([v | v := input.apparmor.violations[_]; v.profile in critical_profiles]) > 0,
    "enforcement_level": input.system.security_level,
    "recommendations": recommendations
}

# Security recommendations based on current state
recommendations contains "Enable AppArmor enforcement mode" if {
    input.apparmor.mode != "enforce"
}

recommendations contains "Load missing required profiles" if {
    count(missing_required_profiles) > 0
}

recommendations contains "Address critical profile violations immediately" if {
    critical_violation
}

recommendations contains "Update Eos custom profiles" if {
    not validate_eos_profiles
}

# Allow policy if all security requirements are met
allow if {
    apparmor_properly_configured
    validate_eos_profiles
    not critical_violation
    input.system.security_level in ["strict", "standard"]
}

# Deny with specific reasons
deny contains reason if {
    not apparmor_properly_configured
    reason := "AppArmor is not properly configured"
}

deny contains reason if {
    not validate_eos_profiles  
    reason := "Eos AppArmor profiles are invalid or missing"
}

deny contains reason if {
    critical_violation
    reason := "Critical AppArmor violations detected"
}