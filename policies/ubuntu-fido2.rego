package ubuntu.fido2

import rego.v1

# Ubuntu FIDO2/WebAuthn Security Policies
# This policy defines FIDO2 key requirements and enforcement rules

# Supported FIDO2 key types and their security levels
supported_authenticators := {
    "yubikey": {
        "vendor_id": "1050",
        "security_level": "high",
        "required_features": ["resident_keys", "user_verification", "enterprise_attestation"],
        "max_age_days": 365
    },
    "solokey": {
        "vendor_id": "0483", 
        "security_level": "medium",
        "required_features": ["resident_keys", "user_verification"],
        "max_age_days": 180
    },
    "google_titan": {
        "vendor_id": "18d1",
        "security_level": "high", 
        "required_features": ["resident_keys", "user_verification", "enterprise_attestation"],
        "max_age_days": 365
    },
    "nitrokey": {
        "vendor_id": "20a0",
        "security_level": "high",
        "required_features": ["resident_keys", "user_verification"],
        "max_age_days": 365
    }
}

# FIDO2 enforcement levels for different user roles
enforcement_levels := {
    "admin": {
        "require_fido2": true,
        "require_pin": true,
        "require_biometric": false,
        "min_security_level": "high",
        "max_credential_age_days": 90,
        "require_attestation": true,
        "backup_methods": ["totp"]
    },
    "user": {
        "require_fido2": true,
        "require_pin": true, 
        "require_biometric": false,
        "min_security_level": "medium",
        "max_credential_age_days": 180,
        "require_attestation": false,
        "backup_methods": ["totp", "backup_codes"]
    },
    "service": {
        "require_fido2": false,
        "require_pin": false,
        "require_biometric": false,
        "min_security_level": "medium", 
        "max_credential_age_days": 365,
        "require_attestation": false,
        "backup_methods": ["totp", "client_cert"]
    }
}

# Critical operations that always require FIDO2
critical_operations := {
    "sudo",
    "su", 
    "ssh_root",
    "vault_unseal",
    "eos_secure",
    "system_backup",
    "user_management"
}

# FIDO2 configuration requirements
fido2_requirements := {
    "libfido2_min_version": "1.12.0",
    "pam_u2f_enabled": true,
    "udev_rules_configured": true,
    "systemd_logind_configured": true,
    "required_packages": [
        "libfido2-1",
        "libfido2-dev", 
        "fido2-tools",
        "libpam-u2f",
        "pamu2fcfg"
    ]
}

# Security policies for FIDO2 credentials
credential_policies := {
    "max_credentials_per_user": 3,
    "min_credentials_per_admin": 2,  # Backup key required
    "credential_rotation_days": 365,
    "attestation_verification": true,
    "resident_key_required": true,
    "user_verification_required": true
}

# Check if FIDO2 is properly configured system-wide
fido2_system_configured if {
    input.fido2.libfido2_version >= fido2_requirements.libfido2_min_version
    input.fido2.pam_u2f_enabled == fido2_requirements.pam_u2f_enabled
    input.fido2.udev_rules_configured == fido2_requirements.udev_rules_configured
    all_packages_installed
}

# Verify all required packages are installed
all_packages_installed if {
    every package in fido2_requirements.required_packages {
        package in input.system.installed_packages
    }
}

# Check if user has properly configured FIDO2 credentials
user_fido2_compliant(user_role) if {
    enforcement := enforcement_levels[user_role]
    user_config := input.fido2.users[input.user]
    
    # Check if FIDO2 is required for this role
    enforcement.require_fido2 == false
} else if {
    enforcement := enforcement_levels[user_role] 
    user_config := input.fido2.users[input.user]
    
    enforcement.require_fido2 == true
    count(user_config.credentials) >= 1
    valid_credentials_for_role(user_role)
    backup_methods_configured(user_role)
}

# Validate credentials meet role requirements
valid_credentials_for_role(user_role) if {
    enforcement := enforcement_levels[user_role]
    user_config := input.fido2.users[input.user]
    
    every credential in user_config.credentials {
        authenticator := supported_authenticators[credential.type]
        authenticator.security_level >= enforcement.min_security_level
        credential_age_valid(credential, enforcement.max_credential_age_days)
        required_features_present(credential, authenticator.required_features)
    }
}

# Check credential age
credential_age_valid(credential, max_age_days) if {
    age_days := (time.now_ns() - credential.created_at) / (24 * 60 * 60 * 1000000000)
    age_days <= max_age_days
}

# Verify required features are present
required_features_present(credential, required_features) if {
    every feature in required_features {
        feature in credential.features
    }
}

# Check backup authentication methods
backup_methods_configured(user_role) if {
    enforcement := enforcement_levels[user_role]
    user_config := input.fido2.users[input.user]
    
    every method in enforcement.backup_methods {
        method in user_config.backup_methods
        user_config.backup_methods[method].configured == true
    }
}

# Critical operation FIDO2 enforcement
critical_operation_compliant if {
    input.operation in critical_operations
    input.authentication.method == "fido2"
    input.authentication.user_verification == true
} else if {
    not input.operation in critical_operations
}

# FIDO2 device security validation
device_security_compliant if {
    every device in input.fido2.connected_devices {
        device.vendor_id in [auth.vendor_id | auth := supported_authenticators[_]]
        device.firmware_updated == true
        device.attestation_valid == true
    }
}

# Generate FIDO2 compliance report
fido2_compliance_report := {
    "system_configured": fido2_system_configured,
    "user_compliant": user_fido2_compliant(input.user_role),
    "critical_ops_compliant": critical_operation_compliant,
    "device_security": device_security_compliant,
    "recommendations": fido2_recommendations,
    "security_score": fido2_security_score
}

# Security recommendations
fido2_recommendations contains "Install required FIDO2 packages" if {
    not all_packages_installed
}

fido2_recommendations contains "Configure PAM U2F module" if {
    not input.fido2.pam_u2f_enabled
}

fido2_recommendations contains "Update libfido2 to minimum version" if {
    input.fido2.libfido2_version < fido2_requirements.libfido2_min_version
}

fido2_recommendations contains "Register backup FIDO2 key for admin users" if {
    input.user_role == "admin"
    count(input.fido2.users[input.user].credentials) < credential_policies.min_credentials_per_admin
}

fido2_recommendations contains "Rotate aging FIDO2 credentials" if {
    some credential in input.fido2.users[input.user].credentials
    not credential_age_valid(credential, credential_policies.credential_rotation_days)
}

# Calculate security score (0-100)
fido2_security_score := score if {
    base_score := 0
    score_additions := [
        30 if fido2_system_configured else 0,
        25 if user_fido2_compliant(input.user_role) else 0,
        20 if critical_operation_compliant else 0,
        15 if device_security_compliant else 0,
        10 if count(fido2_recommendations) == 0 else 0
    ]
    score := base_score + sum(score_additions)
}

# Allow policy if FIDO2 requirements are met
allow if {
    fido2_system_configured
    user_fido2_compliant(input.user_role)
    critical_operation_compliant
    device_security_compliant
}

# Deny with specific reasons
deny contains reason if {
    not fido2_system_configured
    reason := "FIDO2 system configuration incomplete"
}

deny contains reason if {
    not user_fido2_compliant(input.user_role)
    reason := sprintf("User FIDO2 configuration non-compliant for role: %s", [input.user_role])
}

deny contains reason if {
    not critical_operation_compliant
    reason := sprintf("FIDO2 required for critical operation: %s", [input.operation])
}

deny contains reason if {
    not device_security_compliant
    reason := "Connected FIDO2 devices do not meet security requirements"
}