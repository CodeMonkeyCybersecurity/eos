// policies/data_policy.cue

package policies

// RetentionPolicy defines how long different categories of data should be retained
RetentionPolicy: {
    name:                string
    description:         string
    appliesTo:           [...string] // e.g. ["Vault", "Wazuh", "Wazuh"]
    defaultRetention:    duration
    maxRetention:        duration
    minRetention:        duration
    clientOverride:      bool
    encryptedAtRest:     bool
    immutable:           bool
    requiresAuditTrail:  bool
    rotationSupported:   bool
    purgeAfterExpiry:    bool
}

// Example bindings for MSSP
policies: [RetentionPolicy, ...] & [
    {
        name:               "Authentication Logs"
        description:        "Vault, SSO, Keycloak login attempts and access records"
        appliesTo:          ["Vault", "Keycloak"]
        defaultRetention:   "36mo"
        maxRetention:       "60mo"
        minRetention:       "24mo"
        clientOverride:     true
        encryptedAtRest:    true
        immutable:          true
        requiresAuditTrail: true
        rotationSupported:  false
        purgeAfterExpiry:   true
    },
    {
        name:               "Wazuh Alerts"
        description:        "Alerts triggered by agent sensors"
        appliesTo:          ["Wazuh", "Wazuh"]
        defaultRetention:   "24mo"
        maxRetention:       "36mo"
        minRetention:       "12mo"
        clientOverride:     true
        encryptedAtRest:    true
        immutable:          true
        requiresAuditTrail: true
        rotationSupported:  true
        purgeAfterExpiry:   true
    },
    {
        name:               "Endpoint Telemetry"
        description:        "System logs and agent telemetry from monitored devices"
        appliesTo:          ["Wazuh"]
        defaultRetention:   "24mo"
        maxRetention:       "36mo"
        minRetention:       "12mo"
        clientOverride:     true
        encryptedAtRest:    true
        immutable:          false
        requiresAuditTrail: false
        rotationSupported:  true
        purgeAfterExpiry:   true
    },
    {
        name:               "System Logs"
        description:        "Infrastructure logs (e.g. Docker, nginx)"
        appliesTo:          ["Core", "Eos"]
        defaultRetention:   "90d"
        maxRetention:       "180d"
        minRetention:       "30d"
        clientOverride:     false
        encryptedAtRest:    true
        immutable:          false
        requiresAuditTrail: false
        rotationSupported:  true
        purgeAfterExpiry:   true
    }
]