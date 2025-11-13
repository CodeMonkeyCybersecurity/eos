// pkg/vault/mfa_types.go

package vault

import "time"

// MFABootstrapData contains data needed for MFA setup that is fetched during
// prerequisite verification and cached for later use.
//
// This type serves two critical purposes:
//
//  1. **Eliminates TOCTOU Vulnerability**: By fetching the bootstrap password once
//     during verification and caching it, we avoid the race condition where:
//     - Time T0: Check if password exists → TRUE
//     - Time T1: [Password gets deleted/rotated]
//     - Time T2: Try to read password → FAIL
//
//  2. **Decouples from Vault API**: Instead of passing around Vault's *api.Secret
//     (which has many unrelated fields like lease info, auth data, etc.), we use
//     our own simple structure containing exactly what MFA setup needs.
//
// Usage:
//
//	// Verify prerequisites and fetch bootstrap data atomically
//	bootstrapData, err := VerifyAndFetchMFAPrerequisites(rc, client, "eos")
//	if err != nil {
//	    return err
//	}
//
//	// Use cached data for TOTP setup (no second Vault read)
//	err = SetupUserTOTP(rc, client, "eos", bootstrapData)
//
// The struct is immutable by design (no pointer fields, no exported setters).
// This prevents accidental modification after creation.
type MFABootstrapData struct {
	// Username for which MFA is being set up (e.g., "eos")
	Username string

	// Password from the bootstrap secret (plaintext)
	// This is the temporary password created in Phase 10a that's used to
	// verify TOTP setup before MFA enforcement.
	Password string

	// EntityID from Vault's identity system
	// This is needed for the TOTP admin API calls (admin-generate, admin-destroy)
	// since the root token doesn't have an associated entity.
	EntityID string

	// SecretPath where the password was read from
	// Stored for debugging and error messages.
	// Example: "secret/data/eos/bootstrap"
	SecretPath string

	// FetchedAt timestamp when this data was retrieved from Vault
	// Used for staleness detection - if this data is very old, it might
	// indicate the password has been rotated or the operation is stuck.
	FetchedAt time.Time

	// SecretVersion is the Vault KV v2 version number of the bootstrap password
	// Used for optimistic locking - if this version changes, the password was rotated
	// after we fetched it, and we should refuse to use the cached password.
	//
	// This provides stronger guarantees than time-based staleness detection because
	// it detects actual Vault state changes rather than just elapsed time.
	//
	// Version 0 means version tracking is not available (older Vault or KV v1).
	SecretVersion int
}

// IsStale returns true if the cached data is older than the threshold.
//
// Use this to detect potential TOCTOU issues or stuck operations:
//
//	if bootstrapData.IsStale(5 * time.Minute) {
//	    log.Warn("Bootstrap data is very old, may be stale")
//	}
//
// A stale warning doesn't necessarily mean the data is invalid - it could just
// mean the user is taking a long time to scan the QR code or enter the TOTP.
// But if TOTP setup fails AND the data is stale, that suggests a password
// rotation race condition.
func (d *MFABootstrapData) IsStale(threshold time.Duration) bool {
	return time.Since(d.FetchedAt) > threshold
}

// Age returns how long ago this data was fetched from Vault.
//
// Useful for logging and diagnostics:
//
//	log.Info("Using bootstrap data",
//	    zap.Duration("age", bootstrapData.Age()))
func (d *MFABootstrapData) Age() time.Duration {
	return time.Since(d.FetchedAt)
}
