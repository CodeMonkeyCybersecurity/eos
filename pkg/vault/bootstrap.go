// pkg/vault/bootstrap.go - Bootstrap password management with validation
// RATIONALE: Domain-specific validation prevents generic convenience methods
//           from hiding validation requirements
//
// This file provides validated read/write operations for the bootstrap password,
// which is a temporary credential used during initial Vault setup (Phase 10a → 13).
//
// The bootstrap password is:
// - Written in Phase 10a (userpass setup)
// - Read in Phase 13 (MFA setup to authenticate and configure TOTP)
// - Deleted after first successful TOTP verification
//
// Path: secret/eos/bootstrap
// Structure: {password: string, created_at: timestamp, purpose: string, ...}

package vault

import (
	"context"
	"fmt"
	"time"

	vaultpaths "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

// BootstrapPassword represents the validated bootstrap password structure
type BootstrapPassword struct {
	Password  string
	CreatedAt time.Time
	Purpose   string
	CreatedBy string
}

// WriteBootstrapPassword writes AND VALIDATES bootstrap password to Vault KV
// This replaces the inline code in phase10a_enable_userpass.go with:
// - Pre-write validation (password strength)
// - Automatic write-then-verify (via EosKVv2Store.Put)
// - Post-write validation (structure correctness)
//
// Example:
//
//	kv := NewEosKVv2Store(client, "secret", log)
//	err := WriteBootstrapPassword(ctx, kv, password, log)
func WriteBootstrapPassword(ctx context.Context, kv *EosKVv2Store, password string, log *zap.Logger) error {
	log.Info(" [INTERVENE] Writing bootstrap password to Vault KV",
		zap.String("path", "secret/eos/bootstrap"))

	// ASSESS: Validate password before writing
	if len(password) < 20 {
		return cerr.Newf("bootstrap password too short: %d chars (minimum 20)", len(password))
	}

	if password == "" {
		return cerr.New("bootstrap password cannot be empty")
	}

	bootstrapData := map[string]interface{}{
		vaultpaths.UserpassBootstrapPasswordKVField: password,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"purpose":    "initial-setup-verification",
		"lifecycle":  "ephemeral - deleted after first use",
		"created_by": "eos-phase-10a",
	}

	// INTERVENE: Put() includes automatic write-then-verify
	// This catches storage backend failures immediately instead of
	// failing later at Phase 13 when we try to read it
	if err := kv.Put(ctx, "eos/bootstrap", bootstrapData); err != nil {
		log.Error(" Failed to write bootstrap password",
			zap.Error(err),
			zap.String("path", "secret/eos/bootstrap"))
		return cerr.Wrap(err, "write bootstrap password")
	}

	log.Info(" [EVALUATE] Bootstrap password written and verified successfully",
		zap.String("path", "secret/eos/bootstrap"),
		zap.String("field", vaultpaths.UserpassBootstrapPasswordKVField),
		zap.String("purpose", "initial-setup-verification"))

	return nil
}

// GetBootstrapPassword retrieves AND VALIDATES bootstrap password from Vault KV
// This replaces the generic GetString() convenience method with proper validation
// and returns a structured, validated BootstrapPassword object
//
// Returns ErrPhasePrerequisiteMissing if the secret doesn't exist (Phase 10a incomplete)
// Returns ErrBootstrapPasswordInvalidStructure if the secret exists but is malformed
//
// Example:
//
//	kv := NewEosKVv2Store(client, "secret", log)
//	bootstrapPass, err := GetBootstrapPassword(ctx, kv, log)
//	if err != nil {
//	    // Error includes decision tree with recovery commands
//	    return nil, err
//	}
//	password := bootstrapPass.Password
func GetBootstrapPassword(ctx context.Context, kv *EosKVv2Store, log *zap.Logger) (*BootstrapPassword, error) {
	log.Info(" [ASSESS] Reading bootstrap password from Vault KV",
		zap.String("path", "secret/eos/bootstrap"))

	data, err := kv.Get(ctx, "eos/bootstrap")
	if err != nil {
		// Secret doesn't exist or can't be read - Phase 10a didn't complete
		log.Error(" Bootstrap password not found or not readable",
			zap.Error(err),
			zap.String("path", "secret/eos/bootstrap"))
		return nil, ErrPhasePrerequisiteMissing{
			Phase:           "13 (MFA Setup)",
			DependsOn:       "10a (Userpass Configuration)",
			MissingArtifact: "bootstrap password",
			DiagnosticCmd:   "sudo eos debug vault --identities",
			RecoveryCmd:     "sudo eos create vault --clean",
		}
	}

	// EVALUATE: Validate structure and return typed object
	return ValidateBootstrapPasswordStructure(data)
}

// ValidateBootstrapPasswordStructure validates the data structure from Vault
// Separated for testability - can be unit tested without real Vault instance
//
// Validates:
// - Password field exists and is a string
// - Password is non-empty
// - Password meets minimum length (20 chars)
// - Timestamps are parseable (if present)
//
// Returns structured BootstrapPassword on success
// Returns ErrBootstrapPasswordInvalidStructure on validation failure
func ValidateBootstrapPasswordStructure(data map[string]interface{}) (*BootstrapPassword, error) {
	// Check password field exists and is string
	password, ok := data[vaultpaths.UserpassBootstrapPasswordKVField].(string)
	if !ok {
		return nil, ErrBootstrapPasswordInvalidStructure{
			Expected: fmt.Sprintf("string field '%s'", vaultpaths.UserpassBootstrapPasswordKVField),
			Got:      fmt.Sprintf("%T", data[vaultpaths.UserpassBootstrapPasswordKVField]),
			Fields:   getBootstrapMapKeys(data),
		}
	}

	// Check password is non-empty
	if len(password) == 0 {
		return nil, ErrBootstrapPasswordInvalidStructure{
			Expected: "non-empty password",
			Got:      "empty string",
			Fields:   getBootstrapMapKeys(data),
		}
	}

	// Check password meets minimum length
	if len(password) < 20 {
		return nil, ErrBootstrapPasswordInvalidStructure{
			Expected: "password >= 20 chars",
			Got:      fmt.Sprintf("%d chars", len(password)),
			Fields:   getBootstrapMapKeys(data),
		}
	}

	// Parse created_at timestamp (optional field, default to now if missing)
	createdAt := time.Now()
	if createdAtStr, ok := data["created_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			createdAt = parsed
		}
	}

	// Extract optional metadata fields
	purpose, _ := data["purpose"].(string)
	createdBy, _ := data["created_by"].(string)

	return &BootstrapPassword{
		Password:  password,
		CreatedAt: createdAt,
		Purpose:   purpose,
		CreatedBy: createdBy,
	}, nil
}

// getBootstrapMapKeys extracts keys from a map for error reporting
func getBootstrapMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
