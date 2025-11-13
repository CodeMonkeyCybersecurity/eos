// pkg/vault/util_verify.go

package vault

import (
	"context"
	"fmt"
	"strings"

	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkSecretExistsKVv2 checks if a KV v2 secret exists and is not deleted.
//
// This function implements efficient secret existence checking by querying the metadata
// endpoint instead of reading the actual secret data. This approach:
// - Avoids transferring sensitive data unnecessarily
// - Reduces network bandwidth
// - Works even if the caller doesn't have read permissions on the data
// - Detects soft-deleted secrets (checks deletion_time field)
//
// IMPORTANT Limitation: The metadata endpoint returns success even for DELETED secrets
// (they're marked as deleted, not removed). This function checks the deletion_time field
// and returns false for soft-deleted secrets.
//
// Parameters:
//   - ctx: Context for the operation (used for logging and cancellation)
//   - client: Authenticated Vault client
//   - mount: KV v2 mount point (e.g., "secret")
//   - semanticPath: Semantic path WITHOUT /data/ or /metadata/ prefix (e.g., "eos/bootstrap")
//
// Returns:
//   - exists: true if secret exists AND is not deleted, false otherwise
//   - err: non-nil if error checking (not a 404)
//
// Path Resolution:
//
//	Input semantic path: "eos/bootstrap"
//	Constructed metadata path: "secret/metadata/eos/bootstrap"
//
// Error Handling:
//   - 404 errors are expected (secret doesn't exist) → returns (false, nil)
//   - Other errors indicate problems → returns (false, error)
//   - nil response treated as not found → returns (false, nil)
//   - Secrets with deletion_time set → returns (false, nil)
//
// Use Cases:
//   - Conditional operations: "if backup exists, use it; else create new"
//   - Health checks: "verify critical secrets exist"
//   - Cleanup: "delete only if exists"
//
// For MFA setup, prefer VerifyAndFetchMFAPrerequisites() which reads the secret once
// and caches it, eliminating TOCTOU races and reducing Vault API calls.
//
// Example:
//
//	exists, err := checkSecretExistsKVv2(ctx, client, "secret", "eos/bootstrap")
//	if err != nil {
//	    return fmt.Errorf("failed to check secret existence: %w", err)
//	}
//	if !exists {
//	    return fmt.Errorf("required secret not found or deleted")
//	}
func checkSecretExistsKVv2(
	ctx context.Context,
	client *api.Client,
	mount string,
	semanticPath string,
) (exists bool, err error) {
	log := otelzap.Ctx(ctx)

	// Normalize paths by removing leading/trailing slashes
	mount = strings.TrimSuffix(mount, "/")
	semanticPath = strings.Trim(semanticPath, "/")

	// Construct metadata path for KV v2
	// KV v2 API structure:
	//   - Data read/write: {mount}/data/{path}
	//   - Metadata read: {mount}/metadata/{path}
	//   - Metadata is more efficient for existence checks
	metadataPath := fmt.Sprintf("%s/metadata/%s", mount, semanticPath)

	log.Debug("Checking secret existence via metadata endpoint",
		zap.String("semantic_path", semanticPath),
		zap.String("metadata_path", metadataPath),
		zap.String("mount", mount))

	secret, err := client.Logical().ReadWithContext(ctx, metadataPath)

	if err != nil {
		// Check if this is a 404 (expected - secret doesn't exist)
		// This is NOT an error condition - it just means the secret isn't there yet
		if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == 404 {
			log.Debug("Secret does not exist (404)",
				zap.String("semantic_path", semanticPath),
				zap.String("metadata_path", metadataPath))
			return false, nil
		}

		// Any other error is a problem (network, permissions, Vault down, etc.)
		log.Warn("Error checking secret existence",
			zap.String("semantic_path", semanticPath),
			zap.String("metadata_path", metadataPath),
			zap.Error(err))
		return false, cerr.Wrapf(err, "failed to check secret existence at %s", semanticPath)
	}

	// Secret exists if we got a non-nil response with data
	if secret != nil && secret.Data != nil {
		// CRITICAL P1 FIX: Check if secret is destroyed (all versions permanently deleted)
		// The metadata endpoint returns success even for destroyed secrets,
		// so we must check the destroyed field explicitly.
		//
		// KV v2 has multiple deletion states:
		// 1. Soft-deleted: deletion_time set, can be undeleted
		// 2. Destroyed: destroyed=true, permanently deleted, CANNOT be recovered
		//
		// We check destroyed first because it's the most severe state.
		if destroyed, ok := secret.Data["destroyed"].(bool); ok && destroyed {
			log.Warn("Secret exists in metadata but is destroyed (all versions permanently deleted)",
				zap.String("semantic_path", semanticPath),
				zap.String("metadata_path", metadataPath))
			return false, nil // Treat destroyed secrets as not existing
		}

		// CRITICAL: Check if the secret is soft-deleted in KV v2
		// The metadata endpoint returns success even for deleted secrets,
		// so we must check the deletion_time field explicitly.
		//
		// From Vault docs: "The metadata endpoint returns metadata about a secret,
		// including deletion and version information. A deleted secret still has metadata."
		if deletionTime, ok := secret.Data["deletion_time"].(string); ok && deletionTime != "" {
			log.Warn("Secret exists in metadata but current version is soft-deleted",
				zap.String("semantic_path", semanticPath),
				zap.String("metadata_path", metadataPath),
				zap.String("deletion_time", deletionTime))
			return false, nil // Treat deleted secrets as not existing
		}

		log.Debug("Secret exists and is not deleted",
			zap.String("semantic_path", semanticPath),
			zap.String("metadata_path", metadataPath),
			zap.Any("metadata_keys", getMapKeys(secret.Data)))
		return true, nil
	}

	// Response was nil or had no data - treat as not found
	// This shouldn't happen (Vault should return 404), but be defensive
	log.Debug("Secret does not exist (nil response)",
		zap.String("semantic_path", semanticPath),
		zap.String("metadata_path", metadataPath))
	return false, nil
}
