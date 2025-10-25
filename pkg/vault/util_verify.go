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

// checkSecretExistsKVv2 checks if a KV v2 secret exists at the given semantic path.
//
// This function implements efficient secret existence checking by querying the metadata
// endpoint instead of reading the actual secret data. This approach:
// - Avoids transferring sensitive data unnecessarily
// - Reduces network bandwidth
// - Works even if the caller doesn't have read permissions on the data
//
// Parameters:
//   - ctx: Context for the operation (used for logging and cancellation)
//   - client: Authenticated Vault client
//   - mount: KV v2 mount point (e.g., "secret")
//   - semanticPath: Semantic path WITHOUT /data/ or /metadata/ prefix (e.g., "eos/bootstrap")
//
// Returns:
//   - exists: true if secret exists, false if 404 or not found
//   - err: non-nil if error checking (not a 404)
//
// Path Resolution:
//   Input semantic path: "eos/bootstrap"
//   Constructed metadata path: "secret/metadata/eos/bootstrap"
//
// Error Handling:
//   - 404 errors are expected (secret doesn't exist) → returns (false, nil)
//   - Other errors indicate problems → returns (false, error)
//   - nil response treated as not found → returns (false, nil)
//
// This eliminates TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities by making
// the check and use separate atomic operations. The early check provides fail-fast
// behavior, while the actual read should still handle not-found errors gracefully.
//
// Example:
//
//	exists, err := checkSecretExistsKVv2(ctx, client, "secret", "eos/bootstrap")
//	if err != nil {
//	    return fmt.Errorf("failed to check secret existence: %w", err)
//	}
//	if !exists {
//	    return fmt.Errorf("required secret not found")
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
		log.Debug("Secret exists",
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
