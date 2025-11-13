// pkg/vault/kvstore.go - EosKVv2Store provides consistent KV v2 operations
// RATIONALE: Single source of truth eliminates /data/ prefix bugs
//           and provides validation hooks for all reads/writes
//
// This abstraction solves the critical bug where WriteKVv2() uses client.KVv2()
// (which handles /data/ prefix automatically) but reads used client.Logical()
// (which requires manual /data/ prefix), causing path mismatches.

package vault

import (
	"context"
	"fmt"
	"strings"

	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EosKVv2Store wraps Vault client for consistent KV v2 operations
// Name deliberately specific to avoid confusion with generic stores
type EosKVv2Store struct {
	client *api.Client
	mount  string
	log    *zap.Logger
}

// NewEosKVv2Store creates a KV store for the given mount (e.g., "secret")
// Path parameter should be the mount point name without trailing slash
func NewEosKVv2Store(client *api.Client, mount string, log *zap.Logger) *EosKVv2Store {
	return &EosKVv2Store{
		client: client,
		mount:  strings.TrimSuffix(mount, "/"),
		log:    log,
	}
}

// Get retrieves a secret from KV v2
// Path should NOT include mount or /data/ prefix (e.g., "eos/bootstrap")
//
// Example:
//
//	kv := NewEosKVv2Store(client, "secret", log)
//	data, err := kv.Get(ctx, "eos/bootstrap")
//	// Reads from: secret/data/eos/bootstrap (handled automatically)
func (kv *EosKVv2Store) Get(ctx context.Context, path string) (map[string]interface{}, error) {
	kv.log.Debug("Reading KV v2 secret",
		zap.String("mount", kv.mount),
		zap.String("path", path),
		zap.String("full_path", fmt.Sprintf("%s/data/%s", kv.mount, path)))

	secret, err := kv.client.KVv2(kv.mount).Get(ctx, path)
	if err != nil {
		return nil, cerr.Wrapf(err, "read %s/%s", kv.mount, path)
	}

	if secret == nil || secret.Data == nil {
		return nil, cerr.Newf("secret %s/%s exists but has no data", kv.mount, path)
	}

	kv.log.Debug("KV v2 secret read successfully",
		zap.String("mount", kv.mount),
		zap.String("path", path),
		zap.Int("fields", len(secret.Data)))

	return secret.Data, nil
}

// Put writes a secret to KV v2 WITH IMMEDIATE VERIFICATION
// This implements write-then-verify pattern to catch storage backend failures
//
// CRITICAL P0: The verification catches:
// - Vault storage backend failures (write succeeds but data doesn't persist)
// - Network partitions (write appears successful but isn't replicated)
// - Path mismatches (write to one path, read from another due to API inconsistency)
//
// Example:
//
//	data := map[string]interface{}{"password": "secret", "created_at": "2025-01-24"}
//	err := kv.Put(ctx, "eos/bootstrap", data)
//	// Writes to secret/data/eos/bootstrap AND verifies it's readable
func (kv *EosKVv2Store) Put(ctx context.Context, path string, data map[string]interface{}) error {
	kv.log.Info("Writing KV v2 secret",
		zap.String("mount", kv.mount),
		zap.String("path", path),
		zap.Int("fields", len(data)))

	// INTERVENE: Write
	_, err := kv.client.KVv2(kv.mount).Put(ctx, path, data)
	if err != nil {
		return cerr.Wrapf(err, "write %s/%s", kv.mount, path)
	}

	kv.log.Debug("Write operation completed, starting verification...")

	// EVALUATE: Read back immediately
	readBack, verifyErr := kv.Get(ctx, path)
	if verifyErr != nil {
		kv.log.Error("Write verification failed - cannot read back secret",
			zap.Error(verifyErr),
			zap.String("mount", kv.mount),
			zap.String("path", path))
		kv.log.Error("")
		kv.log.Error("  This indicates one of:")
		kv.log.Error("    • Vault storage backend failure (write not persisted)")
		kv.log.Error("    • Network partition (write not replicated)")
		kv.log.Error("    • Path mismatch bug (write/read use different paths)")
		kv.log.Error("")
		return cerr.Wrapf(verifyErr, "wrote %s/%s but failed to read back", kv.mount, path)
	}

	// Verify all fields were persisted
	for key := range data {
		if _, exists := readBack[key]; !exists {
			kv.log.Error("Write verification failed - field missing after write",
				zap.String("missing_field", key),
				zap.String("mount", kv.mount),
				zap.String("path", path),
				zap.Any("expected_fields", getMapKeys(data)),
				zap.Any("actual_fields", getMapKeys(readBack)))
			return cerr.Newf("wrote %s/%s but field '%s' missing in read-back (expected %v, got %v)",
				kv.mount, path, key, getMapKeys(data), getMapKeys(readBack))
		}
	}

	kv.log.Info("Write verification successful",
		zap.String("mount", kv.mount),
		zap.String("path", path),
		zap.Int("fields_verified", len(data)))

	return nil
}

// Delete removes a secret from KV v2
// Path should NOT include mount or /data/ prefix
func (kv *EosKVv2Store) Delete(ctx context.Context, path string) error {
	kv.log.Info("Deleting KV v2 secret",
		zap.String("mount", kv.mount),
		zap.String("path", path))

	err := kv.client.KVv2(kv.mount).Delete(ctx, path)
	if err != nil {
		return cerr.Wrapf(err, "delete %s/%s", kv.mount, path)
	}

	kv.log.Info("KV v2 secret deleted successfully",
		zap.String("mount", kv.mount),
		zap.String("path", path))

	return nil
}

// getMapKeys extracts keys from a map for logging (helper function)
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
