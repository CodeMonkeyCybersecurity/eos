package saltstack

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// KeyManager handles Salt minion key management operations
type KeyManager struct {
	client *Client
}

// NewKeyManager creates a new KeyManager instance
func NewKeyManager(logger otelzap.LoggerWithCtx) *KeyManager {
	return &KeyManager{
		client: NewClient(logger),
	}
}

// KeyDeletionResult represents the result of a key deletion operation
type KeyDeletionResult struct {
	DeletedKeys []string `json:"deleted_keys"`
	ErrorKeys   []string `json:"error_keys"`
	Message     string   `json:"message"`
}

// DeleteKeysOptions contains options for key deletion
type DeleteKeysOptions struct {
	Keys    []string
	Pattern string
	Force   bool
	DryRun  bool
}

// DeleteKeysWithOptions deletes specific Salt minion keys
// This follows the Assess → Intervene → Evaluate pattern
func (km *KeyManager) DeleteKeysWithOptions(rc *eos_io.RuntimeContext, opts *DeleteKeysOptions) (*KeyDeletionResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing Salt key deletion prerequisites",
		zap.Strings("keys", opts.Keys),
		zap.String("pattern", opts.Pattern),
		zap.Bool("dry_run", opts.DryRun))

	if len(opts.Keys) == 0 && opts.Pattern == "" {
		return nil, fmt.Errorf("must specify either keys or pattern for deletion")
	}

	result := &KeyDeletionResult{
		DeletedKeys: make([]string, 0),
		ErrorKeys:   make([]string, 0),
	}

	// Check if salt-key command is available
	if _, err := exec.LookPath("salt-key"); err != nil {
		return nil, fmt.Errorf("salt-key command not found: %w", err)
	}

	// List existing keys first to verify what will be deleted
	if existingKeys, err := km.listKeys(rc.Ctx); err != nil {
		logger.Warn("Failed to list existing keys", zap.Error(err))
	} else {
		logger.Debug("Existing keys before deletion", zap.Strings("keys", existingKeys))
	}

	// INTERVENE - Perform key deletion
	logger.Info("Executing Salt key deletion")

	if opts.DryRun {
		// For dry run, just simulate what would be deleted
		if opts.Pattern != "" {
			result.Message = fmt.Sprintf("DRY RUN: Would delete keys matching pattern: %s", opts.Pattern)
		} else {
			result.Message = fmt.Sprintf("DRY RUN: Would delete specific keys: %s", strings.Join(opts.Keys, ", "))
		}
		return result, nil
	}

	if opts.Pattern != "" {
		// Delete keys by pattern
		if err := km.deleteKeysByPattern(rc.Ctx, opts.Pattern); err != nil {
			return nil, fmt.Errorf("failed to delete keys by pattern: %w", err)
		}
		result.Message = fmt.Sprintf("Deleted keys matching pattern: %s", opts.Pattern)
	} else {
		// Delete specific keys
		for _, key := range opts.Keys {
			if err := km.deleteSpecificKey(rc.Ctx, key); err != nil {
				logger.Warn("Failed to delete key", zap.String("key", key), zap.Error(err))
				result.ErrorKeys = append(result.ErrorKeys, key)
			} else {
				result.DeletedKeys = append(result.DeletedKeys, key)
			}
		}
		result.Message = fmt.Sprintf("Deleted %d keys, %d errors", len(result.DeletedKeys), len(result.ErrorKeys))
	}

	// EVALUATE - Verify deletion succeeded
	logger.Info("Verifying Salt key deletion")

	// List keys after deletion to verify
	if remainingKeys, err := km.listKeys(rc.Ctx); err != nil {
		logger.Warn("Failed to list remaining keys", zap.Error(err))
	} else {
		logger.Debug("Remaining keys after deletion", zap.Strings("keys", remainingKeys))
	}

	logger.Info("Salt key deletion completed",
		zap.Int("deleted_count", len(result.DeletedKeys)),
		zap.Int("error_count", len(result.ErrorKeys)))

	return result, nil
}

// deleteKeysByPattern deletes keys matching a pattern
func (km *KeyManager) deleteKeysByPattern(ctx context.Context, pattern string) error {
	logger := otelzap.Ctx(ctx)

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-key",
		Args:    []string{"-d", pattern, "-y"},
		Capture: true,
	})

	if err != nil {
		logger.Error("Failed to delete keys by pattern",
			zap.String("pattern", pattern),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("deleting keys by pattern %s: %w", pattern, err)
	}

	logger.Debug("Deleted keys by pattern",
		zap.String("pattern", pattern),
		zap.String("output", output))

	return nil
}

// deleteSpecificKey deletes a specific key
func (km *KeyManager) deleteSpecificKey(ctx context.Context, key string) error {
	logger := otelzap.Ctx(ctx)

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-key",
		Args:    []string{"-d", key, "-y"},
		Capture: true,
	})

	if err != nil {
		logger.Error("Failed to delete specific key",
			zap.String("key", key),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("deleting key %s: %w", key, err)
	}

	logger.Debug("Deleted specific key",
		zap.String("key", key),
		zap.String("output", output))

	return nil
}

// listKeys lists all accepted Salt minion keys
func (km *KeyManager) listKeys(ctx context.Context) ([]string, error) {
	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-key",
		Args:    []string{"-l", "accepted", "--out=json"},
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("listing salt keys: %w", err)
	}

	// Parse the JSON output to extract key names
	// For now, just return the raw output split by lines
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var keys []string
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "}") {
			keys = append(keys, strings.TrimSpace(line))
		}
	}

	return keys, nil
}

// Legacy compatibility functions for existing code

// NewSaltClient creates a new Salt client (legacy compatibility)
func NewSaltClient(logger otelzap.LoggerWithCtx) *KeyManager {
	return NewKeyManager(logger)
}

// Legacy methods for backward compatibility

// DeleteKeys is a legacy method for the original salt_key.go
func (km *KeyManager) DeleteKeys(ctx context.Context, keys []string) (interface{}, error) {
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	opts := &DeleteKeysOptions{
		Keys:   keys,
		Force:  true,
		DryRun: false,
	}
	result, err := km.DeleteKeysWithOptions(rc, opts)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteKeyPattern is a legacy wrapper for the new DeleteKeys method
func (km *KeyManager) DeleteKeyPattern(ctx context.Context, pattern string) (interface{}, error) {
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	opts := &DeleteKeysOptions{
		Pattern: pattern,
		Force:   true,
		DryRun:  false,
	}
	result, err := km.DeleteKeysWithOptions(rc, opts)
	if err != nil {
		return nil, err
	}
	return result, nil
}
