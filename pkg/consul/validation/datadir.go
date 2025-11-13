// pkg/consul/validation/datadir.go
//
// Consul data directory validation for bootstrap token recovery.
//
// This package validates that a directory is a valid Consul data directory before
// writing the ACL bootstrap reset file. Prevents writing reset files to incorrect
// locations which could cause bootstrap failures or data corruption.
//
// Last Updated: 2025-10-25

package validation

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateConsulDataDir validates that a directory is a valid Consul data directory.
//
// A valid Consul data directory must:
//  1. Exist and be a directory
//  2. Be readable and writable by the current process
//  3. Contain a raft/ subdirectory (required for Consul server data)
//
// Optional checks (warnings only, not failures):
//   - raft/raft.db file exists
//   - snapshots/ directory exists
//   - checkpoint-signature file exists
//
// Parameters:
//   - rc: Runtime context for logging
//   - path: Path to validate as Consul data directory
//
// Returns:
//   - error: If validation fails (directory invalid for Consul use)
//   - nil: If directory is valid
//
// Example:
//
//	if err := validation.ValidateConsulDataDir(rc, "/opt/consul"); err != nil {
//	    return fmt.Errorf("invalid Consul data directory: %w", err)
//	}
func ValidateConsulDataDir(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating Consul data directory", zap.String("path", path))

	// Check 1: Path exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("data directory does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat data directory %s: %w", path, err)
	}

	// Check 2: Is a directory
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}

	logger.Debug("Data directory exists and is a directory")

	// Check 3: Readable and writable
	if err := checkDirectoryPermissions(rc, path); err != nil {
		return fmt.Errorf("data directory permissions invalid: %w", err)
	}

	logger.Debug("Data directory has correct permissions")

	// Check 4: Contains raft/ subdirectory (REQUIRED for Consul server)
	raftPath := filepath.Join(path, "raft")
	if _, err := os.Stat(raftPath); os.IsNotExist(err) {
		return fmt.Errorf("data directory does not contain raft/ subdirectory (required for Consul server): %s", path)
	}

	logger.Debug("Data directory contains raft/ subdirectory")

	// Optional checks (warnings only)
	performOptionalValidation(rc, path)

	logger.Info("Data directory validation passed",
		zap.String("path", path))

	return nil
}

// checkDirectoryPermissions verifies the directory is readable and writable.
func checkDirectoryPermissions(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Test read access
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("directory not readable: %w", err)
	}

	logger.Debug("Directory is readable",
		zap.String("path", path),
		zap.Int("entry_count", len(entries)))

	// Test write access by creating a temp file
	testFile := filepath.Join(path, ".eos-write-test")
	err = os.WriteFile(testFile, []byte("test"), shared.SecretFilePerm)
	if err != nil {
		return fmt.Errorf("directory not writable: %w", err)
	}

	// Clean up test file
	_ = os.Remove(testFile)

	logger.Debug("Directory is writable", zap.String("path", path))

	return nil
}

// performOptionalValidation performs non-critical validation checks.
// These checks warn but don't fail if they don't pass.
func performOptionalValidation(rc *eos_io.RuntimeContext, path string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for raft.db (indicates active Raft database)
	raftDBPath := filepath.Join(path, "raft", "raft.db")
	if _, err := os.Stat(raftDBPath); os.IsNotExist(err) {
		logger.Warn("raft.db not found (directory may be empty or new)",
			zap.String("expected_path", raftDBPath))
	} else {
		logger.Debug("raft.db found", zap.String("path", raftDBPath))
	}

	// Check for snapshots/ directory
	snapshotsPath := filepath.Join(path, "raft", "snapshots")
	if _, err := os.Stat(snapshotsPath); os.IsNotExist(err) {
		logger.Debug("snapshots/ directory not found (normal for new installations)",
			zap.String("expected_path", snapshotsPath))
	} else {
		logger.Debug("snapshots/ directory found", zap.String("path", snapshotsPath))
	}

	// Check for checkpoint-signature
	checkpointPath := filepath.Join(path, "checkpoint-signature")
	if _, err := os.Stat(checkpointPath); os.IsNotExist(err) {
		logger.Debug("checkpoint-signature not found (normal)",
			zap.String("expected_path", checkpointPath))
	} else {
		logger.Debug("checkpoint-signature found", zap.String("path", checkpointPath))
	}

	// Check for serf/ directory (local serf state)
	serfPath := filepath.Join(path, "serf")
	if _, err := os.Stat(serfPath); os.IsNotExist(err) {
		logger.Debug("serf/ directory not found (normal for server-only mode)",
			zap.String("expected_path", serfPath))
	} else {
		logger.Debug("serf/ directory found", zap.String("path", serfPath))
	}
}
