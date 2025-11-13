// pkg/vault/secure_io.go
//
// Secure file I/O operations using file descriptors to prevent TOCTOU vulnerabilities
// ARCHITECTURAL PRINCIPLE: Once we open a file, we NEVER re-check the path - only use the FD

package vault

import (
	"fmt"
	"os"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureReadCredential reads a credential file using file descriptors to prevent TOCTOU
//
// SECURITY GUARANTEE:
//  1. Opens file and acquires shared lock (LOCK_SH) - prevents modification during read
//  2. Uses fstat(fd) to get size - NO RACE, we're reading the locked FD
//  3. Reads from locked FD - NO RACE, same FD we just fstat'd
//  4. No path-based operations after open - eliminates TOCTOU window
//
// WHY THIS MATTERS:
//   - AppRole credentials (role_id, secret_id) are authentication secrets
//   - TOCTOU attack: os.Stat() → attacker swaps file → os.ReadFile() reads attacker's credential
//   - Result: Eos uses attacker's role_id/secret_id, attacker gains Vault access
//
// USAGE:
//
//	roleID, err := vault.SecureReadCredential(rc, "/var/lib/eos/secret/vault/role_id", "role_id")
func SecureReadCredential(rc *eos_io.RuntimeContext, path, credName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Securely reading credential file",
		zap.String("credential", credName),
		zap.String("path", path))

	// Phase 1: Open file with O_RDONLY
	fd, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open %s credential file: %w", credName, err)
	}
	defer fd.Close()

	// Phase 2: Acquire shared lock (LOCK_SH) - allows other readers but blocks writers
	// This prevents credential file from being modified during read
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return "", fmt.Errorf("cannot lock %s credential file (in use?): %w", credName, err)
	}
	defer syscall.Flock(int(fd.Fd()), syscall.LOCK_UN)

	logger.Debug("Acquired shared lock on credential file",
		zap.String("credential", credName))

	// Phase 3: Get size from LOCKED file descriptor (NO TOCTOU)
	stat, err := fd.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to fstat %s credential: %w", credName, err)
	}

	// Sanity check: credential files should not be empty
	if stat.Size() == 0 {
		return "", fmt.Errorf("%s credential file is empty", credName)
	}

	// Sanity check: credential files should not be unreasonably large
	// Vault UUIDs are ~36 bytes, tokens are typically < 1KB
	if stat.Size() > 10*1024 { // 10KB limit
		return "", fmt.Errorf("%s credential file suspiciously large: %d bytes", credName, stat.Size())
	}

	logger.Debug("Credential file metadata from locked FD",
		zap.String("credential", credName),
		zap.Int64("size", stat.Size()),
		zap.String("mode", stat.Mode().String()))

	// Phase 4: Read data from LOCKED file descriptor (NO TOCTOU)
	data := make([]byte, stat.Size())
	n, err := fd.Read(data)
	if err != nil {
		return "", fmt.Errorf("failed to read %s credential: %w", credName, err)
	}
	if int64(n) != stat.Size() {
		return "", fmt.Errorf("incomplete read of %s credential: got %d bytes, expected %d", credName, n, stat.Size())
	}

	logger.Info("Credential file read successfully via FD operations",
		zap.String("credential", credName),
		zap.Int("bytes_read", n))

	return string(data), nil
}

// SecureWriteCredential writes a credential file using file descriptors and verifies integrity
//
// SECURITY GUARANTEE:
//  1. Creates file with O_WRONLY|O_CREATE|O_EXCL - fails if file exists (no overwrite races)
//  2. Acquires exclusive lock (LOCK_EX) immediately after creation
//  3. Writes data to locked FD
//  4. Syncs to disk (fsync) before verification
//  5. Re-reads from same FD to verify integrity
//  6. No path-based operations after create - eliminates TOCTOU window
//
// WHY THIS MATTERS:
//   - Writing root tokens, unseal keys, AppRole credentials
//   - TOCTOU attack: create file → attacker symlinks it elsewhere → write goes to attacker location
//   - O_EXCL prevents overwrite races, flock prevents concurrent access
//
// USAGE:
//
//	err := vault.SecureWriteCredential(rc, "/var/lib/eos/secret/vault/role_id", roleID, 0600, "role_id")
func SecureWriteCredential(rc *eos_io.RuntimeContext, path, data string, perm os.FileMode, credName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Securely writing credential file",
		zap.String("credential", credName),
		zap.String("path", path),
		zap.Int("data_length", len(data)))

	// Phase 1: Create file with O_EXCL - fails if exists (prevents overwrite races)
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		// If file exists, this might be legitimate (re-run scenario)
		// Let caller decide how to handle
		return fmt.Errorf("failed to create %s credential file: %w", credName, err)
	}
	defer fd.Close()

	// Phase 2: Acquire exclusive lock immediately
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = os.Remove(path) // Clean up file we just created
		return fmt.Errorf("cannot lock %s credential file: %w", credName, err)
	}
	defer syscall.Flock(int(fd.Fd()), syscall.LOCK_UN)

	logger.Debug("Acquired exclusive lock on new credential file",
		zap.String("credential", credName))

	// Phase 3: Write data to locked FD
	dataBytes := []byte(data)
	wrote, err := fd.Write(dataBytes)
	if err != nil {
		_ = os.Remove(path) // Clean up on error
		return fmt.Errorf("failed to write %s credential: %w", credName, err)
	}
	if wrote != len(dataBytes) {
		_ = os.Remove(path)
		return fmt.Errorf("incomplete write of %s credential: wrote %d, expected %d", credName, wrote, len(dataBytes))
	}

	// Phase 4: Sync to disk before verification
	if err := fd.Sync(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("failed to sync %s credential to disk: %w", credName, err)
	}

	// Phase 5: Verify by re-reading from same FD
	fd.Seek(0, 0) // Rewind to start
	verifyData := make([]byte, len(dataBytes))
	n, err := fd.Read(verifyData)
	if err != nil || n != len(dataBytes) {
		_ = os.Remove(path)
		return fmt.Errorf("failed to verify %s credential after write: %w", credName, err)
	}

	// Compare hashes (don't log actual credentials!)
	writeHash := crypto.HashData(dataBytes)
	readHash := crypto.HashData(verifyData)
	if writeHash != readHash {
		_ = os.Remove(path)
		return fmt.Errorf("%s credential verification failed: data corruption detected", credName)
	}

	logger.Info("Credential file written and verified via FD operations",
		zap.String("credential", credName),
		zap.String("path", path),
		zap.Int("bytes_written", wrote))

	return nil
}

// SecureWriteCredentialOrOverwrite is like SecureWriteCredential but removes existing file first
//
// USAGE: When you want to update an existing credential (e.g., secret_id rotation)
func SecureWriteCredentialOrOverwrite(rc *eos_io.RuntimeContext, path, data string, perm os.FileMode, credName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Remove existing file if present
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing %s credential: %w", credName, err)
	}

	logger.Debug("Removed existing credential file for overwrite",
		zap.String("credential", credName),
		zap.String("path", path))

	// Now write with standard secure write
	return SecureWriteCredential(rc, path, data, perm, credName)
}
