// pkg/vault/binary_cleanup.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BinaryLocation represents a discovered vault binary
type BinaryLocation struct {
	Path       string
	Version    string
	Size       int64
	IsSymlink  bool
	LinkTarget string
}

// CleanupDuplicateBinaries finds and removes duplicate vault binaries
// This implements P1 requirement from audit: cleanup duplicate binaries
func CleanupDuplicateBinaries(rc *eos_io.RuntimeContext, keepPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Searching for duplicate Vault binaries")

	// ASSESS: Find all vault binaries
	binaries, err := findVaultBinaries(rc)
	if err != nil {
		return fmt.Errorf("failed to find vault binaries: %w", err)
	}

	if len(binaries) == 0 {
		log.Warn("No Vault binaries found on system")
		return nil
	}

	log.Info("Found Vault binaries",
		zap.Int("count", len(binaries)),
		zap.String("keep_path", keepPath))

	// Display findings
	displayBinaryFindings(binaries, keepPath)

	// INTERVENE: Remove duplicates
	removed, err := removeDuplicates(rc, binaries, keepPath)
	if err != nil {
		return fmt.Errorf("failed to remove duplicates: %w", err)
	}

	// EVALUATE: Report results
	log.Info("Binary cleanup completed",
		zap.Int("total_found", len(binaries)),
		zap.Int("removed", removed),
		zap.Int("kept", len(binaries)-removed))

	return nil
}

// FindVaultBinaries searches common locations for vault binaries (exported)
func FindVaultBinaries(rc *eos_io.RuntimeContext) ([]BinaryLocation, error) {
	return findVaultBinaries(rc)
}

// findVaultBinaries searches common locations for vault binaries
func findVaultBinaries(rc *eos_io.RuntimeContext) ([]BinaryLocation, error) {
	log := otelzap.Ctx(rc.Ctx)
	var binaries []BinaryLocation

	// Common installation locations
	searchPaths := []string{
		"/usr/bin/vault",
		"/usr/local/bin/vault",
		"/opt/vault/bin/vault",
		"/snap/bin/vault",
		shared.VaultBinaryPath, // /usr/local/bin/vault
	}

	// Also search PATH
	pathBinary, err := exec.LookPath("vault")
	if err == nil && pathBinary != "" {
		searchPaths = append(searchPaths, pathBinary)
	}

	// Deduplicate search paths
	seen := make(map[string]bool)
	uniquePaths := []string{}
	for _, path := range searchPaths {
		// Resolve symlinks to real path for comparison
		realPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			realPath = path // Use original if can't resolve
		}

		if !seen[realPath] {
			seen[realPath] = true
			uniquePaths = append(uniquePaths, path)
		}
	}

	log.Debug("Searching for vault binaries", zap.Strings("paths", uniquePaths))

	// Check each location
	for _, path := range uniquePaths {
		info, err := os.Lstat(path) // Use Lstat to detect symlinks
		if err != nil {
			if !os.IsNotExist(err) {
				log.Debug("Error checking path", zap.String("path", path), zap.Error(err))
			}
			continue
		}

		binary := BinaryLocation{
			Path:      path,
			Size:      info.Size(),
			IsSymlink: info.Mode()&os.ModeSymlink != 0,
		}

		// Resolve symlink target
		if binary.IsSymlink {
			target, err := os.Readlink(path)
			if err == nil {
				binary.LinkTarget = target
			}
		}

		// Get version
		version, err := getVaultVersion(rc, path)
		if err == nil {
			binary.Version = version
		}

		binaries = append(binaries, binary)
		log.Debug("Found vault binary",
			zap.String("path", path),
			zap.String("version", binary.Version),
			zap.Bool("symlink", binary.IsSymlink))
	}

	return binaries, nil
}

// getVaultVersion executes vault --version to get version string
func getVaultVersion(rc *eos_io.RuntimeContext, binaryPath string) (string, error) {
	cmd := exec.CommandContext(rc.Ctx, binaryPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Parse "Vault vX.Y.Z" format
	version := strings.TrimSpace(string(output))
	return version, nil
}

// displayBinaryFindings shows all discovered binaries to the user
func displayBinaryFindings(binaries []BinaryLocation, keepPath string) {
	fmt.Println("\n Vault Binary Discovery Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for i, binary := range binaries {
		fmt.Printf("\n%d. %s\n", i+1, binary.Path)

		if binary.Path == keepPath {
			fmt.Println("   Status:  PRIMARY (will be kept)")
		} else {
			fmt.Println("   Status: DUPLICATE (will be removed)")
		}

		if binary.Version != "" {
			fmt.Printf("   Version: %s\n", binary.Version)
		}

		if binary.IsSymlink {
			fmt.Printf("   Type: Symlink → %s\n", binary.LinkTarget)
		} else {
			fmt.Printf("   Type: Regular file (%d bytes)\n", binary.Size)
		}
	}

	fmt.Println()
}

// removeDuplicates removes all binaries except the one at keepPath
func removeDuplicates(rc *eos_io.RuntimeContext, binaries []BinaryLocation, keepPath string) (int, error) {
	log := otelzap.Ctx(rc.Ctx)
	removed := 0

	// Resolve keepPath to real path for comparison
	keepRealPath, err := filepath.EvalSymlinks(keepPath)
	if err != nil {
		keepRealPath = keepPath
	}

	for _, binary := range binaries {
		// Resolve binary path to real path
		binaryRealPath, err := filepath.EvalSymlinks(binary.Path)
		if err != nil {
			binaryRealPath = binary.Path
		}

		// Skip if this is the binary we want to keep
		if binary.Path == keepPath || binaryRealPath == keepRealPath {
			log.Info("Keeping primary binary",
				zap.String("path", binary.Path),
				zap.String("version", binary.Version))
			continue
		}

		// Remove duplicate
		log.Info("Removing duplicate binary",
			zap.String("path", binary.Path),
			zap.String("version", binary.Version),
			zap.Bool("symlink", binary.IsSymlink))

		if err := os.Remove(binary.Path); err != nil {
			log.Warn("Failed to remove duplicate binary",
				zap.String("path", binary.Path),
				zap.Error(err))
			continue
		}

		fmt.Printf("  Removed: %s\n", binary.Path)
		removed++
	}

	return removed, nil
}

// VerifyBinaryIntegrity checks that the vault binary is properly installed
func VerifyBinaryIntegrity(rc *eos_io.RuntimeContext, binaryPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Verifying binary integrity", zap.String("path", binaryPath))

	// Check file exists
	info, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	// Check it's executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("binary is not executable (mode: %o)", info.Mode().Perm())
	}

	// Check it's not empty
	if info.Size() == 0 {
		return fmt.Errorf("binary is empty (0 bytes)")
	}

	// Try to execute --version
	version, err := getVaultVersion(rc, binaryPath)
	if err != nil {
		return fmt.Errorf("binary failed to execute: %w", err)
	}

	log.Info("Binary integrity verified",
		zap.String("path", binaryPath),
		zap.String("version", version),
		zap.Int64("size", info.Size()))

	return nil
}

// RecommendBinaryCleanup analyzes the system and recommends cleanup actions
func RecommendBinaryCleanup(rc *eos_io.RuntimeContext) ([]string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Analyzing system for binary cleanup recommendations")

	binaries, err := findVaultBinaries(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries: %w", err)
	}

	var recommendations []string

	if len(binaries) == 0 {
		recommendations = append(recommendations, "No Vault binaries found - run 'eos create vault' to install")
		return recommendations, nil
	}

	if len(binaries) == 1 {
		recommendations = append(recommendations, "Only one Vault binary found - no cleanup needed")
		return recommendations, nil
	}

	// Multiple binaries found
	recommendations = append(recommendations,
		fmt.Sprintf("Found %d Vault binaries on system:", len(binaries)))

	for _, binary := range binaries {
		recommendations = append(recommendations,
			fmt.Sprintf("  - %s (%s)", binary.Path, binary.Version))
	}

	recommendations = append(recommendations, "")
	recommendations = append(recommendations,
		fmt.Sprintf("Recommended action: Keep %s, remove others", shared.VaultBinaryPath))
	recommendations = append(recommendations,
		"Run: sudo eos repair vault --cleanup-binaries")

	return recommendations, nil
}
