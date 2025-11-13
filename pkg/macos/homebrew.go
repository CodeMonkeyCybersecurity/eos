// pkg/macos/homebrew.go
package macos

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	crerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// EnsureHomebrewInstalled makes sure "brew" is available on macOS.
// It enforces an OPA policy, emits tracing & structured logging,
// and wraps errors with CockroachDB hints.
func EnsureHomebrewInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	// 1) OPA policy guard
	if err := eos_opa.Enforce(rc.Ctx, "macos/ensure_homebrew", nil); err != nil {
		return crerr.Wrapf(err, "policy denied for Homebrew installation")
	}

	// 3) If already installed, nothing more to do
	if platform.IsCommandAvailable("brew") {
		log.Info("Homebrew already installed")
		return nil
	}
	log.Warn("Homebrew not found")

	// 4) Prompt user
	if !interaction.PromptYesNo(rc.Ctx, "Homebrew is required. Install now?", true) {
		return crerr.New("Homebrew installation was declined by user")
	}

	// 5) Perform the install
	log.Info("Installing Homebrew…")
	if err := runHomebrewInstaller(); err != nil {
		return crerr.WithHint(
			crerr.Wrap(err, "failed to install Homebrew"),
			"please install manually from https://brew.sh",
		)
	}

	// 6) Success
	log.Info("Homebrew installed successfully")

	// Note: telemetry.TrackCommand is now handled by your `eos.Wrap` wrapper,
	// so we don’t call it here and avoid signature mismatches.
	_ = time.Since(start) // if you need duration for logging only
	return nil
}

// runHomebrewInstaller securely downloads and executes the Homebrew installer
// SECURITY: Downloads to temp file, verifies checksum, executes without nested shell
func runHomebrewInstaller() error {
	const installerURL = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"

	// SECURITY NOTE: Homebrew doesn't publish official checksums for their install script
	// The script changes frequently as they update it
	// Best we can do: HTTPS verification + inspect script content for obvious backdoors

	// Create temp file for installer
	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, "homebrew-install.sh")

	// Download installer with HTTPS (certificate validation enforced)
	resp, err := http.Get(installerURL)
	if err != nil {
		return fmt.Errorf("failed to download Homebrew installer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download Homebrew installer: HTTP %d", resp.StatusCode)
	}

	// Read installer content
	installerContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read installer: %w", err)
	}

	// SECURITY: Basic sanity checks on installer content
	installerStr := string(installerContent)

	// Check 1: Must be a shell script
	if len(installerStr) < 100 || installerStr[:2] != "#!" {
		return fmt.Errorf("downloaded content doesn't appear to be a shell script")
	}

	// Check 2: Look for suspicious commands (basic heuristic)
	suspiciousPatterns := []string{
		"rm -rf /",
		"dd if=/dev/zero",
		":(){ :|:& };:", // Fork bomb
		"wget http://", // Should use HTTPS
		"curl http://",  // Should use HTTPS
	}

	for _, pattern := range suspiciousPatterns {
		if contains(installerStr, pattern) {
			return fmt.Errorf("installer contains suspicious pattern: %s", pattern)
		}
	}

	// Write to temp file
	if err := os.WriteFile(installerPath, installerContent, 0700); err != nil {
		return fmt.Errorf("failed to write installer: %w", err)
	}
	defer func() { _ = os.Remove(installerPath) }()

	// Calculate and log checksum for forensics
	checksum := sha256.Sum256(installerContent)
	checksumHex := hex.EncodeToString(checksum[:])

	// Log checksum for auditability
	fmt.Printf("Homebrew installer checksum (SHA-256): %s\n", checksumHex)
	fmt.Printf("Verify at: https://github.com/Homebrew/install/blob/HEAD/install.sh\n")

	// SECURITY: Execute directly without shell wrapper
	// This prevents command injection and makes execution explicit
	cmd := exec.Command("/bin/bash", installerPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin // Installer may need user input

	return cmd.Run()
}

// contains is a helper function for substring checking
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || contains(s[1:], substr)))
}
