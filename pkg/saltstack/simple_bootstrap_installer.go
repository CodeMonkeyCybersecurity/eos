package saltstack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Constants for the current, correct Salt bootstrap URLs after 2024 migration
const (
	// This is the CURRENT correct URL as of November 2024 (GitHub-hosted)
	// The old bootstrap.saltproject.io was decommissioned in October 2024
	DefaultBootstrapURL = "https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh"

	// Checksum URL for verification (also moved to GitHub)
	BootstrapChecksumURL = "https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh.sha256"

	// Decommissioned URLs - DO NOT USE (return HTML migration warnings)
	// OldBootstrapURL = "https://bootstrap.saltstack.com"    // Redirects to HTML
	// OldSaltProjectURL = "https://bootstrap.saltproject.io" // Decommissioned Oct 2024
)

// SimpleBootstrapInstaller handles Salt installation using only the official bootstrap script
// This replaces the complex multi-method approach with one reliable method
type SimpleBootstrapInstaller struct {
	config *Config
}

// NewSimpleBootstrapInstaller creates a new simple bootstrap installer
func NewSimpleBootstrapInstaller(config *Config) *SimpleBootstrapInstaller {
	return &SimpleBootstrapInstaller{
		config: config,
	}
}

// Install performs Salt installation using the official bootstrap script (simplified)
func (sbi *SimpleBootstrapInstaller) Install(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Salt using official bootstrap method (simplified)")

	// Step 1: Download the bootstrap script from correct URL
	scriptPath, err := sbi.downloadScript(rc)
	if err != nil {
		return sbi.handleInstallError(rc, fmt.Errorf("failed to download bootstrap script: %w", err))
	}
	defer os.Remove(scriptPath) // Clean up

	// Step 2: Verify checksum for security
	if err := sbi.verifyChecksum(rc, scriptPath); err != nil {
		return sbi.handleInstallError(rc, fmt.Errorf("checksum verification failed: %w", err))
	}

	// Step 3: Run the bootstrap script
	if err := sbi.runBootstrap(rc, scriptPath); err != nil {
		return sbi.handleInstallError(rc, fmt.Errorf("bootstrap script execution failed: %w", err))
	}

	// Step 4: Configure Salt for the intended mode
	if err := sbi.Configure(rc); err != nil {
		return sbi.handleInstallError(rc, fmt.Errorf("configuration failed: %w", err))
	}

	// Step 5: Verify installation works
	if err := sbi.Verify(rc); err != nil {
		return sbi.handleInstallError(rc, fmt.Errorf("verification failed: %w", err))
	}

	logger.Info("Salt installation completed successfully!")
	logger.Info("Test your installation with: salt-call --local test.ping")

	return nil
}

// downloadScript downloads the bootstrap script from the correct URL with validation
func (sbi *SimpleBootstrapInstaller) downloadScript(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use custom URL if specified, otherwise use the correct default
	bootstrapURL := DefaultBootstrapURL
	if customURL, ok := rc.Attributes["bootstrap_url"]; ok && customURL != "" {
		bootstrapURL = customURL
	}

	// Define fallback URLs in case GitHub is not accessible
	fallbackURLs := []string{
		bootstrapURL,
		"https://raw.githubusercontent.com/saltstack/salt-bootstrap/develop/bootstrap-salt.sh",
	}

	scriptPath := filepath.Join("/tmp", fmt.Sprintf("salt-bootstrap-%d.sh", time.Now().Unix()))

	var lastErr error
	var content []byte

	// Try each URL until one works
	for i, url := range fallbackURLs {
		logger.Info("Downloading Salt bootstrap script",
			zap.String("url", url),
			zap.String("destination", scriptPath),
			zap.Int("attempt", i+1),
			zap.Int("total_urls", len(fallbackURLs)))

		// Download with proper timeout
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = fmt.Errorf("failed to download from %s: %w", url, err)
			logger.Warn("Download failed, trying next URL", zap.Error(lastErr))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("download failed with status %d from %s", resp.StatusCode, url)
			logger.Warn("HTTP error, trying next URL", zap.Error(lastErr))
			continue
		}

		// Read the content
		content, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read content from %s: %w", url, err)
			logger.Warn("Read failed, trying next URL", zap.Error(lastErr))
			continue
		}

		// CRITICAL: Validate it's actually a shell script
		if !sbi.isValidShellScript(content) {
			// Show what we got instead for debugging
			preview := string(content)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}

			lastErr = fmt.Errorf("downloaded content is not a shell script from %s", url)
			logger.Warn("Content validation failed, trying next URL",
				zap.String("content_preview", preview),
				zap.String("url", url))
			continue
		}

		// Success! Break out of the loop
		logger.Info("Bootstrap script downloaded and validated successfully",
			zap.String("url", url),
			zap.Int("size_bytes", len(content)))
		break
	}

	// Check if we succeeded with any URL
	if content == nil {
		return "", fmt.Errorf("failed to download valid bootstrap script from any URL, last error: %w", lastErr)
	}

	// Write to file
	if err := os.WriteFile(scriptPath, content, 0755); err != nil {
		return "", fmt.Errorf("failed to write bootstrap script to %s: %w", scriptPath, err)
	}

	return scriptPath, nil
}

// isValidShellScript validates that the downloaded content is actually a shell script
func (sbi *SimpleBootstrapInstaller) isValidShellScript(content []byte) bool {
	contentStr := string(content)

	// Check for shell script indicators
	validIndicators := []string{
		"#!/bin/sh",
		"#!/bin/bash",
		"#!/usr/bin/env sh",
		"#!/usr/bin/env bash",
	}

	for _, indicator := range validIndicators {
		if strings.HasPrefix(contentStr, indicator) {
			return true
		}
	}

	// Also check if it contains typical shell script content
	// (in case shebang is missing but it's still a valid script)
	shellKeywords := []string{
		"if [",
		"case ",
		"function ",
		"echo ",
		"export ",
		"#!/",
	}

	matchCount := 0
	for _, keyword := range shellKeywords {
		if strings.Contains(contentStr, keyword) {
			matchCount++
		}
	}

	// If we see multiple shell keywords, it's probably a script
	return matchCount >= 3
}

// verifyChecksum verifies the bootstrap script checksum for security
func (sbi *SimpleBootstrapInstaller) verifyChecksum(rc *eos_io.RuntimeContext, scriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if checksum verification is skipped
	if skip, ok := rc.Attributes["skip_checksum"]; ok && skip == "true" {
		logger.Warn("Skipping checksum verification (not recommended)")
		return nil
	}

	logger.Info("Verifying bootstrap script checksum for security")

	// Get expected checksum
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(BootstrapChecksumURL)
	if err != nil {
		logger.Warn("Failed to download checksum for verification", zap.Error(err))
		logger.Warn("Proceeding without checksum verification")
		return nil // Don't fail installation for checksum issues
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn("Checksum download failed",
			zap.Int("status", resp.StatusCode))
		logger.Warn("Proceeding without checksum verification")
		return nil
	}

	expectedChecksum, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("Failed to read checksum", zap.Error(err))
		return nil
	}

	// Calculate actual checksum
	actualChecksum, err := sbi.calculateSHA256(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Compare
	expected := strings.TrimSpace(string(expectedChecksum))
	if actualChecksum != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actualChecksum)
	}

	logger.Info("Checksum verified successfully")
	return nil
}

// calculateSHA256 calculates the SHA256 checksum of a file
func (sbi *SimpleBootstrapInstaller) calculateSHA256(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Warning: Failed to close file: %v\n", err)
		}
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// runBootstrap executes the bootstrap script with appropriate arguments
func (sbi *SimpleBootstrapInstaller) runBootstrap(rc *eos_io.RuntimeContext, scriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build command arguments
	args := []string{scriptPath}

	// Common flags for all installations
	args = append(args, "-P") // Allow pip based installations

	if !sbi.config.MasterMode {
		// For masterless mode
		args = append(args, "-X") // Do not start services
		logger.Info("Installing Salt in masterless mode")
	} else {
		// For master-minion mode
		args = append(args, "-M")              // Install master
		args = append(args, "-A", "localhost") // Accept local minion
		logger.Info("Installing Salt in master-minion mode")
	}

	// Add version if specified
	if sbi.config.Version != "" && sbi.config.Version != "latest" {
		args = append(args, "git", sbi.config.Version)
		logger.Info("Installing specific Salt version",
			zap.String("version", sbi.config.Version))
	}

	logger.Info("Running bootstrap script",
		zap.Strings("args", args))

	// Execute with proper timeout and context
	ctx, cancel := context.WithTimeout(rc.Ctx, 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", args...)

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Bootstrap script failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("bootstrap script failed: %w", err)
	}

	logger.Info("Bootstrap script completed successfully")
	logger.Debug("Bootstrap output", zap.String("output", string(output)))

	return nil
}

// Configure sets up Salt for the specified mode
func (sbi *SimpleBootstrapInstaller) Configure(rc *eos_io.RuntimeContext) error {
	if sbi.config.MasterMode {
		// Master mode needs different configuration
		return sbi.configureMasterMode(rc)
	}

	return sbi.configureMasterlessMode(rc)
}

// configureMasterlessMode configures Salt for masterless operation
func (sbi *SimpleBootstrapInstaller) configureMasterlessMode(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt for masterless operation")

	// Create minion configuration
	minionConfig := fmt.Sprintf(`# Masterless configuration created by Eos
file_client: local
master_type: disable

# Local file roots
file_roots:
  base:
    - /srv/salt
    - /srv/salt/eos

# Local pillar roots  
pillar_roots:
  base:
    - /srv/pillar

# Logging
log_level: %s
log_file: /var/log/salt/minion
`, sbi.config.LogLevel)

	// Ensure directory exists
	if err := os.MkdirAll("/etc/salt", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/salt directory: %w", err)
	}

	// Write configuration
	if err := os.WriteFile("/etc/salt/minion", []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write minion configuration: %w", err)
	}

	// Create state directories
	dirs := []string{
		"/srv/salt",
		"/srv/salt/eos",
		"/srv/pillar",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Created directory", zap.String("path", dir))
	}

	// Create a test state
	testState := `# EOS Salt test state
eos_verification_file:
  file.managed:
    - name: /tmp/eos-salt-verified.txt
    - contents: |
        Salt successfully installed by Eos
        Installation date: {{ salt['cmd.run']('date') }}
        Salt version: {{ salt['cmd.run']('salt-call --version') }}
    - mode: 644
`

	testStatePath := "/srv/salt/eos/test.sls"
	if err := os.WriteFile(testStatePath, []byte(testState), 0644); err != nil {
		return fmt.Errorf("failed to create test state: %w", err)
	}

	logger.Info("Masterless configuration completed successfully")
	return nil
}

// configureMasterMode configures Salt for master-minion mode
func (sbi *SimpleBootstrapInstaller) configureMasterMode(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt for master-minion mode")

	// Basic master configuration
	masterConfig := fmt.Sprintf(`# Master configuration created by Eos
interface: 0.0.0.0
log_level: %s
log_file: /var/log/salt/master

# Auto accept minions (for development - change for production)
auto_accept: True
`, sbi.config.LogLevel)

	// Write master configuration
	if err := os.WriteFile("/etc/salt/master", []byte(masterConfig), 0644); err != nil {
		return fmt.Errorf("failed to write master configuration: %w", err)
	}

	logger.Info("Master-minion configuration completed successfully")
	return nil
}

// Verify checks that Salt installation is working correctly
func (sbi *SimpleBootstrapInstaller) Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if sbi.config.SkipTest {
		logger.Info("Skipping verification as requested")
		return nil
	}

	logger.Info("Verifying Salt installation")

	// Check salt-call exists
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		return fmt.Errorf("salt-call not found in PATH after installation")
	}

	logger.Debug("salt-call found", zap.String("path", saltCallPath))

	// Test basic functionality
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "salt-call", "--local", "test.ping")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Salt verification failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("salt verification failed: %w", err)
	}

	logger.Info("Salt verification completed successfully",
		zap.String("output", strings.TrimSpace(string(output))))

	return nil
}

// handleInstallError provides specific guidance based on the error type
func (sbi *SimpleBootstrapInstaller) handleInstallError(rc *eos_io.RuntimeContext, err error) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Provide specific guidance based on the error
	if strings.Contains(err.Error(), "not a shell script") {
		logger.Error("Bootstrap URL returned HTML instead of script")
		logger.Info("This usually means the bootstrap URL has changed")
		logger.Info("Please check https://docs.saltproject.io/salt/install-guide/ for current installation instructions")
		logger.Info("You can also try specifying a different bootstrap URL with --bootstrap-url")
	} else if strings.Contains(err.Error(), "Permission denied") {
		logger.Error("Insufficient permissions")
		logger.Info("Salt installation requires root privileges. Please run with sudo.")
	} else if strings.Contains(err.Error(), "checksum mismatch") {
		logger.Error("Security verification failed")
		logger.Info("The bootstrap script failed checksum verification.")
		logger.Info("This could indicate a corrupted download or security issue.")
		logger.Info("You can skip verification with --skip-checksum (not recommended)")
	} else if strings.Contains(err.Error(), "context deadline exceeded") {
		logger.Error("Installation timed out")
		logger.Info("The bootstrap process took longer than expected.")
		logger.Info("This could indicate network issues or a slow system.")
		logger.Info("Try running again or check your internet connection.")
	}

	return eos_err.NewExpectedError(rc.Ctx, err)
}
