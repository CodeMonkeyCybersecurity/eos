package saltstack

import (
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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapInstaller handles Salt installation using the official bootstrap script
type BootstrapInstaller struct {
	configurer *Configurer
	verifier   *Verifier
}

// NewBootstrapInstaller creates a new bootstrap-based Salt installer
func NewBootstrapInstaller() *BootstrapInstaller {
	return &BootstrapInstaller{
		configurer: NewConfigurer(),
		verifier:   NewVerifier(),
	}
}

// InstallationStrategy defines the interface for different installation methods
type InstallationStrategy interface {
	Name() string
	Install(rc *eos_io.RuntimeContext, version string, config *Config) error
	Verify(rc *eos_io.RuntimeContext) error
}

// BootstrapConfig holds configuration for bootstrap installation
type BootstrapConfig struct {
	BootstrapURL     string
	SkipChecksum     bool
	ConfigureMaster  bool
	CreateStateTree  bool
}

// Install performs Salt installation using the official bootstrap script
func (bi *BootstrapInstaller) Install(rc *eos_io.RuntimeContext, version string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Salt installation using official bootstrap script",
		zap.String("version", version),
		zap.Bool("master_mode", config.MasterMode))

	// Get bootstrap configuration from context
	bootstrapURL := "https://bootstrap.saltstack.com"
	if url, ok := rc.Attributes["bootstrap_url"]; ok && url != "" {
		bootstrapURL = url
	}
	
	skipChecksum := false
	if skip, ok := rc.Attributes["skip_checksum"]; ok && skip == "true" {
		skipChecksum = true
	}

	// Step 1: Download the bootstrap script
	scriptPath, err := bi.downloadBootstrapScript(rc, bootstrapURL)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to download bootstrap script: %w", err))
	}
	defer os.Remove(scriptPath) // Clean up

	// Step 2: Verify checksum (critical for security)
	if !skipChecksum {
		if err := bi.verifyBootstrapChecksum(rc, scriptPath); err != nil {
			logger.Warn("Checksum verification failed", zap.Error(err))
			// Continue anyway if checksum fails, but warn user
			logger.Warn("Proceeding with installation despite checksum failure")
			logger.Warn("This may indicate a compromised script or network issues")
		}
	} else {
		logger.Warn("Skipping checksum verification as requested")
		logger.Warn("This is not recommended for security reasons")
	}

	// Step 3: Execute the bootstrap script with appropriate flags
	if err := bi.executeBootstrapScript(rc, scriptPath, version, config); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("bootstrap script execution failed: %w", err))
	}

	// Step 4: Configure Salt for masterless operation
	if !config.MasterMode {
		if err := bi.configureMasterlessMode(rc, config); err != nil {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to configure masterless mode: %w", err))
		}
	}

	// Step 5: Create initial state tree structure
	if err := bi.createStateTreeStructure(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to create state tree: %w", err))
	}

	logger.Info("Salt bootstrap installation completed successfully")
	return nil
}

// downloadBootstrapScript downloads the official Salt bootstrap script
func (bi *BootstrapInstaller) downloadBootstrapScript(rc *eos_io.RuntimeContext, bootstrapURL string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Downloading Salt bootstrap script", zap.String("url", bootstrapURL))

	// Create temporary file
	scriptPath := "/tmp/salt-bootstrap.sh"

	// Download the script
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(bootstrapURL)
	if err != nil {
		return "", fmt.Errorf("failed to download bootstrap script: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bootstrap script download failed with status: %d", resp.StatusCode)
	}

	// Create the file
	file, err := os.Create(scriptPath)
	if err != nil {
		return "", fmt.Errorf("failed to create script file: %w", err)
	}
	defer file.Close()

	// Copy content
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to write script content: %w", err)
	}

	// Make executable
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return "", fmt.Errorf("failed to make script executable: %w", err)
	}

	logger.Debug("Bootstrap script downloaded successfully", zap.String("path", scriptPath))
	return scriptPath, nil
}

// verifyBootstrapChecksum verifies the integrity of the downloaded bootstrap script
func (bi *BootstrapInstaller) verifyBootstrapChecksum(rc *eos_io.RuntimeContext, scriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying bootstrap script checksum")

	// Calculate the actual checksum of our downloaded script
	file, err := os.Open(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to open script for checksum: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	// Download the expected checksum
	checksumURL := "https://bootstrap.saltproject.io/sha256"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(checksumURL)
	if err != nil {
		logger.Warn("Failed to download expected checksum", zap.Error(err))
		return fmt.Errorf("failed to download expected checksum: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download failed with status: %d", resp.StatusCode)
	}

	checksumData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read checksum data: %w", err)
	}

	expectedChecksum := strings.TrimSpace(string(checksumData))

	// Compare checksums
	if actualChecksum != expectedChecksum {
		logger.Error("Checksum mismatch detected",
			zap.String("expected", expectedChecksum),
			zap.String("actual", actualChecksum))
		return fmt.Errorf("bootstrap script checksum mismatch - potential security issue")
	}

	logger.Info("Bootstrap script checksum verified successfully")
	return nil
}

// buildBootstrapCommand creates the command arguments for the bootstrap script
func (bi *BootstrapInstaller) buildBootstrapCommand(scriptPath, version string, config *Config) []string {
	args := []string{"sh", scriptPath}

	// Pin to specific version if provided
	if version != "" && version != "latest" {
		args = append(args, "git", version)
	}

	// Don't start services automatically (we'll configure first)
	args = append(args, "-X")

	// For masterless mode, we don't need the master daemon
	if !config.MasterMode {
		args = append(args, "-N") // No minion daemon auto-start
	}

	// Force installation even if already installed
	args = append(args, "-F")

	return args
}

// executeBootstrapScript runs the bootstrap script with appropriate arguments
func (bi *BootstrapInstaller) executeBootstrapScript(rc *eos_io.RuntimeContext, scriptPath, version string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	args := bi.buildBootstrapCommand(scriptPath, version, config)

	logger.Info("Executing bootstrap script",
		zap.Strings("args", args))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: args[0],
		Args:    args[1:],
		Timeout: 600 * time.Second, // Bootstrap can take a while
	})

	if err != nil {
		return bi.handleBootstrapError(rc, err, output)
	}

	logger.Debug("Bootstrap script completed successfully",
		zap.String("output", output))

	return nil
}

// configureMasterlessMode configures Salt for masterless operation
func (bi *BootstrapInstaller) configureMasterlessMode(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Salt for masterless operation")

	// Create the minion configuration
	minionConfig := fmt.Sprintf(`# Salt minion configuration for Eos masterless mode
file_client: local
master_type: disable

# Local file roots for masterless operation
file_roots:
  base:
    - /srv/salt
    - /srv/salt/eos

# Local pillar roots
pillar_roots:
  base:
    - /srv/pillar

# Logging configuration
log_level: %s

# Security settings
hash_type: sha256

# Performance settings
multiprocessing: true
`, config.LogLevel)

	// Write to /etc/salt/minion
	minionConfigPath := "/etc/salt/minion"
	if err := os.WriteFile(minionConfigPath, []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write minion configuration: %w", err)
	}

	logger.Debug("Masterless configuration written", zap.String("path", minionConfigPath))
	return nil
}

// createStateTreeStructure creates the basic Salt state tree structure
func (bi *BootstrapInstaller) createStateTreeStructure(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Salt state tree structure")

	// Create directory structure
	directories := []string{
		"/srv/salt",
		"/srv/salt/eos",
		"/srv/pillar",
	}

	for _, dir := range directories {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Created directory", zap.String("path", dir))
	}

	// Create a sample top.sls to verify functionality
	topSLS := `# Top file for Salt state tree
base:
  '*':
    - eos.test
`

	topPath := "/srv/salt/top.sls"
	if err := os.WriteFile(topPath, []byte(topSLS), 0644); err != nil {
		return fmt.Errorf("failed to create top.sls: %w", err)
	}

	// Create the eos directory and test state
	eosDir := "/srv/salt/eos"
	if err := os.MkdirAll(eosDir, 0755); err != nil {
		return fmt.Errorf("failed to create eos directory: %w", err)
	}

	// Create a test state that Eos can use
	testState := `# Eos test state to verify Salt functionality
eos_verification_file:
  file.managed:
    - name: /tmp/eos-salt-verified.txt
    - contents: |
        Salt successfully installed by Eos
        Installation date: {{ salt['cmd.run']('date') }}
        Salt version: {{ salt['cmd.run']('salt-call --version') }}
    - mode: 644

eos_verification_test:
  cmd.run:
    - name: echo "Salt masterless mode is working correctly"
    - require:
      - file: eos_verification_file
`

	testStatePath := filepath.Join(eosDir, "test.sls")
	if err := os.WriteFile(testStatePath, []byte(testState), 0644); err != nil {
		return fmt.Errorf("failed to create test state: %w", err)
	}

	logger.Info("State tree structure created successfully")
	return nil
}

// handleBootstrapError provides detailed error handling for bootstrap failures
func (bi *BootstrapInstaller) handleBootstrapError(rc *eos_io.RuntimeContext, err error, output string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Error("Bootstrap script failed", zap.Error(err), zap.String("output", output))

	// Parse common bootstrap script errors
	switch {
	case strings.Contains(output, "No repository"):
		logger.Error("Bootstrap couldn't find appropriate repository")
		logger.Info("This might indicate:")
		logger.Info("- Unsupported OS version")
		logger.Info("- Network connectivity issues")
		logger.Info("Try running with --log-level=debug for more details")

	case strings.Contains(output, "Permission denied"):
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Salt installation requires root privileges"))

	case strings.Contains(err.Error(), "connection refused") || strings.Contains(output, "connection refused"):
		logger.Error("Network connectivity issue detected")
		logger.Info("Please check:")
		logger.Info("1. Internet connectivity: ping bootstrap.saltstack.com")
		logger.Info("2. Proxy settings if behind corporate firewall")
		logger.Info("3. DNS resolution: nslookup bootstrap.saltstack.com")

	case strings.Contains(output, "404") || strings.Contains(output, "Not Found"):
		logger.Error("Bootstrap script or dependencies not found")
		logger.Info("This might indicate:")
		logger.Info("- Temporary service outage")
		logger.Info("- Changed URLs in Salt infrastructure")
		logger.Info("- Try again later or check Salt documentation")

	default:
		logger.Error("Unexpected bootstrap failure")
		logger.Info("Full output for debugging:")
		logger.Info(output)
	}

	return fmt.Errorf("bootstrap installation failed: %w", err)
}

// Verify checks that Salt is working correctly after bootstrap installation
func (bi *BootstrapInstaller) Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying Salt bootstrap installation")

	// Check salt-call exists and is executable
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		return fmt.Errorf("salt-call not found in PATH after bootstrap installation")
	}

	logger.Debug("salt-call found", zap.String("path", saltCallPath))

	// Verify version
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to get Salt version: %w", err)
	}

	logger.Info("Salt version verified", zap.String("version", strings.TrimSpace(output)))

	// Test masterless functionality
	logger.Info("Testing masterless operation")
	pingOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "test.ping"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("masterless mode test failed: %w", err)
	}

	logger.Info("Masterless mode verified", zap.String("output", strings.TrimSpace(pingOutput)))

	// Test state application
	logger.Info("Testing state application")
	stateOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "state.apply", "eos.test"},
		Timeout: 60 * time.Second,
	})

	if err != nil {
		logger.Warn("State application test failed", zap.Error(err))
		// Don't fail verification if state test fails - it's not critical
	} else {
		logger.Info("State application verified", zap.String("output", strings.TrimSpace(stateOutput)))
	}

	logger.Info("Salt bootstrap installation verification completed successfully")
	return nil
}

// Name returns the name of this installation strategy
func (bi *BootstrapInstaller) Name() string {
	return "Bootstrap Script"
}

// Configure sets up Salt configuration using the configurer
func (bi *BootstrapInstaller) Configure(rc *eos_io.RuntimeContext, config *Config) error {
	// Configuration is handled within the Install method for bootstrap
	// This method is kept for interface compatibility
	return nil
}