// pkg/consul/installer/binary.go
// Binary download and installation for Consul

package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BinaryInstaller handles direct binary download and installation
type BinaryInstaller struct {
	rc         *eos_io.RuntimeContext
	logger     otelzap.LoggerWithCtx
	binaryPath string
}

// NewBinaryInstaller creates a new binary installer instance
func NewBinaryInstaller(rc *eos_io.RuntimeContext, binaryPath string) *BinaryInstaller {
	if binaryPath == "" {
		binaryPath = "/usr/bin/consul"
	}

	return &BinaryInstaller{
		rc:         rc,
		logger:     otelzap.Ctx(rc.Ctx),
		binaryPath: binaryPath,
	}
}

// Install downloads and installs Consul binary directly from HashiCorp releases
func (bi *BinaryInstaller) Install(version string) error {
	bi.logger.Info("Installing Consul via direct binary download",
		zap.String("version", version))

	// Determine architecture
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
		arch = "arm64"
	} else {
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	// Construct download URL
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
		version, version, arch)

	bi.logger.Info("Downloading Consul binary",
		zap.String("version", version),
		zap.String("arch", arch),
		zap.String("url", downloadURL))

	// Create temporary directory
	tmpDir := "/tmp/consul-install"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download binary
	zipPath := filepath.Join(tmpDir, "consul.zip")
	if err := bi.downloadFile(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Consul: %w", err)
	}

	// Extract binary
	if err := bi.extractZip(zipPath, tmpDir); err != nil {
		return fmt.Errorf("failed to extract Consul: %w", err)
	}

	// Install binary
	binaryPath := filepath.Join(tmpDir, "consul")
	if err := bi.installBinary(binaryPath); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}

	bi.logger.Info("Consul binary installed successfully",
		zap.String("path", bi.binaryPath),
		zap.String("version", version))

	return nil
}

// downloadFile downloads a file using wget with timeout
func (bi *BinaryInstaller) downloadFile(url, dest string) error {
	ctx, cancel := context.WithTimeout(bi.rc.Ctx, 5*time.Minute)
	defer cancel()

	bi.logger.Info("Downloading file with wget",
		zap.String("url", url),
		zap.String("dest", dest))

	cmd := exec.CommandContext(ctx, "wget", "-O", dest, url)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wget failed for %s: %w", url, err)
	}

	return nil
}

// extractZip extracts a zip file to destination directory
func (bi *BinaryInstaller) extractZip(zipPath, destDir string) error {
	bi.logger.Info("Extracting zip file",
		zap.String("zip", zipPath),
		zap.String("dest", destDir))

	cmd := exec.Command("unzip", "-o", zipPath, "-d", destDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unzip failed: %w", err)
	}

	return nil
}

// installBinary installs the binary to the target location
func (bi *BinaryInstaller) installBinary(sourcePath string) error {
	bi.logger.Info("Installing binary",
		zap.String("source", sourcePath),
		zap.String("target", bi.binaryPath))

	cmd := exec.Command("install", "-m", "755", sourcePath, bi.binaryPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install command failed: %w", err)
	}

	return nil
}

// GetBinaryPath returns the configured binary path
func (bi *BinaryInstaller) GetBinaryPath() string {
	return bi.binaryPath
}
