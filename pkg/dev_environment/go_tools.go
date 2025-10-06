package dev_environment

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallGoTools installs essential Go development tools
func InstallGoTools(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Go development tools")

	// Check if Go is installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args:    []string{"version"},
		Capture: true,
	}); err != nil {
		return fmt.Errorf("Go is not installed. Please install Go first")
	}

	// Get GOPATH
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		gopath = filepath.Join(homeDir, "go")
	}

	// Ensure GOPATH/bin is in PATH
	goBin := filepath.Join(gopath, "bin")
	if err := os.MkdirAll(goBin, 0755); err != nil {
		return fmt.Errorf("failed to create go bin directory: %w", err)
	}

	// Install golangci-lint
	logger.Info("Installing golangci-lint")
	if err := installGolangciLint(rc); err != nil {
		return fmt.Errorf("failed to install golangci-lint: %w", err)
	}

	// Install other useful Go tools
	tools := []struct {
		name    string
		pkg     string
		version string
	}{
		{
			name:    "gopls",
			pkg:     "golang.org/x/tools/gopls",
			version: "latest",
		},
		{
			name:    "dlv",
			pkg:     "github.com/go-delve/delve/cmd/dlv",
			version: "latest",
		},
		{
			name:    "staticcheck",
			pkg:     "honnef.co/go/tools/cmd/staticcheck",
			version: "latest",
		},
		{
			name:    "goimports",
			pkg:     "golang.org/x/tools/cmd/goimports",
			version: "latest",
		},
		{
			name:    "gomodifytags",
			pkg:     "github.com/fatih/gomodifytags",
			version: "latest",
		},
		{
			name:    "impl",
			pkg:     "github.com/josharian/impl",
			version: "latest",
		},
		{
			name:    "fillstruct",
			pkg:     "github.com/davidrjenni/reftools/cmd/fillstruct",
			version: "latest",
		},
	}

	for _, tool := range tools {
		logger.Info("Installing Go tool", zap.String("tool", tool.name))
		fmt.Printf("Installing %s...\n", tool.name)

		// Check if already installed
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: tool.name,
			Args:    []string{"--version"},
			Capture: true,
		}); err == nil {
			logger.Debug("Tool already installed", zap.String("tool", tool.name))
			continue
		}

		// Install the tool
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "go",
			Args:    []string{"install", tool.pkg + "@" + tool.version},
		}); err != nil {
			logger.Warn("Failed to install tool",
				zap.String("tool", tool.name),
				zap.Error(err))
			fmt.Printf("Failed to install %s: %v\n", tool.name, err)
		} else {
			fmt.Printf("✓ %s installed successfully\n", tool.name)
		}
	}

	// Add GOPATH/bin to PATH reminder
	fmt.Println("\n📝 Make sure your GOPATH/bin is in your PATH:")
	fmt.Printf("   export PATH=$PATH:%s\n", goBin)
	fmt.Println("   Add this to your ~/.bashrc or ~/.zshrc to make it permanent")

	logger.Info("Go development tools installation completed")
	return nil
}

// installGolangciLint installs golangci-lint using the official installer
func installGolangciLint(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already installed
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "golangci-lint",
		Args:    []string{"version"},
		Capture: true,
	}); err == nil {
		logger.Info("golangci-lint already installed", zap.String("version", strings.TrimSpace(output)))
		fmt.Printf("✓ golangci-lint already installed: %s\n", strings.TrimSpace(output))
		return nil
	}

	fmt.Println("Installing golangci-lint...")

	// Detect architecture
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	// Download and install using the official installer script
	installerURL := "https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh"

	// Create a temporary script file
	tmpScript := "/tmp/golangci-lint-installer.sh"

	// Download the installer
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sSfL", installerURL, "-o", tmpScript},
	}); err != nil {
		return fmt.Errorf("failed to download golangci-lint installer: %w", err)
	}
	defer os.Remove(tmpScript)

	// Make it executable
	if err := os.Chmod(tmpScript, 0755); err != nil {
		return fmt.Errorf("failed to make installer executable: %w", err)
	}

	// Run the installer to install in /usr/local/bin (requires sudo)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"sh", tmpScript, "-b", "/usr/local/bin"},
	}); err != nil {
		// Try installing to user's go/bin as fallback
		logger.Warn("Failed to install to /usr/local/bin, trying user install", zap.Error(err))

		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			homeDir, _ := os.UserHomeDir()
			gopath = filepath.Join(homeDir, "go")
		}
		goBin := filepath.Join(gopath, "bin")

		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sh",
			Args:    []string{tmpScript, "-b", goBin},
		}); err != nil {
			return fmt.Errorf("failed to install golangci-lint: %w", err)
		} else {
			logger.Info("golangci-lint installed to user directory",
				zap.String("path", goBin),
				zap.String("output", output))
		}
	} else {
		logger.Info("golangci-lint installed successfully", zap.String("output", output))
	}

	// Verify installation
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "golangci-lint",
		Args:    []string{"version"},
		Capture: true,
	}); err == nil {
		fmt.Printf("✓ golangci-lint installed successfully: %s\n", strings.TrimSpace(output))
	} else {
		return fmt.Errorf("golangci-lint installation verification failed: %w", err)
	}

	return nil
}
