// cmd/create/osquery.go

package create

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var createOsQueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Install osquery and configure its APT repository",
	Long:  "Installs osquery on Debian/Ubuntu-based systems by configuring the GPG key and APT repository.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()

		if err := platform.RequireLinuxDistro([]string{"debian"}, log); err != nil {
			log.Fatal("Platform requirement not met", zap.Error(err))
		}

		// Ensure the base platform is Linux
		if platform.GetOSPlatform(log) != "linux" {
			log.Fatal("osquery install only supported on Linux")
		}

		// Check distro support
		distro := platform.DetectLinuxDistro(log)
		log.Info("Detected Linux distribution", zap.String("distro", distro))

		if distro != "debian" {
			log.Fatal("Unsupported Linux distribution for osquery install", zap.String("distro", distro))
		}

		// Check architecture
		arch := platform.GetArch(log)
		log.Info("Detected architecture", zap.String("arch", arch))

		if arch != "amd64" && arch != "arm64" {
			log.Fatal("Unsupported architecture", zap.String("arch", arch))
		}

		// Run the installer
		if err := installOsquery(log, arch); err != nil {
			log.Fatal("Failed to install osquery", zap.Error(err))
		}
		return nil
	}),
}

func installOsquery(log *zap.Logger, arch string) error {
	log.Info("Creating /etc/apt/keyrings directory...")
	if err := execute.Execute("sudo", "mkdir", "-p", "/etc/apt/keyrings"); err != nil {
		return fmt.Errorf("mkdir keyrings: %w", err)
	}

	log.Info("Downloading osquery GPG key...")
	curlCmd := exec.Command("curl", "-L", "https://pkg.osquery.io/deb/pubkey.gpg")
	var curlOutput bytes.Buffer
	curlCmd.Stdout = &curlOutput
	curlCmd.Stderr = os.Stderr
	if err := curlCmd.Run(); err != nil {
		return fmt.Errorf("failed to download key: %w", err)
	}

	log.Info("Saving GPG key to /etc/apt/keyrings/osquery.asc")
	teeCmd := exec.Command("sudo", "tee", "/etc/apt/keyrings/osquery.asc")
	teeCmd.Stdin = &curlOutput
	teeCmd.Stdout = os.Stdout
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	log.Info("Writing osquery APT repository...")
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main", arch)
	if err := execute.Execute("sudo", "sh", "-c", fmt.Sprintf("echo '%s' > /etc/apt/sources.list.d/osquery.list", repoLine)); err != nil {
		return fmt.Errorf("add repo: %w", err)
	}

	log.Info("Updating APT cache...")
	if err := execute.Execute("sudo", "apt", "update"); err != nil {
		return fmt.Errorf("apt update: %w", err)
	}

	log.Info("Installing osquery...")
	if err := execute.Execute("sudo", "apt", "install", "-y", "osquery"); err != nil {
		return fmt.Errorf("apt install: %w", err)
	}

	log.Info("osquery installed successfully.")
	return nil
}

func init() {
	CreateCmd.AddCommand(createOsQueryCmd)
}
