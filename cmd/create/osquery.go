// cmd/create/osquery.go

package create

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var createOsQueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Install osquery and configure its APT repository",
	Long:  "Installs osquery on Debian/Ubuntu-based systems by configuring the GPG key and APT repository.",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		if err := platform.RequireLinuxDistro([]string{"debian"}); err != nil {
			zap.L().Fatal("Platform requirement not met", zap.Error(err))
		}

		// Ensure the base platform is Linux
		if platform.GetOSPlatform() != "linux" {
			zap.L().Fatal("osquery install only supported on Linux")
		}

		// Check distro support
		distro := platform.DetectLinuxDistro()
		zap.L().Info("Detected Linux distribution", zap.String("distro", distro))

		if distro != "debian" {
			zap.L().Fatal("Unsupported Linux distribution for osquery install", zap.String("distro", distro))
		}

		// Check architecture
		arch := platform.GetArch()
		zap.L().Info("Detected architecture", zap.String("arch", arch))

		if arch != "amd64" && arch != "arm64" {
			zap.L().Fatal("Unsupported architecture", zap.String("arch", arch))
		}

		// Run the installer
		if err := installOsquery(arch); err != nil {
			zap.L().Fatal("Failed to install osquery", zap.Error(err))
		}
		return nil
	}),
}

func installOsquery(arch string) error {
	zap.L().Info("Creating /etc/apt/keyrings directory...")
	if err := execute.Execute("mkdir", "-p", "/etc/apt/keyrings"); err != nil {
		return fmt.Errorf("mkdir keyrings: %w", err)
	}

	zap.L().Info("Downloading osquery GPG key...")
	curlCmd := exec.Command("curl", "-L", "https://pkg.osquery.io/deb/pubkey.gpg")
	var curlOutput bytes.Buffer
	curlCmd.Stdout = &curlOutput
	curlCmd.Stderr = os.Stderr
	if err := curlCmd.Run(); err != nil {
		return fmt.Errorf("failed to download key: %w", err)
	}

	zap.L().Info("Saving GPG key to /etc/apt/keyrings/osquery.asc")
	teeCmd := exec.Command("sudo", "tee", "/etc/apt/keyrings/osquery.asc")
	teeCmd.Stdin = &curlOutput
	teeCmd.Stdout = os.Stdout
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	zap.L().Info("Writing osquery APT repository...")
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main", arch)
	if err := execute.Execute("sh", "-c", fmt.Sprintf("echo '%s' > /etc/apt/sources.list.d/osquery.list", repoLine)); err != nil {
		return fmt.Errorf("add repo: %w", err)
	}

	zap.L().Info("Updating APT cache...")
	if err := execute.Execute("sudo", "apt", "update"); err != nil {
		return fmt.Errorf("apt update: %w", err)
	}

	zap.L().Info("Installing osquery...")
	if err := execute.Execute("sudo", "apt", "install", "-y", "osquery"); err != nil {
		return fmt.Errorf("apt install: %w", err)
	}

	zap.L().Info("osquery installed successfully.")
	return nil
}

func init() {
	CreateCmd.AddCommand(createOsQueryCmd)
}
