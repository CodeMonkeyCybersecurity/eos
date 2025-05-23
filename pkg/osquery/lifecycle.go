// pkg/osquery/lifecycle.go

package osquery

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

func InstallOsquery(arch string) error {
	zap.L().Info("Creating /etc/apt/keyrings directory...")
	err := execute.RunSimple("mkdir", "-p", "/etc/apt/keyrings")
	if err != nil {
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
	teeCmd := exec.Command("tee", "/etc/apt/keyrings/osquery.asc")
	teeCmd.Stdin = &curlOutput
	teeCmd.Stdout = os.Stdout
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	zap.L().Info("Writing osquery APT repository...")
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main", arch)
	err = execute.RunSimple("sh", "-c", fmt.Sprintf("echo '%s' > /etc/apt/sources.list.d/osquery.list", repoLine))
	if err != nil {
		return fmt.Errorf("add repo: %w", err)
	}

	zap.L().Info("Updating APT cache...")
	err = execute.RunSimple("apt", "update")
	if err != nil {
		return fmt.Errorf("apt update: %w", err)
	}

	zap.L().Info("Installing osquery...")
	err = execute.RunSimple("apt", "install", "-y", "osquery")
	if err != nil {
		return fmt.Errorf("apt install: %w", err)
	}

	zap.L().Info("osquery installed successfully.")
	return nil
}

