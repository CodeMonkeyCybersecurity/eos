// cmd/delphi/delete/agent.go
package delete

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var agentID string

var DeleteAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Delete a Wazuh agent using its agent ID and uninstall it from the local machine",
	Long: `This command deletes a Wazuh agent from the server via API and uninstalls the agent locally.

Supported OS uninstallers:
- macOS: /Library/Ossec/uninstall.sh
- Linux: apt-get, yum, or dnf depending on distribution
- Windows: wmic + msiexec`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()

		if agentID == "" {
			log.Error("Agent ID is required")
			fmt.Println("❌ Please provide an agent ID using --agent-id")
			return nil
		}

		log.Info("🔐 Authenticating and loading Delphi config...")
		config, err := delphi.LoadAndConfirmConfig()
		if err != nil {
			log.Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}

		token, err := delphi.Authenticate(config)
		if err != nil {
			log.Error("Authentication failed", zap.Error(err))
			os.Exit(1)
		}

		log.Info("🗑️  Deleting Wazuh agent via API", zap.String("agentID", agentID))
		resp, err := delphi.DeleteAgent(agentID, token, config)
		if err != nil {
			log.Error("Failed to delete agent via API", zap.Error(err))
			os.Exit(1)
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println("\n✅ Agent deleted successfully from Wazuh:\n" + string(prettyJSON))

		log.Info("🧹 Attempting local Wazuh agent uninstall...")
		switch runtime.GOOS {
		case "darwin":
			uninstallMacOS(log)
		case "linux":
			uninstallLinux(log)
		case "windows":
			uninstallWindows(log)
		default:
			log.Warn("Unsupported OS for local uninstall", zap.String("os", runtime.GOOS))
		}
		cmd.Help()
		return nil
	}),
}

func init() {
	DeleteAgentCmd.Flags().StringVar(&agentID, "agent-id", "", "ID of the agent to delete")
}

// --- OS Uninstall Helpers ---

func uninstallMacOS(log *zap.Logger) {
	scriptPath := "/Library/Ossec/uninstall.sh"
	if _, err := os.Stat(scriptPath); err == nil {
		log.Info("Found macOS uninstall script", zap.String("path", scriptPath))
		cmd := exec.Command("sudo", scriptPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Error("macOS uninstall failed", zap.Error(err))
		} else {
			log.Info("Wazuh agent uninstalled on macOS")
		}
	} else {
		log.Warn("Uninstall script not found", zap.String("path", scriptPath))
	}
}

func uninstallLinux(log *zap.Logger) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		log.Warn("Could not read /etc/os-release, defaulting to apt", zap.Error(err))
		uninstallDeb(log)
		return
	}
	content := strings.ToLower(string(data))
	switch {
	case strings.Contains(content, "debian"), strings.Contains(content, "ubuntu"):
		uninstallDeb(log)
	case strings.Contains(content, "rhel"), strings.Contains(content, "centos"),
		strings.Contains(content, "fedora"), strings.Contains(content, "suse"):
		uninstallRpm(log)
	default:
		log.Warn("Unrecognized Linux distro, defaulting to apt-based removal")
		uninstallDeb(log)
	}
}

func uninstallDeb(log *zap.Logger) {
	log.Info("Uninstalling with apt-get purge...")
	cmd := exec.Command("sudo", "apt-get", "purge", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("apt-get purge failed", zap.Error(err))
	} else {
		log.Info("Wazuh agent uninstalled via apt-get")
	}
}

func uninstallRpm(log *zap.Logger) {
	var manager string
	if path, err := exec.LookPath("yum"); err == nil {
		manager = path
	} else if path, err := exec.LookPath("dnf"); err == nil {
		manager = path
	}

	if manager == "" {
		log.Warn("Neither yum nor dnf found; cannot uninstall")
		return
	}

	log.Info("Uninstalling with", zap.String("manager", manager))
	cmd := exec.Command("sudo", manager, "remove", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("RPM uninstall failed", zap.Error(err))
	} else {
		log.Info("Wazuh agent uninstalled via RPM-based manager")
	}
}

func uninstallWindows(log *zap.Logger) {
	log.Info("Querying WMIC for Wazuh agent")
	query := `wmic product where "Name like '%%Wazuh%%'" get IdentifyingNumber,Name`
	cmd := exec.Command("cmd", "/C", query)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("WMIC query failed", zap.Error(err))
		return
	}

	output := outBuf.String()
	log.Info("WMIC Output", zap.String("output", output))

	scanner := bufio.NewScanner(strings.NewReader(output))
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 {
		log.Warn("No Wazuh agent found in WMIC output")
		return
	}

	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		productCode := parts[0]
		productName := strings.Join(parts[1:], " ")
		if strings.Contains(productName, "Wazuh") {
			log.Info("Found Wazuh product", zap.String("productName", productName), zap.String("code", productCode))
			uninstallCmd := fmt.Sprintf("msiexec /x %s /qn", productCode)
			cmdUninstall := exec.Command("cmd", "/C", uninstallCmd)
			cmdUninstall.Stdout = os.Stdout
			cmdUninstall.Stderr = os.Stderr
			if err := cmdUninstall.Run(); err != nil {
				log.Error("Windows uninstall failed", zap.Error(err))
			} else {
				log.Info("Wazuh agent uninstalled from Windows")
			}
			return
		}
	}

	log.Warn("No matching Wazuh product found in WMIC output")
}
