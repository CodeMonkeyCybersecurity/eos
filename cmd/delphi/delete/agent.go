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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
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
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		if agentID == "" {
			zap.L().Error("Agent ID is required")
			fmt.Println("❌ Please provide an agent ID using --agent-id")
			return nil
		}

		zap.L().Info("🔐 Authenticating and loading Delphi config...")
		config, err := delphi.ResolveConfig()
		if err != nil {
			zap.L().Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}

		token, err := delphi.Authenticate(config)
		if err != nil {
			zap.L().Error("Authentication failed", zap.Error(err))
			os.Exit(1)
		}

		zap.L().Info("🗑️  Deleting Wazuh agent via API", zap.String("agentID", agentID))
		resp, err := delphi.DeleteAgent(agentID, token, config)
		if err != nil {
			zap.L().Error("Failed to delete agent via API", zap.Error(err))
			os.Exit(1)
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println("\n✅ Agent deleted successfully from Wazuh:\n" + string(prettyJSON))

		zap.L().Info("🧹 Attempting local Wazuh agent uninstall...")
		switch runtime.GOOS {
		case "darwin":
			uninstallMacOS()
		case "linux":
			uninstallLinux()
		case "windows":
			uninstallWindows()
		default:
			zap.L().Warn("Unsupported OS for local uninstall", zap.String("os", runtime.GOOS))
		}
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	DeleteAgentCmd.Flags().StringVar(&agentID, "agent-id", "", "ID of the agent to delete")
}

// --- OS Uninstall Helpers ---

func uninstallMacOS() {
	scriptPath := "/Library/Ossec/uninstall.sh"
	if _, err := os.Stat(scriptPath); err == nil {
		zap.L().Info("Found macOS uninstall script", zap.String("path", scriptPath))
		cmd := exec.Command( scriptPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			zap.L().Error("macOS uninstall failed", zap.Error(err))
		} else {
			zap.L().Info("Wazuh agent uninstalled on macOS")
		}
	} else {
		zap.L().Warn("Uninstall script not found", zap.String("path", scriptPath))
	}
}

func uninstallLinux() {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		zap.L().Warn("Could not read /etc/os-release, defaulting to apt", zap.Error(err))
		uninstallDeb()
		return
	}
	content := strings.ToLower(string(data))
	switch {
	case strings.Contains(content, "debian"), strings.Contains(content, "ubuntu"):
		uninstallDeb()
	case strings.Contains(content, "rhel"), strings.Contains(content, "centos"),
		strings.Contains(content, "fedora"), strings.Contains(content, "suse"):
		uninstallRpm()
	default:
		zap.L().Warn("Unrecognized Linux distro, defaulting to apt-based removal")
		uninstallDeb()
	}
}

func uninstallDeb() {
	zap.L().Info("Uninstalling with apt-get purge...")
	cmd := exec.Command( "apt-get", "purge", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		zap.L().Error("apt-get purge failed", zap.Error(err))
	} else {
		zap.L().Info("Wazuh agent uninstalled via apt-get")
	}
}

func uninstallRpm() {
	var manager string
	if path, err := exec.LookPath("yum"); err == nil {
		manager = path
	} else if path, err := exec.LookPath("dnf"); err == nil {
		manager = path
	}

	if manager == "" {
		zap.L().Warn("Neither yum nor dnf found; cannot uninstall")
		return
	}

	zap.L().Info("Uninstalling with", zap.String("manager", manager))
	cmd := exec.Command(manager,  "remove", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		zap.L().Error("RPM uninstall failed", zap.Error(err))
	} else {
		zap.L().Info("Wazuh agent uninstalled via RPM-based manager")
	}
}

func uninstallWindows() {
	zap.L().Info("Querying WMIC for Wazuh agent")
	query := `wmic product where "Name like '%%Wazuh%%'" get IdentifyingNumber,Name`
	cmd := exec.Command("cmd", "/C", query)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		zap.L().Error("WMIC query failed", zap.Error(err))
		return
	}

	output := outBuf.String()
	zap.L().Info("WMIC Output", zap.String("output", output))

	scanner := bufio.NewScanner(strings.NewReader(output))
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 {
		zap.L().Warn("No Wazuh agent found in WMIC output")
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
			zap.L().Info("Found Wazuh product", zap.String("productName", productName), zap.String("code", productCode))
			uninstallCmd := fmt.Sprintf("msiexec /x %s /qn", productCode)
			cmdUninstall := exec.Command("cmd", "/C", uninstallCmd)
			cmdUninstall.Stdout = os.Stdout
			cmdUninstall.Stderr = os.Stderr
			if err := cmdUninstall.Run(); err != nil {
				zap.L().Error("Windows uninstall failed", zap.Error(err))
			} else {
				zap.L().Info("Wazuh agent uninstalled from Windows")
			}
			return
		}
	}

	zap.L().Warn("No matching Wazuh product found in WMIC output")
}
