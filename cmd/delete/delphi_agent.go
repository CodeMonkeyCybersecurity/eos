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

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if agentID == "" {
			otelzap.Ctx(rc.Ctx).Error("Agent ID is required")
			otelzap.Ctx(rc.Ctx).Info("terminal prompt:  Please provide an agent ID using --agent-id")
			return nil
		}

		otelzap.Ctx(rc.Ctx).Info(" Authenticating and loading Delphi config...")
		config, err := delphi.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}

		token, err := delphi.Authenticate(rc, config)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Authentication failed", zap.Error(err))
			os.Exit(1)
		}

		otelzap.Ctx(rc.Ctx).Info("  Deleting Wazuh agent via API", zap.String("agentID", agentID))
		resp, err := delphi.DeleteAgent(rc, agentID, token, config)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to delete agent via API", zap.Error(err))
			os.Exit(1)
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Agent deleted successfully from Wazuh", zap.String("response", string(prettyJSON)))

		otelzap.Ctx(rc.Ctx).Info("🧹 Attempting local Wazuh agent uninstall...")
		switch runtime.GOOS {
		case "darwin":
			uninstallMacOS(rc)
		case "linux":
			uninstallLinux(rc)
		case "windows":
			uninstallWindows(rc)
		default:
			otelzap.Ctx(rc.Ctx).Warn("Unsupported OS for local uninstall", zap.String("os", runtime.GOOS))
		}
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	DeleteAgentCmd.Flags().StringVar(&agentID, "agent-id", "", "ID of the agent to delete")
}

// --- OS Uninstall Helpers ---
// TODO
func uninstallMacOS(rc *eos_io.RuntimeContext) {
	scriptPath := "/Library/Ossec/uninstall.sh"
	if _, err := os.Stat(scriptPath); err == nil {
		otelzap.Ctx(rc.Ctx).Info("Found macOS uninstall script", zap.String("path", scriptPath))
		cmd := exec.Command(scriptPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			otelzap.Ctx(rc.Ctx).Error("macOS uninstall failed", zap.Error(err))
		} else {
			otelzap.Ctx(rc.Ctx).Info("Wazuh agent uninstalled on macOS")
		}
	} else {
		otelzap.Ctx(rc.Ctx).Warn("Uninstall script not found", zap.String("path", scriptPath))
	}
}

// TODO
func uninstallLinux(rc *eos_io.RuntimeContext) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Could not read /etc/os-release, defaulting to apt", zap.Error(err))
		uninstallDeb(rc)
		return
	}
	content := strings.ToLower(string(data))
	switch {
	case strings.Contains(content, "debian"), strings.Contains(content, "ubuntu"):
		uninstallDeb(rc)
	case strings.Contains(content, "rhel"), strings.Contains(content, "centos"),
		strings.Contains(content, "fedora"), strings.Contains(content, "suse"):
		uninstallRpm(rc)
	default:
		otelzap.Ctx(rc.Ctx).Warn("Unrecognized Linux distro, defaulting to apt-based removal")
		uninstallDeb(rc)
	}
}

// TODO
func uninstallDeb(rc *eos_io.RuntimeContext) {
	otelzap.Ctx(rc.Ctx).Info("Uninstalling with apt-get purge...")
	cmd := exec.Command("apt-get", "purge", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error("apt-get purge failed", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info("Wazuh agent uninstalled via apt-get")
	}
}

// TODO
func uninstallRpm(rc *eos_io.RuntimeContext) {
	var manager string
	if path, err := exec.LookPath("yum"); err == nil {
		manager = path
	} else if path, err := exec.LookPath("dnf"); err == nil {
		manager = path
	}

	if manager == "" {
		otelzap.Ctx(rc.Ctx).Warn("Neither yum nor dnf found; cannot uninstall")
		return
	}

	otelzap.Ctx(rc.Ctx).Info("Uninstalling with", zap.String("manager", manager))
	cmd := exec.Command(manager, "remove", "-y", "wazuh-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error("RPM uninstall failed", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info("Wazuh agent uninstalled via RPM-based manager")
	}
}

// TODO
func uninstallWindows(rc *eos_io.RuntimeContext) {
	otelzap.Ctx(rc.Ctx).Info("Querying WMIC for Wazuh agent")
	query := `wmic product where "Name like '%%Wazuh%%'" get IdentifyingNumber,Name`
	cmd := exec.Command("cmd", "/C", query)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error("WMIC query failed", zap.Error(err))
		return
	}

	output := outBuf.String()
	otelzap.Ctx(rc.Ctx).Info("WMIC Output", zap.String("output", output))

	scanner := bufio.NewScanner(strings.NewReader(output))
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 {
		otelzap.Ctx(rc.Ctx).Warn("No Wazuh agent found in WMIC output")
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
			otelzap.Ctx(rc.Ctx).Info("Found Wazuh product", zap.String("productName", productName), zap.String("code", productCode))
			uninstallCmd := fmt.Sprintf("msiexec /x %s /qn", productCode)
			cmdUninstall := exec.Command("cmd", "/C", uninstallCmd)
			cmdUninstall.Stdout = os.Stdout
			cmdUninstall.Stderr = os.Stderr
			if err := cmdUninstall.Run(); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Windows uninstall failed", zap.Error(err))
			} else {
				otelzap.Ctx(rc.Ctx).Info("Wazuh agent uninstalled from Windows")
			}
			return
		}
	}

	otelzap.Ctx(rc.Ctx).Warn("No matching Wazuh product found in WMIC output")
}
