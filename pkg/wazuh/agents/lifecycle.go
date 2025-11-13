package agents

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// --- OS Uninstall Helpers ---
// TODO
func UninstallMacOS(rc *eos_io.RuntimeContext) {
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
func UninstallLinux(rc *eos_io.RuntimeContext) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Could not read /etc/os-release, defaulting to apt", zap.Error(err))
		UninstallDeb(rc)
		return
	}
	content := strings.ToLower(string(data))
	switch {
	case strings.Contains(content, "debian"), strings.Contains(content, "ubuntu"):
		UninstallDeb(rc)
	case strings.Contains(content, "rhel"), strings.Contains(content, "centos"),
		strings.Contains(content, "fedora"), strings.Contains(content, "suse"):
		UninstallRpm(rc)
	default:
		otelzap.Ctx(rc.Ctx).Warn("Unrecognized Linux distro, defaulting to apt-based removal")
		UninstallDeb(rc)
	}
}

func UninstallDeb(rc *eos_io.RuntimeContext) {
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

func UninstallRpm(rc *eos_io.RuntimeContext) {
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

func UninstallWindows(rc *eos_io.RuntimeContext) {
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
