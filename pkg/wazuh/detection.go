package wazuh

import (
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Role represents the detected Wazuh role of the current host.
type Role string

const (
	// RoleNone indicates no Wazuh components were detected on this host.
	RoleNone Role = "none"
	// RoleAgent indicates a Wazuh agent installation.
	RoleAgent Role = "agent"
	// RoleManager indicates a Wazuh manager (which implicitly includes agent capabilities).
	RoleManager Role = "manager"
)

var (
	managerBinaries = []string{
		"/var/ossec/bin/wazuh-modulesd",
		"/var/ossec/bin/wazuh-analysisd",
	}
	agentBinaries = []string{
		"/var/ossec/bin/wazuh-agentd",
	}
)

// DetectRole inspects local binaries and systemd units to determine the Wazuh role.
func DetectRole(rc *eos_io.RuntimeContext) Role {
	logger := otelzap.Ctx(rc.Ctx)

	managerDetected := hasAnyFile(managerBinaries) || servicePresent("wazuh-manager")
	agentDetected := hasAnyFile(agentBinaries) || servicePresent("wazuh-agent")

	switch {
	case managerDetected:
		logger.Debug("Detected Wazuh manager components")
		return RoleManager
	case agentDetected:
		logger.Debug("Detected Wazuh agent components")
		return RoleAgent
	default:
		logger.Debug("No Wazuh components detected")
		return RoleNone
	}
}

func hasAnyFile(paths []string) bool {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func servicePresent(name string) bool {
	cmd := exec.Command("systemctl", "status", name)
	if err := cmd.Run(); err == nil {
		return true
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		// exit code 3 -> service exists but inactive; still counts as present
		return exitErr.ExitCode() == 3
	}
	return false
}
