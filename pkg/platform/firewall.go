package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// CheckFirewallStatus tries UFW, then iptables, and returns a string status.
func CheckFirewallStatus(log *zap.Logger) {
	fmt.Println("🔍 Checking firewall status...")

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		log.Info("UFW detected", zap.String("path", ufwPath))
		out, err := exec.Command("sudo", "ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			log.Warn("Failed to get UFW status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		log.Info("iptables detected", zap.String("path", iptablesPath))
		out, err := exec.Command("sudo", "iptables", "-L", "-n").CombinedOutput()
		if err != nil {
			log.Warn("Failed to get iptables status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	log.Warn("No supported firewall tool found (ufw or iptables)")
}

// ConfigureUFW sets up UFW for wazuh ports.
func ConfigureUFW(log *zap.Logger, wazuhPorts []string) error {
	execute.Execute("sudo", "ufw", "enable")
	for _, port := range wazuhPorts {
		execute.Execute("sudo", "ufw", "allow", port)
	}
	execute.Execute("sudo", "ufw", "reload")
	execute.Execute("sudo", "ufw", "status")
	log.Info("✅ UFW configuration complete.")

	return nil
}

// ConfigureFirewalld sets up firewalld for wazuh ports.
func ConfigureFirewalld(log *zap.Logger, wazuhPorts []string) error {
	log.Info("🚦 Checking Firewalld state")
	execute.Execute("sudo", "firewall-cmd", "--state")

	for _, port := range wazuhPorts {
		log.Info("📦 Allowing port", zap.String("port", port))
		execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-port="+port)
	}

	log.Info("🔒 Allowing https service")
	execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-service=https")

	log.Info("🔁 Reloading Firewalld")
	execute.Execute("sudo", "firewall-cmd", "--reload")

	log.Info("📖 Listing open ports")
	execute.Execute("sudo", "firewall-cmd", "--list-ports")

	log.Info("✅ Firewalld configuration complete.")
	return nil
}
