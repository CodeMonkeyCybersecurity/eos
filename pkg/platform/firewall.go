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
	if err := execute.Execute("sudo", "ufw", "enable"); err != nil {
		log.Error("Failed to enable UFW", zap.Error(err))
		return err
	}

	for _, port := range wazuhPorts {
		if err := execute.Execute("sudo", "ufw", "allow", port); err != nil {
			log.Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	if err := execute.Execute("sudo", "ufw", "reload"); err != nil {
		log.Error("Failed to reload UFW", zap.Error(err))
		return err
	}

	if err := execute.Execute("sudo", "ufw", "status"); err != nil {
		log.Warn("Failed to get UFW status", zap.Error(err)) // Not fatal
	}

	log.Info("✅ UFW configuration complete.")
	return nil
}

// ConfigureFirewalld sets up firewalld for wazuh ports.
func ConfigureFirewalld(log *zap.Logger, wazuhPorts []string) error {
	log.Info("🚦 Checking Firewalld state")
	if err := execute.Execute("sudo", "firewall-cmd", "--state"); err != nil {
		log.Error("Firewalld not running", zap.Error(err))
		return err
	}

	for _, port := range wazuhPorts {
		log.Info("📦 Allowing port", zap.String("port", port))
		if err := execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-port="+port); err != nil {
			log.Error("Failed to add port to firewalld", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	log.Info("🔒 Allowing https service")
	if err := execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-service=https"); err != nil {
		log.Error("Failed to add https service to firewalld", zap.Error(err))
		return err
	}

	log.Info("🔁 Reloading Firewalld")
	if err := execute.Execute("sudo", "firewall-cmd", "--reload"); err != nil {
		log.Error("Failed to reload firewalld", zap.Error(err))
		return err
	}

	log.Info("📖 Listing open ports")
	if err := execute.Execute("sudo", "firewall-cmd", "--list-ports"); err != nil {
		log.Warn("Failed to list open ports", zap.Error(err)) // Not fatal
	}

	log.Info("✅ Firewalld configuration complete.")
	return nil
}
