package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// AllowPorts opens multiple ports based on the system's firewall backend.
func AllowPorts(log *zap.Logger, ports []string) error {
	if _, err := exec.LookPath("ufw"); err == nil {
		log.Info("Using UFW for firewall changes")
		return allowPortsUFW(log, ports)
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		log.Info("Using Firewalld for firewall changes")
		return allowPortsFirewalld(log, ports)
	}
	if _, err := exec.LookPath("pfctl"); err == nil {
		log.Info("Detected macOS PF firewall — not yet supported")
		return fmt.Errorf("macOS firewall (pfctl) support not yet implemented")
	}

	log.Warn("⚠️ No supported firewall backend found")
	return fmt.Errorf("no supported firewall backend (ufw, firewalld, pfctl)")
}

// CheckFirewallStatus tries UFW, then iptables, and returns a string status.
func CheckFirewallStatus(log *zap.Logger) {
	fmt.Println("🔍 Checking firewall status...")

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		log.Info("UFW detected", zap.String("path", ufwPath))
		out, err := exec.Command("ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			log.Warn("Failed to get UFW status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		log.Info("iptables detected", zap.String("path", iptablesPath))
		out, err := exec.Command("iptables", "-L", "-n").CombinedOutput()
		if err != nil {
			log.Warn("Failed to get iptables status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	log.Warn("No supported firewall tool found (ufw or iptables)")
}

func allowPortsUFW(log *zap.Logger, ports []string) error {
	if err := execute.Execute("ufw", "enable"); err != nil {
		log.Warn("UFW already enabled or error", zap.Error(err))
	}

	for _, port := range ports {
		if err := execute.Execute("ufw", "allow", port); err != nil {
			log.Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	return execute.Execute("ufw", "reload")
}

func allowPortsFirewalld(log *zap.Logger, ports []string) error {
	if err := execute.Execute("firewall-cmd", "--state"); err != nil {
		log.Error("Firewalld not running", zap.Error(err))
		return err
	}

	for _, port := range ports {
		if err := execute.Execute("firewall-cmd", "--permanent", "--add-port="+port); err != nil {
			log.Error("Failed to allow port in firewalld", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	return execute.Execute("firewall-cmd", "--reload")
}
