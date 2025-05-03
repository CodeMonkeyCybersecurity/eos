package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// AllowPorts opens multiple ports based on the system's firewall backend.
func AllowPorts(ports []string) error {
	if _, err := exec.LookPath("ufw"); err == nil {
		zap.L().Info("Using UFW for firewall changes")
		return allowPortsUFW(ports)
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		zap.L().Info("Using Firewalld for firewall changes")
		return allowPortsFirewalld(ports)
	}
	if _, err := exec.LookPath("pfctl"); err == nil {
		zap.L().Info("Detected macOS PF firewall — not yet supported")
		return fmt.Errorf("macOS firewall (pfctl) support not yet implemented")
	}

	zap.L().Warn("⚠️ No supported firewall backend found")
	return fmt.Errorf("no supported firewall backend (ufw, firewalld, pfctl)")
}

// CheckFirewallStatus tries UFW, then iptables, and returns a string status.
func CheckFirewallStatus() {
	fmt.Println("🔍 Checking firewall status...")

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		zap.L().Info("UFW detected", zap.String("path", ufwPath))
		out, err := exec.Command("ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			zap.L().Warn("Failed to get UFW status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		zap.L().Info("iptables detected", zap.String("path", iptablesPath))
		out, err := exec.Command("iptables", "-L", "-n").CombinedOutput()
		if err != nil {
			zap.L().Warn("Failed to get iptables status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	zap.L().Warn("No supported firewall tool found (ufw or iptables)")
}

func allowPortsUFW(ports []string) error {
	if err := execute.Execute("ufw", "enable"); err != nil {
		zap.L().Warn("UFW already enabled or error", zap.Error(err))
	}

	for _, port := range ports {
		if err := execute.Execute("ufw", "allow", port); err != nil {
			zap.L().Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	return execute.Execute("ufw", "reload")
}

func allowPortsFirewalld(ports []string) error {
	if err := execute.Execute("firewall-cmd", "--state"); err != nil {
		zap.L().Error("Firewalld not running", zap.Error(err))
		return err
	}

	for _, port := range ports {
		if err := execute.Execute("firewall-cmd", "--permanent", "--add-port="+port); err != nil {
			zap.L().Error("Failed to allow port in firewalld", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	return execute.Execute("firewall-cmd", "--reload")
}
