// pkg/platform/firewall.go

package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// AllowPorts opens multiple ports based on the system's firewall backend.
func AllowPorts(ports []string) error {
	switch {
	case hasBinary("ufw"):
		zap.L().Info("Using UFW for firewall changes")
		return allowPortsUFW(ports)
	case hasBinary("firewall-cmd"):
		zap.L().Info("Using Firewalld for firewall changes")
		return allowPortsFirewalld(ports)
	case hasBinary("pfctl"):
		zap.L().Info("Detected macOS PF firewall — not yet supported")
		return fmt.Errorf("macOS firewall (pfctl) support not yet implemented")
	default:
		zap.L().Warn("⚠️ No supported firewall backend found")
		return fmt.Errorf("no supported firewall backend (ufw, firewalld, pfctl)")
	}
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// CheckFirewallStatus tries UFW, then iptables, and prints the firewall status.
func CheckFirewallStatus() {
	fmt.Println("🔍 Checking firewall status...")

	if hasBinary("ufw") {
		zap.L().Info("UFW detected")
		out, err := exec.Command("ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			zap.L().Warn("Failed to get UFW status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	if hasBinary("iptables") {
		zap.L().Info("iptables detected")
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
	_, err := execute.Run(execute.Options{Command: "ufw", Args: []string{"enable"}})
	if err != nil {
		zap.L().Warn("UFW already enabled or error", zap.Error(err))
	}

	for _, port := range ports {
		_, err := execute.Run(execute.Options{Command: "ufw", Args: []string{"allow", port}})
		if err != nil {
			zap.L().Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	_, err = execute.Run(execute.Options{Command: "ufw", Args: []string{"reload"}})
	return err
}

func allowPortsFirewalld(ports []string) error {
	_, err := execute.Run(execute.Options{Command: "firewall-cmd", Args: []string{"--state"}})
	if err != nil {
		zap.L().Error("Firewalld not running", zap.Error(err))
		return err
	}

	for _, port := range ports {
		arg := "--add-port=" + port
		_, err := execute.Run(execute.Options{
			Command: "firewall-cmd",
			Args:    []string{"--permanent", arg},
		})
		if err != nil {
			zap.L().Error("Failed to allow port in firewalld", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	_, err = execute.Run(execute.Options{Command: "firewall-cmd", Args: []string{"--reload"}})
	return err
}
