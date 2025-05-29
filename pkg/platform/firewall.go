// pkg/platform/firewall.go

package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AllowPorts opens multiple ports based on the system's firewall backend.
func AllowPorts(rc *eos_io.RuntimeContext, ports []string) error {
	switch {
	case hasBinary("ufw"):
		otelzap.Ctx(rc.Ctx).Info("Using UFW for firewall changes")
		return allowPortsUFW(rc, ports)
	case hasBinary("firewall-cmd"):
		otelzap.Ctx(rc.Ctx).Info("Using Firewalld for firewall changes")
		return allowPortsFirewalld(rc, ports)
	case hasBinary("pfctl"):
		otelzap.Ctx(rc.Ctx).Info("Detected macOS PF firewall — not yet supported")
		return fmt.Errorf("macOS firewall (pfctl) support not yet implemented")
	default:
		otelzap.Ctx(rc.Ctx).Warn("⚠️ No supported firewall backend found")
		return fmt.Errorf("no supported firewall backend (ufw, firewalld, pfctl)")
	}
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// CheckFirewallStatus tries UFW, then iptables, and prints the firewall status.
func CheckFirewallStatus(rc *eos_io.RuntimeContext) {
	fmt.Println("🔍 Checking firewall status...")

	if hasBinary("ufw") {
		otelzap.Ctx(rc.Ctx).Info("UFW detected")
		out, err := exec.Command("ufw", "status", "verbose").CombinedOutput()
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to get UFW status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	if hasBinary("iptables") {
		otelzap.Ctx(rc.Ctx).Info("iptables detected")
		out, err := exec.Command("iptables", "-L", "-n").CombinedOutput()
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to get iptables status", zap.Error(err))
		} else {
			fmt.Println(string(out))
		}
		return
	}

	otelzap.Ctx(rc.Ctx).Warn("No supported firewall tool found (ufw or iptables)")
}

func allowPortsUFW(rc *eos_io.RuntimeContext, ports []string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{Command: "ufw", Args: []string{"enable"}})
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("UFW already enabled or error", zap.Error(err))
	}

	for _, port := range ports {
		_, err := execute.Run(rc.Ctx, execute.Options{Command: "ufw", Args: []string{"allow", port}})
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	_, err = execute.Run(rc.Ctx, execute.Options{Command: "ufw", Args: []string{"reload"}})
	return err
}

func allowPortsFirewalld(rc *eos_io.RuntimeContext, ports []string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{Command: "firewall-cmd", Args: []string{"--state"}})
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Firewalld not running", zap.Error(err))
		return err
	}

	for _, port := range ports {
		arg := "--add-port=" + port
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "firewall-cmd",
			Args:    []string{"--permanent", arg},
		})
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to allow port in firewalld", zap.String("port", port), zap.Error(err))
			return err
		}
	}

	_, err = execute.Run(rc.Ctx, execute.Options{Command: "firewall-cmd", Args: []string{"--reload"}})
	return err
}
