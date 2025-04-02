// pkg/network/network.go
package network

import (
	"fmt"
	"os/exec"
	"strings"
)

// checkIPv6Enabled checks if IPv6 is enabled on the kernel.
func CheckIPv6Enabled() bool {
	out, err := exec.Command("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

// enableIPv6 attempts to enable IPv6 (requires root privileges).
func EnableIPv6() error {
	cmd := exec.Command("sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	return cmd.Run()
}

// getTailscaleIPv6 attempts to retrieve the first Tailscale IPv6 address.
func GetTailscaleIPv6() (string, error) {
	out, err := exec.Command("tailscale", "ip", "-6").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		ip := strings.TrimSpace(lines[0])
		return ip, nil
	}
	return "", fmt.Errorf("no Tailscale IPv6 address found")
}
