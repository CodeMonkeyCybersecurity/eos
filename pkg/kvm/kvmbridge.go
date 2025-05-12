// pkg/kvm/kvmbridge.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

func ConfigureKVMBridge() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to configure netplan bridge")
	}

	if err := backupNetplanConfigs(); err != nil {
		return err
	}

	iface, err := detectDefaultInterface()
	if err != nil {
		return err
	}

	// Check if a bridge already exists
	existing, err := exec.Command("ip", "link", "show", "br0").CombinedOutput()
	if err == nil && strings.Contains(string(existing), "br0") {
		fmt.Println("🔁 br0 already exists; skipping bridge creation.")
		return nil
	}

	// Render bridge YAML with IPv6 enabled
	content := fmt.Sprintf(`network:
  version: 2
  renderer: networkd
  ethernets:
    %[1]s:
      dhcp4: no
      dhcp6: no
  bridges:
    br0:
      interfaces: [%[1]s]
      dhcp4: true
      dhcp6: true
      accept-ra: true
      parameters:
        stp: false
        forward-delay: 0
`, iface)

	bridgeFile := "/etc/netplan/99-kvm-bridge.yaml"
	if err := os.WriteFile(bridgeFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write bridge config: %w", err)
	}

	cmd := exec.Command("netplan", "apply")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply netplan: %w\nOutput: %s", err, string(out))
	}

	fmt.Println("✅ br0 bridge configured and applied.")
	return nil
}

func detectDefaultInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(out))
	for i := range parts {
		if parts[i] == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("default interface not found in: %s", string(out))
}

func backupNetplanConfigs() error {
	timestamp := time.Now().Format("20060102-150405")
	backupDir := fmt.Sprintf("/etc/netplan_backup_%s", timestamp)

	if err := os.Mkdir(backupDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	cmd := exec.Command("cp", "-r", "/etc/netplan/.", backupDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to back up Netplan configs: %w\nOutput: %s", err, string(out))
	}

	fmt.Printf("🧾 Netplan configs backed up to %s\n", backupDir)
	return nil
}
