// pkg/system/kvmbridge.go

package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	bridgePath := filepath.Join("/sys/class/net", iface, "bridge")
	if _, err := os.Stat(bridgePath); err == nil {
		fmt.Printf("🔁 Interface %s is already bridged.\n", iface)
		return nil
	}

	content := fmt.Sprintf(`network:
  version: 2
  renderer: networkd
  ethernets:
    %s:
      dhcp4: no
  bridges:
    br0:
      interfaces: [%s]
      dhcp4: true
      parameters:
        stp: false
        forward-delay: 0
`, iface, iface)

	filePath := "/etc/netplan/99-kvm-bridge.yaml"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write netplan bridge config: %w", err)
	}

	cmd := exec.Command("sudo", "netplan", "apply")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply netplan config: %w\nOutput: %s", err, string(out))
	}

	fmt.Println("✅ Bridge configured via netplan.")
	return nil
}

func detectDefaultInterface() (string, error) {
	cmd := exec.Command("sudo", "ip", "route", "show", "default")
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

	cmd := exec.Command("sudo", "cp", "-r", "/etc/netplan/.", backupDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to back up Netplan configs: %w\nOutput: %s", err, string(out))
	}

	fmt.Printf("🧾 Netplan configs backed up to %s\n", backupDir)
	return nil
}
