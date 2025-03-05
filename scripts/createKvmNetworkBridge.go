package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	// Ensure the script is run as root.
	if os.Geteuid() != 0 {
		fmt.Println("This script must be run as root.")
		os.Exit(1)
	}

	// Backup current Netplan configuration.
	backupNetplanConfigs()

	// Detect the default interface by parsing the default route.
	defaultIface, err := detectDefaultInterface()
	if err != nil {
		log.Fatalf("Error detecting default interface: %v", err)
	}
	fmt.Printf("Detected default interface: %s\n", defaultIface)

	// Optional: Check if the interface is already a bridge.
	bridgePath := filepath.Join("/sys/class/net", defaultIface, "bridge")
	if _, err := os.Stat(bridgePath); err == nil {
		fmt.Printf("Interface %s is already a bridge. Exiting.\n", defaultIface)
		os.Exit(1)
	}

	// Build the Netplan configuration using the detected interface.
	config := fmt.Sprintf(`network:
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
`, defaultIface, defaultIface)

	// Write the new configuration to a file.
	filePath := "/etc/netplan/99-kvm-bridge.yaml"
	err = os.WriteFile(filePath, []byte(config), 0644)
	if err != nil {
		log.Fatalf("Error writing configuration to %s: %v", filePath, err)
	}
	fmt.Printf("Netplan configuration written to %s\n", filePath)

	// Apply the new Netplan configuration.
	cmd := exec.Command("netplan", "apply")
	combinedOut, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error applying netplan configuration: %v\nOutput: %s", err, string(combinedOut))
	}
	fmt.Println("Netplan configuration applied successfully.")
}

// detectDefaultInterface runs "ip route show default" and extracts the default interface.
func detectDefaultInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	routeOutput := string(out)
	// Expected output example: "default via <gateway> dev <interface> ..."
	parts := strings.Fields(routeOutput)
	for i, part := range parts {
		if part == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("default interface not found in: %s", routeOutput)
}

// backupNetplanConfigs copies the /etc/netplan directory to a backup folder with a timestamp.
func backupNetplanConfigs() {
	timestamp := time.Now().Format("20060102-150405")
	backupDir := fmt.Sprintf("/etc/netplan_backup_%s", timestamp)
	
	// Create backup directory.
	if err := os.Mkdir(backupDir, 0755); err != nil {
		log.Fatalf("Error creating backup directory %s: %v", backupDir, err)
	}
	
	// Use the "cp" command to copy contents.
	cmd := exec.Command("cp", "-r", "/etc/netplan/.", backupDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("Error backing up Netplan configurations: %v\nOutput: %s", err, string(out))
	}
	fmt.Printf("Netplan configurations backed up to %s\n", backupDir)
}
