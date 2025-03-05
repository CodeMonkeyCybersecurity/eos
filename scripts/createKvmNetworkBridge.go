package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// Ensure the script is run as root.
	if os.Geteuid() != 0 {
		fmt.Println("This script must be run as root.")
		os.Exit(1)
	}

	// Detect the default interface by parsing the default route.
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("Error executing ip route: %v", err)
	}

	routeOutput := string(out)
	// Expected output: "default via <gateway> dev <interface> ..."
	var defaultIface string
	parts := strings.Fields(routeOutput)
	for i, part := range parts {
		if part == "dev" && i+1 < len(parts) {
			defaultIface = parts[i+1]
			break
		}
	}
	if defaultIface == "" {
		log.Fatalf("Could not determine the default interface from: %s", routeOutput)
	}
	fmt.Printf("Detected default interface: %s\n", defaultIface)

	// Optional: Check if the interface is already a bridge.
	bridgePath := fmt.Sprintf("/sys/class/net/%s/bridge", defaultIface)
	if _, err := os.Stat(bridgePath); err == nil {
		fmt.Printf("Interface %s is already a bridge. Exiting.\n", defaultIface)
		os.Exit(1)
	}

	// Build the Netplan configuration using the detected interface.
	// This configuration disables DHCP on the physical interface and enables DHCP on the new bridge.
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

	filePath := "/etc/netplan/99-kvm-bridge.yaml"
	err = os.WriteFile(filePath, []byte(config), 0644)
	if err != nil {
		log.Fatalf("Error writing configuration to %s: %v", filePath, err)
	}
	fmt.Printf("Netplan configuration written to %s\n", filePath)

	// Apply the new Netplan configuration.
	cmd = exec.Command("netplan", "apply")
	combinedOut, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error applying netplan configuration: %v\nOutput: %s", err, string(combinedOut))
	}
	fmt.Println("Netplan configuration applied successfully.")
}
