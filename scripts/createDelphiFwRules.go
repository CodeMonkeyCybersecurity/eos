package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// checkDistro determines if the system is Debian-based or RHEL-based
func checkDistro() string {
	output, err := exec.Command("cat", "/etc/os-release").Output()
	if err != nil {
		fmt.Println("Error reading /etc/os-release:", err)
		os.Exit(1)
	}

	osInfo := string(output)
	if strings.Contains(osInfo, "ID_LIKE=debian") || strings.Contains(osInfo, "ID=debian") || strings.Contains(osInfo, "ID=ubuntu") {
		return "debian"
	} else if strings.Contains(osInfo, "ID_LIKE=rhel") || strings.Contains(osInfo, "ID=rhel") || strings.Contains(osInfo, "ID=centos") || strings.Contains(osInfo, "ID=fedora") {
		return "rhel"
	}
	return "unknown"
}

// runCommand executes a shell command and prints output
func runCommand(command string, args ...string) {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing %s: %v\n", command, err)
	}
}

// configureRHELFirewall sets up Firewalld rules
func configureRHELFirewall() {
	fmt.Println("Detected RHEL-based system. Configuring Firewalld...")

	// Check if Firewalld is running
	runCommand("sudo", "firewall-cmd", "--state")

	// Allow required ports
  runCommand("sudo", "firewall-cmd", "--permanent", "--add-port=55000/tcp")
  runCommand("sudo", "firewall-cmd", "--permanent", "--add-port=1516/tcp")
	runCommand("sudo", "firewall-cmd", "--permanent", "--add-port=1515/tcp")
	runCommand("sudo", "firewall-cmd", "--permanent", "--add-port=1514/tcp")
	runCommand("sudo", "firewall-cmd", "--permanent", "--add-port=443/tcp")

	// Reload Firewalld
	runCommand("sudo", "firewall-cmd", "--reload")

	// Verify that the ports are open
	runCommand("sudo", "firewall-cmd", "--list-ports")

	// Allow HTTPS service if available
	runCommand("sudo", "firewall-cmd", "--permanent", "--add-service=https")
	runCommand("sudo", "firewall-cmd", "--reload")
}

// configureDebianFirewall sets up UFW rules
func configureDebianFirewall() {
	fmt.Println("Detected Debian-based system. Configuring UFW...")

	// Check if UFW is installed and enable it if necessary
	runCommand("sudo", "ufw", "enable")

	// Allow required ports
  runCommand("sudo", "ufw", "allow", "55000/tcp")
  runCommand("sudo", "ufw", "allow", "1516/tcp")
	runCommand("sudo", "ufw", "allow", "1515/tcp")
	runCommand("sudo", "ufw", "allow", "1514/tcp")
	runCommand("sudo", "ufw", "allow", "443/tcp")

	// Reload UFW
	runCommand("sudo", "ufw", "reload")

	// Verify that the rules are applied
	runCommand("sudo", "ufw", "status")
}

func main() {
	distro := checkDistro()

	switch distro {
	case "rhel":
		configureRHELFirewall()
	case "debian":
		configureDebianFirewall()
	default:
		fmt.Println("Unsupported Linux distribution detected.")
	}

	fmt.Println("finis")
}
