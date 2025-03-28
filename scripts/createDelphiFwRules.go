package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// checkDistro determines if the system is Debian-based or RHEL-based
func checkDistro() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		log.Printf("Error opening /etc/os-release, defaulting to 'unknown': %v", err)
		return "unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var id, idLike string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
		}
	}

	// Normalize to lowercase
	id = strings.ToLower(id)
	idLike = strings.ToLower(idLike)

	// Check for Debian-based OS
	if strings.Contains(id, "debian") || strings.Contains(idLike, "debian") || strings.Contains(id, "ubuntu") {
		return "debian"
	}

	// Check for RHEL-based OS (including CentOS Stream)
	if strings.Contains(id, "rhel") || strings.Contains(id, "centos") || strings.Contains(id, "fedora") ||
		strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") || strings.Contains(idLike, "centos") ||
		strings.Contains(id, "centos-stream") || strings.Contains(idLike, "platform:el") {
		return "rhel"
	}

	// Log unknown OS type for debugging
	log.Printf("Unknown OS detected: ID=%s, ID_LIKE=%s", id, idLike)

	// Explicit fallback
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
