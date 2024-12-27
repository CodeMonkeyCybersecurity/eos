// cmd/update/hostname.go
package update

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var hostnameCmd = &cobra.Command{
	Use:   "hostname",
	Short: "Update the system hostname",
	Long:  `Update the system hostname by modifying /etc/hostname and /etc/hosts.`,
	Run: func(cmd *cobra.Command, args []string) {
		UpdateHostname()
	},
}

// UpdateHostname updates the system hostname
func UpdateHostname() {
	// Get the current hostname
	currentHostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("Error retrieving current hostname: %v\n", err)
		return
	}
	fmt.Printf("The current hostname is: %s\n", currentHostname)

	// Ask for confirmation to proceed
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to change the hostname? (yes/no): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "yes" {
		fmt.Println("Hostname change aborted.")
		return
	}

	// Ask for the new hostname
	fmt.Print("Enter the new hostname: ")
	newHostname, _ := reader.ReadString('\n')
	newHostname = strings.TrimSpace(newHostname)

	// Check if the input is not empty
	if newHostname == "" {
		fmt.Println("The hostname cannot be empty!")
		return
	}

	// Change the hostname temporarily
	err = exec.Command("sudo", "hostname", newHostname).Run()
	if err != nil {
		fmt.Printf("Error changing hostname temporarily: %v\n", err)
		return
	}

	// Change the hostname permanently
	err = exec.Command("sudo", "sh", "-c", fmt.Sprintf("echo %s > /etc/hostname", newHostname)).Run()
	if err != nil {
		fmt.Printf("Error changing hostname permanently: %v\n", err)
		return
	}

	// Update the /etc/hosts file
	err = exec.Command("sudo", "sed", "-i", fmt.Sprintf("s/%s/%s/g", currentHostname, newHostname), "/etc/hosts").Run()
	if err != nil {
		fmt.Printf("Error updating /etc/hosts file: %v\n", err)
		return
	}

	fmt.Printf("Hostname changed successfully to %s\n", newHostname)
}
