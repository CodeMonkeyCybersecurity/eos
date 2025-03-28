package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// Get the current hostname
	currentHostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error retrieving hostname:", err)
		return
	}
	fmt.Println("The current hostname is:", currentHostname)

	// Ask for confirmation
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to change the hostname? (yes/no) ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)

	if strings.EqualFold(confirm, "yes") {
		// Ask for the new hostname
		fmt.Print("Enter the new hostname: ")
		newHostname, _ := reader.ReadString('\n')
		newHostname = strings.TrimSpace(newHostname)

		// Check if input is not empty
		if newHostname == "" {
			fmt.Println("The hostname cannot be empty!")
			return
		}

		// Change hostname temporarily
		err = exec.Command("sudo", "hostname", newHostname).Run()
		if err != nil {
			fmt.Println("Error changing hostname temporarily:", err)
			return
		}

		// Change hostname permanently
		hostnameFile, err := os.OpenFile("/etc/hostname", os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Println("Error opening /etc/hostname:", err)
			return
		}
		defer hostnameFile.Close()

		_, err = hostnameFile.WriteString(newHostname + "\n")
		if err != nil {
			fmt.Println("Error writing to /etc/hostname:", err)
			return
		}

		// Update /etc/hosts file
		cmd := exec.Command("sudo", "sed", "-i", fmt.Sprintf("s/%s/%s/g", currentHostname, newHostname), "/etc/hosts")
		if err := cmd.Run(); err != nil {
			fmt.Println("Error updating /etc/hosts:", err)
			return
		}

		fmt.Println("Hostname changed successfully to", newHostname)
	} else {
		fmt.Println("Hostname change aborted.")
	}
}
