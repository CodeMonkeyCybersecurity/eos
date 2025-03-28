package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runCommand runs a command and prints its output.
func runCommand(name string, args ...string) error {
	fmt.Printf("Running command: %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Update and upgrade system packages.
	if err := runCommand("sudo", "apt", "update"); err != nil {
		fmt.Println("Error during apt update:", err)
		return
	}
	if err := runCommand("sudo", "apt", "upgrade", "-y"); err != nil {
		fmt.Println("Error during apt upgrade:", err)
		return
	}

	// Install XFCE and xrdp.
	if err := runCommand("sudo", "apt", "install", "xfce4", "xfce4-goodies", "-y"); err != nil {
		fmt.Println("Error installing xfce4:", err)
		return
	}
	if err := runCommand("sudo", "apt", "install", "xrdp", "-y"); err != nil {
		fmt.Println("Error installing xrdp:", err)
		return
	}

	// Add the xrdp user to the ssl-cert group.
	if err := runCommand("sudo", "adduser", "xrdp", "ssl-cert"); err != nil {
		fmt.Println("Error adding xrdp to ssl-cert:", err)
		return
	}

	// Configure UFW for RDP.
	if err := runCommand("sudo", "ufw", "allow", "3389/tcp"); err != nil {
		fmt.Println("Error allowing port 3389:", err)
		return
	}
	if err := runCommand("sudo", "ufw", "reload"); err != nil {
		fmt.Println("Error reloading UFW:", err)
		return
	}

	// Ask user for the new username.
	fmt.Print("Enter the new username: ")
	newUsername, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading username:", err)
		return
	}
	newUsername = strings.TrimSpace(newUsername)

	// Create new user with a home directory and bash shell.
	if err := runCommand("sudo", "useradd", "-m", newUsername, "--shell", "/bin/bash"); err != nil {
		fmt.Println("Error creating new user:", err)
		return
	}

	// Set the password for the new user.
	if err := runCommand("sudo", "passwd", newUsername); err != nil {
		fmt.Println("Error setting password for new user:", err)
		return
	}

	// Add the new user to the sudo group.
	if err := runCommand("sudo", "usermod", "-aG", "sudo", newUsername); err != nil {
		fmt.Println("Error adding user to sudo group:", err)
		return
	}

	// Create the .xsession file with the content "xfce4-session".
	xsessionPath := fmt.Sprintf("/home/%s/.xsession", newUsername)
	echoCmd := fmt.Sprintf("echo 'xfce4-session' > %s", xsessionPath)
	if err := runCommand("sudo", "bash", "-c", echoCmd); err != nil {
		fmt.Println("Error creating .xsession file:", err)
		return
	}

	// Make the .xsession file executable.
	if err := runCommand("sudo", "chmod", "+x", xsessionPath); err != nil {
		fmt.Println("Error setting .xsession as executable:", err)
		return
	}

	// Restart the xrdp service.
	if err := runCommand("sudo", "systemctl", "restart", "xrdp"); err != nil {
		fmt.Println("Error restarting xrdp:", err)
		return
	}

	fmt.Println("Script completed successfully!")
}
