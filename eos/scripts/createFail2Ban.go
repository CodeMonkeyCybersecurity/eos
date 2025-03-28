package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runCommand(command string, args ...string) error {
	fmt.Printf("Running: %s %s\n", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	fmt.Println("Setting up Fail2Ban...")

	// Step 1: Install Fail2Ban
	fmt.Println("\nInstalling Fail2Ban...")
	if err := runCommand("sudo", "apt", "update"); err != nil {
		fmt.Println("Failed to update package list.")
		return
	}
	if err := runCommand("sudo", "apt", "install", "-y", "fail2ban"); err != nil {
		fmt.Println("Failed to install Fail2Ban.")
		return
	}

	// Step 2: Backup existing configuration
	fmt.Println("\nBacking up existing Fail2Ban configuration...")
	if err := runCommand("sudo", "cp", "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.conf.bak"); err != nil {
		fmt.Println("Failed to backup jail.conf.")
	}

	// Step 3: Create jail.local with recommended settings
	fmt.Println("\nCreating jail.local configuration...")
	config := `[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
`
	if err := os.WriteFile("/tmp/jail.local", []byte(config), 0644); err != nil {
		fmt.Println("Failed to create jail.local file.")
		return
	}
	if err := runCommand("sudo", "mv", "/tmp/jail.local", "/etc/fail2ban/jail.local"); err != nil {
		fmt.Println("Failed to move jail.local to /etc/fail2ban.")
		return
	}

	// Step 4: Restart Fail2Ban
	fmt.Println("\nRestarting Fail2Ban...")
	if err := runCommand("sudo", "systemctl", "restart", "fail2ban"); err != nil {
		fmt.Println("Failed to restart Fail2Ban.")
		return
	}

	// Step 5: Enable Fail2Ban on startup
	fmt.Println("\nEnabling Fail2Ban to start on boot...")
	if err := runCommand("sudo", "systemctl", "enable", "fail2ban"); err != nil {
		fmt.Println("Failed to enable Fail2Ban on startup.")
		return
	}

	// Step 6: Show status
	fmt.Println("\nChecking Fail2Ban status...")
	if err := runCommand("sudo", "fail2ban-client", "status"); err != nil {
		fmt.Println("Failed to get Fail2Ban status.")
		return
	}

	// Step 7: Check SSH jail status
	fmt.Println("\nChecking SSH jail status...")
	if err := runCommand("sudo", "fail2ban-client", "status", "sshd"); err != nil {
		fmt.Println("Failed to get SSH jail status.")
	}

	fmt.Println("\nFail2Ban setup completed successfully!")
}
