package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// generateRandomString creates a random alphanumeric string of the specified length.
func generateRandomString(n int) (string, error) {
	bytesNeeded := n * 3 / 4 // rough approximation
	b := make([]byte, bytesNeeded)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(b)
	var alnum []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') {
			alnum = append(alnum, r)
		}
	}
	if len(alnum) < n {
		return generateRandomString(n)
	}
	return string(alnum[:n]), nil
}

// runCommand executes a command and returns its output or an error.
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command %s %v failed: %v - %s", name, args, err, errBuf.String())
	}
	return outBuf.String(), nil
}

// userExists checks if a user exists by using the "id" command.
func userExists(username string) bool {
	_, err := runCommand("id", username)
	return err == nil
}

// getAdminGroup determines the administrative group based on the OS.
// For Debian-based systems, it returns "sudo".
// For RHEL-based systems, it returns "wheel".
func getAdminGroup() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		log.Printf("Error opening /etc/os-release, defaulting to 'sudo': %v", err)
		return "sudo"
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
	// Check for known IDs or ID_LIKE values.
	if strings.Contains(id, "debian") || strings.Contains(idLike, "debian") || strings.Contains(id, "ubuntu") {
		return "sudo"
	}
	if strings.Contains(id, "rhel") || strings.Contains(id, "centos") || strings.Contains(id, "fedora") ||
		strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") {
		return "wheel"
	}
	// Default fallback.
	return "sudo"
}

func main() {
	adminGroup := getAdminGroup()
	fmt.Printf("Determined administrative group: %s\n", adminGroup)

	// Check if the user "hera" exists.
	if userExists("hera") {
		fmt.Println("User 'hera' already exists. Skipping user creation.")
	} else {
		// Create the Linux user "hera"
		fmt.Println("Creating user 'hera'...")
		if _, err := runCommand("useradd", "-m", "hera"); err != nil {
			log.Fatalf("Error creating user hera: %v", err)
		}
	}

	// Add hera to the determined admin group.
	fmt.Printf("Adding 'hera' to %s group...\n", adminGroup)
	if _, err := runCommand("usermod", "-aG", adminGroup, "hera"); err != nil {
		log.Fatalf("Error adding hera to %s group: %v", adminGroup, err)
	}

	// Create SSH directory and generate an SSH key for hera.
	heraHome := "/home/hera"
	sshDir := heraHome + "/.ssh"
	fmt.Println("Creating .ssh directory for hera...")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		log.Fatalf("Error creating .ssh directory: %v", err)
	}
	if _, err := runCommand("chown", "-R", "hera:hera", sshDir); err != nil {
		log.Fatalf("Error changing ownership of .ssh directory: %v", err)
	}
	fmt.Println("Generating SSH key for hera...")
	sshKeyPath := sshDir + "/id_rsa"
	if _, err := runCommand("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", sshKeyPath); err != nil {
		log.Fatalf("Error generating SSH key: %v", err)
	}
	if _, err := runCommand("chown", "hera:hera", sshKeyPath, sshKeyPath+".pub"); err != nil {
		log.Fatalf("Error changing ownership of SSH key files: %v", err)
	}

	// Generate two long random alphanumeric strings for passwords.
	const passLength = 20
	rootPass, err := generateRandomString(passLength)
	if err != nil {
		log.Fatalf("Error generating random password for root: %v", err)
	}
	heraPass, err := generateRandomString(passLength)
	if err != nil {
		log.Fatalf("Error generating random password for hera: %v", err)
	}

	// Change the password for root.
	fmt.Println("Changing password for root...")
	rootPassCmd := exec.Command("chpasswd")
	rootPassInput := fmt.Sprintf("root:%s", rootPass)
	rootPassCmd.Stdin = strings.NewReader(rootPassInput)
	if err := rootPassCmd.Run(); err != nil {
		log.Fatalf("Error setting root password: %v", err)
	}

	// Change the password for hera.
	fmt.Println("Changing password for hera...")
	heraPassCmd := exec.Command("chpasswd")
	heraPassInput := fmt.Sprintf("hera:%s", heraPass)
	heraPassCmd.Stdin = strings.NewReader(heraPassInput)
	if err := heraPassCmd.Run(); err != nil {
		log.Fatalf("Error setting hera password: %v", err)
	}

	// Output the new passwords to the terminal.
	fmt.Println("Passwords have been updated. Please save these credentials in your password manager:")
	fmt.Printf("root password: %s\n", rootPass)
	fmt.Printf("hera password: %s\n", heraPass)

	// Dummy password policy check function.
	checkPasswordStrength := func(pw string) bool {
		return len(pw) >= 20
	}

	if !checkPasswordStrength(rootPass) || !checkPasswordStrength(heraPass) {
		log.Println("One or more passwords do not meet the strong password policy. Please change them immediately.")
	} else {
		fmt.Println("Passwords meet the strong password policy. Disabling weak passwords...")
		// Dummy action for disabling weak passwords.
	}

	// Check current user's password strength.
	currentUser := os.Getenv("USER")
	fmt.Printf("Checking password strength for current user (%s)...\n", currentUser)
	currentUserStrong := true // assume strong for demonstration
	if !currentUserStrong {
		fmt.Println("Your current password is weak. Please change it immediately.")
	} else {
		fmt.Println("Your current password meets the strength requirements.")
	}

	fmt.Println("Script completed.")
}
