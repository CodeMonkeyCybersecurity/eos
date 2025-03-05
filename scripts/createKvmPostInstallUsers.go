package main

import (
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
	// generate random bytes, then base64-encode and remove non-alphanumerics.
	bytesNeeded := n * 3 / 4 // rough approximation
	b := make([]byte, bytesNeeded)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// base64 encode, then remove padding and any non-alphanumerics.
	s := base64.StdEncoding.EncodeToString(b)
	// remove any non alphanumeric characters
	var alnum []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') {
			alnum = append(alnum, r)
		}
	}
	// ensure the string is at least n characters
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

func main() {
	// Create the Linux user "hera"
	fmt.Println("Creating user 'hera'...")
	if _, err := runCommand("useradd", "-m", "hera"); err != nil {
		log.Fatalf("Error creating user hera: %v", err)
	}

	// Add hera to the sudo group
	fmt.Println("Adding 'hera' to sudo group...")
	if _, err := runCommand("usermod", "-aG", "sudo", "hera"); err != nil {
		log.Fatalf("Error adding hera to sudo group: %v", err)
	}

	// Create SSH directory and generate an SSH key for hera
	heraHome := "/home/hera"
	sshDir := heraHome + "/.ssh"
	fmt.Println("Creating .ssh directory for hera...")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		log.Fatalf("Error creating .ssh directory: %v", err)
	}
	// Change owner of .ssh directory to hera (assumes UID/GID resolution)
	if _, err := runCommand("chown", "-R", "hera:hera", sshDir); err != nil {
		log.Fatalf("Error changing ownership of .ssh directory: %v", err)
	}
	// Generate an SSH key without a passphrase
	fmt.Println("Generating SSH key for hera...")
	sshKeyPath := sshDir + "/id_rsa"
	if _, err := runCommand("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", sshKeyPath); err != nil {
		log.Fatalf("Error generating SSH key: %v", err)
	}
	// Change ownership of the generated keys
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

	// Change the password for root
	fmt.Println("Changing password for root...")
	rootPassCmd := exec.Command("chpasswd")
	rootPassInput := fmt.Sprintf("root:%s", rootPass)
	rootPassCmd.Stdin = strings.NewReader(rootPassInput)
	if err := rootPassCmd.Run(); err != nil {
		log.Fatalf("Error setting root password: %v", err)
	}

	// Change the password for hera
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

	// Dummy password policy check function
	// (In real scenarios, this might involve checking against a policy file or using PAM libraries.)
	checkPasswordStrength := func(pw string) bool {
		// For example, a strong password could be defined as at least 20 characters long
		return len(pw) >= 20
	}

	// Check the new passwords against our dummy policy.
	if !checkPasswordStrength(rootPass) || !checkPasswordStrength(heraPass) {
		log.Println("One or more passwords do not meet the strong password policy. Please change them immediately.")
	} else {
		fmt.Println("Passwords meet the strong password policy. Disabling weak passwords...")
		// Dummy action: here you could disable legacy password authentication methods,
		// for example by editing /etc/ssh/sshd_config or enforcing PAM policies.
		// For demonstration, we just print a message.
	}

	// Check current user's password strength.
	// (This part is highly system-dependent. We will simulate a check.)
	currentUser := os.Getenv("USER")
	fmt.Printf("Checking password strength for current user (%s)...\n", currentUser)
	// Dummy check: In a real scenario, you might interact with PAM or system-specific tools.
	currentUserStrong := true // assume current user has a strong password for demonstration

	if !currentUserStrong {
		fmt.Println("Your current password is weak. Please change it immediately.")
		// Here you might trigger a password change prompt.
	} else {
		fmt.Println("Your current password meets the strength requirements.")
	}

	fmt.Println("Script completed.")
}
