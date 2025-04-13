// pkg/system/user.go

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// SetPassword sets the Linux user's password using chpasswd.
func SetPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	return cmd.Run()
}

func UserExists(name string) bool {
	return exec.Command("id", name).Run() == nil
}

// CreateEosUser creates a special Eos system user "eos" with a secure password and no login shell.
func CreateEosUser(auto bool, loginShell bool) (string, error) {
	const defaultUsername = "eos"
	username := defaultUsername

	if UserExists(username) {
		return "", nil // Already exists
	}

	// Interactive prompt
	if !auto {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter username (default: eos): ")
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(input) != "" {
			username = strings.TrimSpace(input)
		}
	}

	shell := "/usr/sbin/nologin"
	if loginShell {
		shell = "/bin/bash"
	}

	if err := execute.Execute("useradd", "-m", "-s", shell, username); err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	var password string
	if auto {
		pw, err := crypto.GeneratePassword(20)
		if err != nil {
			return "", err
		}
		password = pw
	} else {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter password: ")
			pw1, _ := reader.ReadString('\n')
			pw1 = strings.TrimSpace(pw1)

			if !crypto.IsPasswordStrong(pw1) {
				fmt.Println("❌ Password is too weak. Please use at least 12 characters, a mix of upper/lowercase, number, and special character.")
				continue
			}

			fmt.Print("Confirm password: ")
			pw2, _ := reader.ReadString('\n')
			pw2 = strings.TrimSpace(pw2)

			if pw1 != pw2 {
				fmt.Println("❌ Passwords do not match. Try again.")
				continue
			}
			password = pw1
			break
		}
	}

	if err := SetPassword(username, password); err != nil {
		return "", err
	}

	adminGroup := platform.GuessAdminGroup()
	if !auto {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Should this user have sudo privileges? (yes/no): ")
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) == "no" {
			adminGroup = ""
		}
	}

	if adminGroup != "" {
		if err := execute.Execute("usermod", "-aG", adminGroup, username); err != nil {
			return "", fmt.Errorf("failed to add user to group: %w", err)
		}
	}

	// Save password to file
	secretsPath := "/var/lib/eos/secrets"
	if err := os.MkdirAll(secretsPath, 0700); err != nil {
		fmt.Printf("⚠️ Warning: could not create secrets directory: %v\n", err)
	} else {
		outFile := secretsPath + "/eos-password.txt"
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Println("⚠️ Warning: Could not save password to disk.")
		} else {
			defer func() {
				if cerr := f.Close(); cerr != nil {
					fmt.Printf("⚠️ Warning: failed to close file %s: %v\n", outFile, cerr)
				}
			}()

			if _, err := fmt.Fprintf(f, "eos:%s\n", password); err != nil {
				fmt.Printf("⚠️ Warning: failed to write password to file: %v\n", err)
			} else {
				fmt.Printf("🔐 eos password saved to: %s\n", outFile)
				fmt.Println("💡 Please store this password in a secure password manager.")
			}
		}
	}
	return username, nil
}
