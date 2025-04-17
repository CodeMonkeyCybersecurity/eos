/* pkg/system/user.go */

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"os/user"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"go.uber.org/zap"
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
func CreateEosUser(auto bool, loginShell bool, log *zap.Logger) (string, error) {

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

	adminGroup := platform.GuessAdminGroup(log)

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

// ensureEosUser ensures the 'eos' user exists and has the correct attributes.
func EnsureEosUser() error {
	const eosUsername = "eos"

	if !platform.UserExists(eosUsername) {
		fmt.Println("👤 eos user not found, creating...")
		if err := platform.EnsureSystemUserExists(eosUsername); err != nil {
			return fmt.Errorf("failed to create eos user: %w", err)
		}
		fmt.Println("✅ eos user created successfully")
	} else {
		fmt.Println("✅ eos user exists")

		u, err := user.Lookup(eosUsername)
		if err != nil {
			return fmt.Errorf("failed to lookup user '%s': %w", eosUsername, err)
		}

		// Basic sanity check on name
		if u.Username != eosUsername {
			return fmt.Errorf("⚠️ eos username mismatch '%s': %w", eosUsername, err)
		}

		// Check shell is nologin
		shell, err := getUserShell(eosUsername)
		if err != nil {
			return err
		}
		if !strings.Contains(shell, "nologin") {
			return fmt.Errorf("user '%s' has shell access: %s (expected /usr/sbin/nologin)", eosUsername, shell)
		}

		fmt.Println("✅ eos user has no shell access")
		fmt.Println("✅ eos user validation complete")
		return nil
	}
	return nil
}

func getUserShell(username string) (string, error) {
	cmd := exec.Command("getent", "passwd", username)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get shell for user '%s': %w", username, err)
	}
	parts := strings.Split(string(out), ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("unexpected passwd format for user '%s'", username)
	}
	return strings.TrimSpace(parts[6]), nil
}
