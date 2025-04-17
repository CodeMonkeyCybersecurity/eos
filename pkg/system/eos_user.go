/* pkg/system/user.go */

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func EnsureEosUser(auto bool, loginShell bool, log *zap.Logger) error {
	const defaultUsername = "eos"
	username := defaultUsername

	// Check if user already exists
	if UserExists(username) {
		log.Info("✅ eos user exists")

		_, err := user.Lookup(username)
		if err != nil {
			return fmt.Errorf("failed to lookup user '%s': %w", username, err)
		}
		shell, err := getUserShell(username)
		if err != nil {
			return err
		}
		if !strings.Contains(shell, "nologin") {
			return fmt.Errorf("user '%s' has shell access: %s (expected /usr/sbin/nologin)", username, shell)
		}

		log.Info("✅ eos user has no shell access")
		log.Info("✅ eos user validation complete")
		return nil
	}

	log.Warn("👤 eos user not found — creating...")

	// Interactive username override (optional)
	if !auto {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter username (default: eos): ")
		input, _ := reader.ReadString('\n')
		if trimmed := strings.TrimSpace(input); trimmed != "" {
			username = trimmed
		}
	}

	// Determine login shell
	shell := "/usr/sbin/nologin"
	if loginShell {
		shell = "/bin/bash"
	}

	if err := execute.Execute("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Set password
	var password string
	if auto {
		pw, err := crypto.GeneratePassword(20)
		if err != nil {
			return err
		}
		password = pw
	} else {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter password: ")
			pw1, _ := reader.ReadString('\n')
			pw1 = strings.TrimSpace(pw1)

			if !crypto.IsPasswordStrong(pw1) {
				fmt.Println("❌ Password is too weak. Please use at least 12 characters, with mixed case, numbers, and symbols.")
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
		return err
	}

	// Handle sudo group
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
			return fmt.Errorf("failed to add user to group: %w", err)
		}
	}

	// Save password to secrets dir
	secretsPath := "/var/lib/eos/secrets"
	if err := os.MkdirAll(secretsPath, 0700); err != nil {
		fmt.Printf("⚠️ Could not create secrets directory: %v\n", err)
	} else {
		outFile := filepath.Join(secretsPath, "eos-password.txt")
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Println("⚠️ Could not save password to disk.")
		} else {
			defer f.Close()
			if _, err := fmt.Fprintf(f, "eos:%s\n", password); err != nil {
				fmt.Printf("⚠️ Failed to write password: %v\n", err)
			} else {
				fmt.Printf("🔐 eos password saved to: %s\n", outFile)
				fmt.Println("💡 Please store this password in a secure password manager.")
			}
		}
	}

	log.Info("✅ eos user created and configured")
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
