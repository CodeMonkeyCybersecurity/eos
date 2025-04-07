// cmd/create/user.go

package create

import (
	"bufio"

	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	username   string
	auto       bool
	loginShell bool
)

var CreateUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a new Linux user",
	Long: `Creates a new user account and optionally adds them to the admin group, 
generates SSH keys, and sets a secure password.`,
	RunE: runCreateUser,
}

func init() {
	CreateCmd.AddCommand(CreateUserCmd)
	CreateUserCmd.Flags().StringVar(&username, "username", "eos", "Username for the new account")
	CreateUserCmd.Flags().BoolVar(&auto, "auto", false, "Enable non-interactive auto mode with secure random password")
	CreateUserCmd.Flags().BoolVar(&loginShell, "login", false, "Allow login shell for this user (default is no shell)")
}

func runCreateUser(cmd *cobra.Command, args []string) error {
	log := logger.L()

	// Ctrl+C cancel handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n❌ Operation canceled.")
		os.Exit(1)
	}()

	if os.Geteuid() != 0 {
		return errors.New("please run as root or with sudo")
	}

	reader := bufio.NewReader(os.Stdin)

	// Prompt if interactive
	if !auto {
		fmt.Print("Enter new username (default: eos): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			username = input
		}
	}

	// Check if user exists
	if system.UserExists(username) {
		log.Warn("User already exists", zap.String("username", username))
		return nil
	}

	shell := "/usr/sbin/nologin"
	if loginShell {
		log.Info("Creating user with login shell")
		shell = "/bin/bash"
	} else {
		log.Info("Creating system user with no login shell")
	}

	log.Info("Creating user", zap.String("username", username))
	if err := execute.Execute("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Set password
	var password string
	if auto {
		pw, err := utils.GeneratePassword(20)
		if err != nil {
			return err
		}
		password = pw
	} else {
		fmt.Print("Enter password: ")
		pw1, _ := reader.ReadString('\n')
		fmt.Print("Confirm password: ")
		pw2, _ := reader.ReadString('\n')
		if strings.TrimSpace(pw1) != strings.TrimSpace(pw2) {
			return errors.New("passwords do not match")
		}
		password = strings.TrimSpace(pw1)
	}

	if err := system.SetPassword(username, password); err != nil {
		return err
	}

	// Admin group prompt or auto-detect
	adminGroup := platform.GuessAdminGroup()
	if !auto {
		fmt.Print("Should this user have sudo privileges? (yes/no): ")
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) == "no" {
			adminGroup = ""
		}
	}

	if adminGroup != "" {
		log.Info("Granting admin privileges", zap.String("group", adminGroup))
		if err := execute.Execute("usermod", "-aG", adminGroup, username); err != nil {
			return fmt.Errorf("error adding to admin group: %w", err)
		}
	}

	// SSH keygen
	home := "/home/" + username
	sshDir := home + "/.ssh"
	log.Info("Creating SSH key")
	_ = os.MkdirAll(sshDir, 0700)
	_ = execute.Execute("chown", "-R", username+":"+username, sshDir)

	keyPath := sshDir + "/id_rsa"
	_ = execute.Execute("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", keyPath)
	_ = execute.Execute("chown", username+":"+username, keyPath, keyPath+".pub")

	fmt.Println("✅ User created:", username)
	fmt.Println("🔐 Password:", password)
	fmt.Println("📁 SSH key:", keyPath)

	// Attempt to store password in Vault
	if err := vault.StoreUserSecret(username, password, keyPath); err != nil {
		log.Warn("Vault is not available or write failed", zap.Error(err))
		fmt.Println("⚠️ Vault write failed. Save these credentials manually:")
		fmt.Printf("🔐 Password for %s: %s\n", username, password)
	} else {
		log.Info("User credentials securely stored in Vault")
		fmt.Println("🔐 Credentials stored in Vault for user:", username)
	}
	return nil
}
