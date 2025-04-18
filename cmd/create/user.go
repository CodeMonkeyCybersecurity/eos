package create

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runCreateUser(cmd, args)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateUserCmd)
	CreateUserCmd.Flags().StringVar(&username, "username", "eos", "Username for the new account")
	CreateUserCmd.Flags().BoolVar(&auto, "auto", false, "Enable non-interactive auto mode with secure random password")
	CreateUserCmd.Flags().BoolVar(&loginShell, "login", false, "Allow login shell for this user (default is no shell)")
}

// runCreateUser coordinates all steps needed to create a new user.
func runCreateUser(_ *cobra.Command, _ []string) error {
	log := logger.L()

	// Setup a signal handler for graceful cancellation.
	setupSignalHandler()

	// Ensure we're running with root privileges.
	if os.Geteuid() != 0 {
		return errors.New("please run as root or with sudo")
	}

	reader := bufio.NewReader(os.Stdin)
	if !auto {
		// Prompt for username interactively.
		input, err := prompt(reader, "Enter new username (default: eos): ")
		if err != nil {
			return err
		}
		if input != "" {
			username = input
		}
	}

	// Exit early if the user already exists.
	if system.UserExists(username) {
		log.Warn("User already exists", zap.String("username", username))
		return nil
	}

	// Determine the login shell.
	shell := "/usr/sbin/nologin"
	if loginShell {
		log.Info("Creating user with login shell")
		shell = "/bin/bash"
	} else {
		log.Info("Creating system user with no login shell")
	}

	// Create the new user.
	log.Info("Creating user", zap.String("username", username))
	if err := execute.Execute("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Determine the password.
	var password string
	if auto {
		pw, err := crypto.GeneratePassword(20)
		if err != nil {
			return err
		}
		password = pw
	} else {
		pw1, err := prompt(reader, "Enter password: ")
		if err != nil {
			return err
		}
		pw2, err := prompt(reader, "Confirm password: ")
		if err != nil {
			return err
		}
		if strings.TrimSpace(pw1) != strings.TrimSpace(pw2) {
			return errors.New("passwords do not match")
		}
		password = strings.TrimSpace(pw1)
	}

	// Set the user password.
	if err := system.SetPassword(username, password); err != nil {
		return err
	}

	// Decide if the user should have admin privileges.
	adminGroup := platform.GuessAdminGroup(log)
	if !auto {
		input, err := prompt(reader, "Should this user have sudo privileges? (yes/no): ")
		if err != nil {
			return err
		}
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

	// Generate SSH keys.
	if err := createSSHKeys(username); err != nil {
		return err
	}

	fmt.Println("✅ User created:", username)
	fmt.Println("🔐 Password:", password)
	fmt.Println("📁 SSH key:", "/home/"+username+"/.ssh/id_rsa")

	// Attempt to store the credentials in Vault.
	if err := vault.StoreUserSecret(username, password, "/home/"+username+"/.ssh/id_rsa", log); err != nil {
		log.Warn("Vault is not available or write failed", zap.Error(err))
		fmt.Println("⚠️ Vault write failed. Save these credentials manually:")
		fmt.Printf("🔐 Password for %s: %s\n", username, password)
	} else {
		log.Info("User credentials securely stored in Vault")
		fmt.Println("🔐 Credentials stored in Vault for user:", username)
	}

	return nil
}

// setupSignalHandler catches Ctrl+C and cancels the operation.
func setupSignalHandler() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n❌ Operation canceled.")
		os.Exit(1)
	}()
}

// prompt prints a message and returns trimmed input from the user.
func prompt(reader *bufio.Reader, message string) (string, error) {
	fmt.Print(message)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// createSSHKeys generates SSH key pair for the new user and sets proper permissions.
func createSSHKeys(username string) error {
	log := logger.L()
	home := "/home/" + username
	sshDir := home + "/.ssh"

	log.Info("Creating SSH key for user", zap.String("username", username))
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH directory: %w", err)
	}
	if err := execute.Execute("chown", "-R", username+":"+username, sshDir); err != nil {
		return fmt.Errorf("failed to set ownership on SSH directory: %w", err)
	}

	keyPath := sshDir + "/id_rsa"
	if err := execute.Execute("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", keyPath); err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}
	if err := execute.Execute("chown", username+":"+username, keyPath, keyPath+".pub"); err != nil {
		return fmt.Errorf("failed to set ownership on SSH keys: %w", err)
	}

	return nil
}
