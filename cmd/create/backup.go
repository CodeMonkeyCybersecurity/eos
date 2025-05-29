/*
cmd/create/backup.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/

package create

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateBackupCmd represents the create backup command
var CreateBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a new restic backup",
	Long: `This command initializes a restic repository if not already initialized,
then creates a backup of specified directories.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		// Step 1: Ensure Restic is Installed
		otelzap.Ctx(rc.Ctx).Info("Ensuring Restic is installed")
		if err := ensureResticInstalled(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to ensure Restic is installed", zap.Error(err))
			return err
		}

		// Step 2: Generate SSH Keys
		otelzap.Ctx(rc.Ctx).Info("Generating SSH keys for backup")
		if err := generateSSHKeys(); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to generate SSH keys", zap.Error(err))
			return err
		}

		// Step 3: Copy SSH Keys to Backup Server
		otelzap.Ctx(rc.Ctx).Info("Copying SSH keys to the backup server")
		if err := copySSHKeys(); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to copy SSH keys", zap.Error(err))
			return err
		}

		// Step 4: Initialize Restic Repository
		otelzap.Ctx(rc.Ctx).Info("Initializing restic repository")
		if err := initializeResticRepo(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to initialize restic repository", zap.Error(err))
			return err
		}

		// Step 5: Backup Data
		otelzap.Ctx(rc.Ctx).Info("Backing up data")
		if err := performResticBackup(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to backup data", zap.Error(err))
			return err
		}

		otelzap.Ctx(rc.Ctx).Info("Backup completed successfully")
		return nil
	}),
}

// ensureResticInstalled ensures Restic is installed on the system
func ensureResticInstalled(rc *eos_io.RuntimeContext) error {

	// Ensure the script is run with sudo
	if os.Getenv("SUDO_USER") == "" {
		otelzap.Ctx(rc.Ctx).Error("Restic installation requires sudo permissions")
		return fmt.Errorf("need sudo permissions: run `sudo apt install restic`")
	}
	// Check for Restic installation
	_, err := exec.LookPath("restic")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Restic is not installed", zap.Error(err))
		return fmt.Errorf("restic is not installed: run `sudo apt install restic`")
	}
	otelzap.Ctx(rc.Ctx).Info("Restic is installed and ready to use")
	return nil
}

// generateSSHKeys generates SSH keys for accessing the backup server
func generateSSHKeys() error {
	// You may want to add checks to avoid overwriting existing keys.
	cmd := exec.Command("ssh-keygen", "-q", "-N", "", "-f", "/home/eos_user/.ssh/id_rsa")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// copySSHKeys copies the generated SSH keys to the backup server
func copySSHKeys() error {
	// Use standard "user@host" syntax; adjust if needed.
	cmd := exec.Command("ssh-copy-id", "eos_user@backup")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// initializeResticRepo initializes the Restic repository
func initializeResticRepo(rc *eos_io.RuntimeContext) error {
	repoPath := fmt.Sprintf("sftp:eos_user@backup:/srv/restic-repos/%s", hostname(rc))
	cmd := exec.Command("restic", "-r", repoPath, "init")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// performResticBackup performs the Restic backup
func performResticBackup(rc *eos_io.RuntimeContext) error {
	repoPath := fmt.Sprintf("sftp:eos_user@backup:/srv/restic-repos/%s", hostname(rc))
	password := getResticPassword(rc)

	cmd := exec.Command(

		"restic", "-r", repoPath,
		"--password-file=/home/eos_user/.restic-password",
		"--verbose", "backup",
		"/home", "/var", "/etc", "/srv", "/usr", "/opt",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+password)

	return cmd.Run()
}

// getResticPassword retrieves and stores the Restic repository password
func getResticPassword(rc *eos_io.RuntimeContext) string {

	var password string
	fmt.Print("Enter your Restic repository password: ")
	_, err := fmt.Scanln(&password)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to retrieve password", zap.Error(err))
		os.Exit(1)
	}

	file := "/home/eos_user/.restic-password" // Updated path
	err = os.WriteFile(file, []byte(password), 0600)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to write password file", zap.Error(err))
		os.Exit(1)
	}
	return password
}

// hostname retrieves the current hostname
func hostname(rc *eos_io.RuntimeContext) string {

	name, err := os.Hostname()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to retrieve hostname, using 'unknown'", zap.Error(err))
		return "unknown"
	}
	return name
}

func init() {
	// Register this backup command under the create command
	CreateCmd.AddCommand(CreateBackupCmd)
}
