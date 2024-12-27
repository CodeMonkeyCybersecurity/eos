/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
// cmd/create/backup.go
package create

import (
	"fmt"
	"os"
	"os/exec"

	"eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// createBackupCmd represents the createBackup command
var createBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a new restic backup",
	Long: `This command initializes a restic repository if not already initialized,
then creates a backup of specified directories.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		// Step 1: Ensure Restic is Installed
		log.Info("Ensuring Restic is installed")
		if err := ensureResticInstalled(); err != nil {
			log.Error("Failed to install Restic", zap.Error(err))
			return
		}

		// Step 2: Generate SSH Keys
		log.Info("Generating SSH keys for backup")
		if err := generateSSHKeys(); err != nil {
			log.Error("Failed to generate SSH keys", zap.Error(err))
			return
		}

		// Step 3: Copy SSH Keys to Backup Server
		log.Info("Copying SSH keys to the backup server")
		if err := copySSHKeys(); err != nil {
			log.Error("Failed to copy SSH keys", zap.Error(err))
			return
		}

		// Step 4: Initialize Restic Repository
		log.Info("Initializing restic repository")
		if err := initializeResticRepo(); err != nil {
			log.Error("Failed to initialize restic repository", zap.Error(err))
			return
		}

		// Step 5: Backup Data
		log.Info("Backing up data")
		if err := performResticBackup(); err != nil {
			log.Error("Failed to backup data", zap.Error(err))
			return
		}

		log.Info("Backup completed successfully")
	},
}

// ensureResticInstalled ensures Restic is installed on the system
func ensureResticInstalled() error {
	cmd := exec.Command("apt", "install", "-y", "restic")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// generateSSHKeys generates SSH keys for accessing the backup server
func generateSSHKeys() error {
	cmd := exec.Command("sudo", "ssh-keygen", "-q", "-N", "", "-f", "/root/.ssh/id_rsa")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// copySSHKeys copies the generated SSH keys to the backup server
func copySSHKeys() error {
	cmd := exec.Command("sudo", "ssh-copy-id", "henry@backup")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// initializeResticRepo initializes the Restic repository
func initializeResticRepo() error {
	repoPath := fmt.Sprintf("sftp:henry@backup:/srv/restic-repos/%s", hostname())
	cmd := exec.Command("sudo", "restic", "-r", repoPath, "init")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// performResticBackup performs the Restic backup
func performResticBackup() error {
	repoPath := fmt.Sprintf("sftp:henry@backup:/srv/restic-repos/%s", hostname())
	password := getResticPassword()

	cmd := exec.Command(
		"sudo", "restic", "-r", repoPath,
		"--password-file=/root/.restic-password",
		"--verbose", "backup",
		"/root", "/home", "/var", "/etc", "/srv", "/usr", "/opt",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+password)

	return cmd.Run()
}

// getResticPassword retrieves and stores the Restic repository password
func getResticPassword() string {
	fmt.Print("What is your restic repo password?: ")
	var password string
	fmt.Scanln(&password)

	file := "/root/.restic-password"
	_ = os.WriteFile(file, []byte(password), 0600)
	return password
}

// hostname retrieves the current hostname
func hostname() string {
	name, _ := os.Hostname()
	return name
}

func init() {
	CreateCmd.AddCommand(createBackupCmd)
}
