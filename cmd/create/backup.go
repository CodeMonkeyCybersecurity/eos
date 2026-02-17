/*
cmd/create/backup.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/

package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateBackupCmd represents the create backup command
type backupOptions struct {
	Host         string
	User         string
	RepoDir      string
	PasswordFile string
	Paths        []string
}

var (
	backupOpts backupOptions
	pathsFlag  string
)

var CreateBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a new restic backup",
	Long: `This command initializes a restic repository if not already initialized,
then creates a backup of specified directories.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		hostFlag, _ := cmd.Flags().GetString("host")
		hostWasSet := cmd.Flags().Changed("host")
		hostResult, err := interaction.GetRequiredString(rc, hostFlag, hostWasSet, &interaction.RequiredFlagConfig{
			FlagName:      "host",
			PromptMessage: "Enter backup host: ",
			HelpText:      "Hostname or IP of the restic repository server",
		})
		if err != nil {
			return err
		}
		backupOpts.Host = hostResult.Value

		userFlag, _ := cmd.Flags().GetString("user")
		userWasSet := cmd.Flags().Changed("user")
		userResult, err := interaction.GetRequiredString(rc, userFlag, userWasSet, &interaction.RequiredFlagConfig{
			FlagName:      "user",
			PromptMessage: "Enter backup user: ",
			HelpText:      "SSH user used to connect to the backup server",
		})
		if err != nil {
			return err
		}
		backupOpts.User = userResult.Value

		repoFlag, _ := cmd.Flags().GetString("repo-dir")
		repoWasSet := cmd.Flags().Changed("repo-dir")
		repoResult, err := interaction.GetRequiredString(rc, repoFlag, repoWasSet, &interaction.RequiredFlagConfig{
			FlagName:      "repo-dir",
			PromptMessage: "Enter remote restic repo directory: ",
			HelpText:      "Directory on the backup host that stores restic repositories",
		})
		if err != nil {
			return err
		}
		backupOpts.RepoDir = repoResult.Value

		passwordFileFlag, _ := cmd.Flags().GetString("password-file")
		passwordFileWasSet := cmd.Flags().Changed("password-file")
		passwordFileResult, err := interaction.GetRequiredString(rc, passwordFileFlag, passwordFileWasSet, &interaction.RequiredFlagConfig{
			FlagName:      "password-file",
			PromptMessage: "Enter restic password file: ",
			HelpText:      "Local file path that stores the restic repository password",
		})
		if err != nil {
			return err
		}
		backupOpts.PasswordFile = passwordFileResult.Value

		pathsFlagValue, _ := cmd.Flags().GetString("paths")
		pathsWasSet := cmd.Flags().Changed("paths")
		pathsResult, err := interaction.GetRequiredString(rc, pathsFlagValue, pathsWasSet, &interaction.RequiredFlagConfig{
			FlagName:      "paths",
			PromptMessage: "Enter paths to backup (comma separated): ",
			HelpText:      "Specify one or more directories to include in the restic backup",
		})
		if err != nil {
			return err
		}
		pathsFlag = pathsResult.Value
		if pathsFlag != "" {
			for _, p := range strings.Split(pathsFlag, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					backupOpts.Paths = append(backupOpts.Paths, p)
				}
			}
		}

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
	keyPath := filepath.Join("/home", backupOpts.User, ".ssh", "id_rsa")
	cmd := exec.Command("ssh-keygen", "-q", "-N", "", "-f", keyPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// copySSHKeys copies the generated SSH keys to the backup server
func copySSHKeys() error {
	target := fmt.Sprintf("%s@%s", backupOpts.User, backupOpts.Host)
	cmd := exec.Command("ssh-copy-id", target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// initializeResticRepo initializes the Restic repository
func initializeResticRepo(rc *eos_io.RuntimeContext) error {
	repoPath := buildRepoPath(rc)
	cmd := exec.Command("restic", "-r", repoPath, "init")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// performResticBackup performs the Restic backup
func performResticBackup(rc *eos_io.RuntimeContext) error {
	repoPath := buildRepoPath(rc)
	password := getResticPassword(rc, backupOpts.PasswordFile)

	args := []string{"-r", repoPath, "--password-file=" + backupOpts.PasswordFile, "--verbose", "backup"}
	args = append(args, backupOpts.Paths...)
	cmd := exec.Command("restic", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+password)

	return cmd.Run()
}

// getResticPassword retrieves and stores the Restic repository password
func getResticPassword(rc *eos_io.RuntimeContext, file string) string {

	var password string
	var err error
	password, err = interaction.PromptSecret(rc.Ctx, "Enter your Restic repository password")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to retrieve password", zap.Error(err))
		os.Exit(1)
	}

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

func buildRepoPath(rc *eos_io.RuntimeContext) string {
	hostName := hostname(rc)
	return fmt.Sprintf("sftp:%s@%s:%s/%s", backupOpts.User, backupOpts.Host, backupOpts.RepoDir, hostName)
}

func init() {
	// Register this backup command under the create command
	CreateCmd.AddCommand(CreateBackupCmd)
	CreateBackupCmd.Flags().StringVar(&backupOpts.Host, "host", "", "Backup server host")
	CreateBackupCmd.Flags().StringVar(&backupOpts.User, "user", "", "SSH user for backup host")
	CreateBackupCmd.Flags().StringVar(&backupOpts.RepoDir, "repo-dir", "", "Remote restic repository directory")
	CreateBackupCmd.Flags().StringVar(&backupOpts.PasswordFile, "password-file", "", "Path to restic password file")
	CreateBackupCmd.Flags().StringVar(&pathsFlag, "paths", "", "Comma-separated list of paths to backup")
}
