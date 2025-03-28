package restore

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
)

var log = logger.L()
var timestampFlag string

// RestoreCmd represents the restore command.
var RestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore configuration and files from backup",
	Long: `Restore configuration files, certificates, and docker-compose file from backups.

If --timestamp is provided (e.g. --timestamp 20250325-101010), then restore will look for:
  conf.d.<timestamp>.bak
  certs.<timestamp>.bak
  docker-compose.yml.<timestamp>.bak

If no --timestamp is given, the command enters interactive mode to choose which resources to restore.`,
	Run: func(cmd *cobra.Command, args []string) {
		if timestampFlag != "" {
			runAutoRestore(timestampFlag)
		} else {
			runInteractiveRestore()
		}
	},
}

func init() {

	// Define timestamp flag
	RestoreCmd.Flags().StringVarP(&timestampFlag, "timestamp", "t", "",
		"Timestamp for backup (format: YYYYMMDD-HHMMSS). If omitted, interactive mode is used.")
}

// runAutoRestore automatically restores resources using the provided timestamp.
func runAutoRestore(ts string) {
	backupConf := fmt.Sprintf("%s.%s.bak", config.DefaultConfDir, ts)
	backupCerts := fmt.Sprintf("%s.%s.bak", config.DefaultCertsDir, ts)
	backupCompose := fmt.Sprintf("%s.%s.bak", config.DefaultComposeYML, ts)

	fmt.Printf("Restoring backups with timestamp %s...\n", ts)
	backup.RestoreDir(backupConf, config.DefaultConfDir)
	backup.RestoreDir(backupCerts, config.DefaultCertsDir)
	backup.RestoreFile(backupCompose, config.DefaultComposeYML)
}

// runInteractiveRestore presents a menu to choose which resource(s) to restore.
func runInteractiveRestore() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Interactive Restore ===")
	fmt.Println("Select the resource you want to restore:")
	fmt.Println("1) Restore configuration (conf.d)")
	fmt.Println("2) Restore certificates (certs)")
	fmt.Println("3) Restore docker-compose file")
	fmt.Println("4) Restore all resources")
	fmt.Print("Enter choice (1-4): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		restoreConf()
	case "2":
		restoreCerts()
	case "3":
		restoreCompose()
	case "4":
		restoreConf()
		restoreCerts()
		restoreCompose()
	default:
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}
}

func restoreConf() {
	backupConf, err := backup.FindLatestBackup(fmt.Sprintf("%s.", config.DefaultConfDir))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", config.DefaultConfDir, err)
		return
	}
	fmt.Printf("Restoring configuration from backup: %s\n", backupConf)
	backup.RestoreDir(backupConf, config.DefaultConfDir)
}

func restoreCerts() {
	backupCerts, err := backup.FindLatestBackup(fmt.Sprintf("%s.", config.DefaultCertsDir))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", config.DefaultCertsDir, err)
		return
	}
	fmt.Printf("Restoring certificates from backup: %s\n", backupCerts)
	backup.RestoreDir(backupCerts, config.DefaultCertsDir)
}

func restoreCompose() {
	backupCompose, err := backup.FindLatestBackup(fmt.Sprintf("%s.", config.DefaultComposeYML))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", config.DefaultComposeYML, err)
		return
	}
	fmt.Printf("Restoring docker-compose file from backup: %s\n", backupCompose)
	backup.RestoreFile(backupCompose, config.DefaultComposeYML)
}
