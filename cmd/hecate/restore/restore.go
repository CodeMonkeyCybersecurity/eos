// cmd/hecate/restore/restore.go

package restore

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

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
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {

	// Define timestamp flag
	RestoreCmd.Flags().StringVarP(&timestampFlag, "timestamp", "t", "",
		"Timestamp for backup (format: YYYYMMDD-HHMMSS). If omitted, interactive mode is used.")
}

// runAutoRestore automatically restores resources using the provided timestamp.
func RunAutoRestore(ts string) {
	backupConf := fmt.Sprintf("%s.%s.bak", shared.DefaultConfDir, ts)
	backupCerts := fmt.Sprintf("%s.%s.bak", shared.DefaultCertsDir, ts)
	backupCompose := fmt.Sprintf("%s.%s.bak", shared.DefaultComposeYML, ts)

	fmt.Printf("Restoring backups with timestamp %s...\n", ts)
	system.RestoreDir(backupConf, shared.DefaultConfDir)
	system.RestoreDir(backupCerts, shared.DefaultCertsDir)
	system.RestoreFile(backupCompose, shared.DefaultComposeYML)
}

// runInteractiveRestore presents a menu to choose which resource(s) to restore.
func RunInteractiveRestore() {
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
		RestoreConf()
	case "2":
		RestoreCerts()
	case "3":
		RestoreCompose()
	case "4":
		RestoreConf()
		RestoreCerts()
		RestoreCompose()
	default:
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}
}

func RestoreConf() {
	backupConf, err := system.FindLatestBackup(fmt.Sprintf("%s.", shared.DefaultConfDir))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", shared.DefaultConfDir, err)
		return
	}
	fmt.Printf("Restoring configuration from backup: %s\n", backupConf)
	system.RestoreDir(backupConf, shared.DefaultConfDir)
}

func RestoreCerts() {
	backupCerts, err := system.FindLatestBackup(fmt.Sprintf("%s.", shared.DefaultCertsDir))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", shared.DefaultCertsDir, err)
		return
	}
	fmt.Printf("Restoring certificates from backup: %s\n", backupCerts)
	system.RestoreDir(backupCerts, shared.DefaultCertsDir)
}

func RestoreCompose() {
	backupCompose, err := system.FindLatestBackup(fmt.Sprintf("%s.", shared.DefaultComposeYML))
	if err != nil {
		fmt.Printf("Error finding backup for %s: %v\n", shared.DefaultComposeYML, err)
		return
	}
	fmt.Printf("Restoring docker-compose file from backup: %s\n", backupCompose)
	system.RestoreFile(backupCompose, shared.DefaultComposeYML)
}

func init() {
	// Initialize the shared logger for the entire deploy package
}
