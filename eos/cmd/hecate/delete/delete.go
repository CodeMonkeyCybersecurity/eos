package delete

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// DeleteCmd is the root "delete" command: supports either `delete <app>` or subcommands like `delete resources`
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete deployed applications or resources",
	Long: `Delete applications or configuration resources managed by Hecate.

Examples:
  hecate delete jenkins
  hecate delete resources`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("🗑️  Please use a subcommand like 'delete resources' or specify an app name.")
			return
		}

		app := args[0]
		fmt.Printf("🗑️  Deleting application: %s\n", app)
		// TODO: Add logic to delete individual app configuration
	},
}

var deleteResourcesCmd = &cobra.Command{
	Use:   "resources",
	Short: "Interactively delete configuration resources",
	Long: `This command deletes various resources for Hecate:

  1) Delete Certificates
  2) Delete docker-compose modifications/backups
  3) Delete Eos backend web apps configuration files
  4) Delete (or revert) Nginx defaults
  5) Delete all specified resources`,
	Run: func(cmd *cobra.Command, args []string) {
		runDeleteConfig()
	},
}

func init() {
	DeleteCmd.AddCommand(deleteResourcesCmd)
}

// runDeleteConfig presents an interactive menu for delete actions.
func runDeleteConfig() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Delete Resources ===")
	fmt.Println("Select the resource you want to delete:")
	fmt.Println("1) Delete Certificates")
	fmt.Println("2) Delete docker-compose modifications/backups")
	fmt.Println("3) Delete Eos backend web apps configuration files")
	fmt.Println("4) Delete (or revert) Nginx defaults")
	fmt.Println("5) Delete all specified resources")
	fmt.Print("Enter choice (1-5): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.ToLower(strings.TrimSpace(choice))

	switch choice {
	case "1":
		deleteCertificates()
	case "2":
		deleteDockerCompose()
	case "3":
		deleteEosConfig()
	case "4":
		deleteNginxDefaults()
	case "5":
		deleteCertificates()
		deleteDockerCompose()
		deleteEosConfig()
		deleteNginxDefaults()
	default:
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}
}

func deleteCertificates() {
	fmt.Println("\n--- Deleting Certificates ---")
	certsDir := "certs"
	err := os.RemoveAll(certsDir)
	if err != nil {
		fmt.Printf("Error deleting certificates directory: %v\n", err)
	} else {
		fmt.Printf("Certificates deleted (directory '%s' removed).\n", certsDir)
	}
}

func deleteDockerCompose() {
	fmt.Println("\n--- Deleting docker-compose modifications/backups ---")
	matches, err := filepath.Glob("*_docker-compose.yml.bak")
	if err != nil {
		fmt.Printf("Error searching for backups: %v\n", err)
		return
	}
	for _, file := range matches {
		if err := os.Remove(file); err != nil {
			fmt.Printf("Error removing backup file %s: %v\n", file, err)
		} else {
			fmt.Printf("Removed backup file: %s\n", file)
		}
	}
}

func deleteEosConfig() {
	fmt.Println("\n--- Deleting Eos backend web apps configuration files ---")
	confDir := "conf.d"
	err := os.RemoveAll(confDir)
	if err != nil {
		fmt.Printf("Error deleting Eos configuration directory %s: %v\n", confDir, err)
	} else {
		fmt.Printf("Eos backend configuration files deleted (directory '%s' removed).\n", confDir)
	}
}

func deleteNginxDefaults() {
	fmt.Println("\n--- Deleting (or reverting) Nginx defaults ---")
	configFile := "http.conf"
	backupFile := "http.conf.bak"
	if _, err := os.Stat(backupFile); err == nil {
		if err := os.Remove(configFile); err != nil {
			fmt.Printf("Error removing current %s: %v\n", configFile, err)
		} else if err := os.Rename(backupFile, configFile); err != nil {
			fmt.Printf("Error restoring backup %s to %s: %v\n", backupFile, configFile, err)
		} else {
			fmt.Printf("Nginx defaults reverted by restoring %s.\n", configFile)
		}
	} else {
		if err := os.Remove(configFile); err != nil {
			fmt.Printf("Error removing %s: %v\n", configFile, err)
		} else {
			fmt.Printf("Deleted %s.\n", configFile)
		}
	}
}
