// cmd/inspect/config.go

package inspect

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
)

// inspectConfigCmd represents the "inspect config" subcommand
var inspectConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect configurations",
	Long: `This command lets you inspect various configuration resources for Hecate.
You can choose from:
  1) Inspect Certificates
  2) Inspect docker-compose file
  3) Inspect Eos backend web apps configuration
  4) Inspect Nginx defaults
  5) Inspect all configurations`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		runInspectConfig()
		return nil 
	}),
}

// runInspectConfig presents an interactive menu for inspection
func runInspectConfig() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Inspect Configurations ===")
	fmt.Println("Select the resource you want to inspect:")
	fmt.Println("1) Inspect Certificates")
	fmt.Println("2) Inspect docker-compose file")
	fmt.Println("3) Inspect Eos backend web apps configuration")
	fmt.Println("4) Inspect Nginx defaults")
	fmt.Println("5) Inspect all configurations")
	fmt.Print("Enter choice (1-5): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.ToLower(strings.TrimSpace(choice))

	switch choice {
	case "1", "certificates", "certs":
		utils.InspectCertificates()
	case "2", "compose", "docker-compose":
		utils.InspectDockerCompose()
	case "3", "github.com/CodeMonkeyCybersecurity/eos":
		utils.InspectEosConfig()
	case "4", "nginx":
		utils.InspectNginxDefaults()
	case "5", "all":
		utils.InspectCertificates()
		utils.InspectDockerCompose()
		utils.InspectEosConfig()
		utils.InspectNginxDefaults()
	default:
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}
}
