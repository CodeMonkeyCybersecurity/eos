package update

import (
	"fmt"

	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
)

// UpdateCmd represents the update command
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update configurations and services",
	Long: `Update Hecate configurations, renew certificates, or update specific services.

Examples:
  hecate update certs
  hecate update eos
  hecate update http
`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("Update command executed")
		if len(args) == 0 {
			fmt.Println("No specific update target provided.")
		}
		return nil 
	}),
}

// Attach subcommands to UpdateCmd
func init() {
	UpdateCmd.AddCommand(runCertsCmd) // ✅ Fix: Use correct variable for subcommand
	UpdateCmd.AddCommand(runEosCmd)   // ✅ Fix: Use correct variable for subcommand
	UpdateCmd.AddCommand(runHttpCmd)  // ✅ Fix: Use correct variable for subcommand
}

// runCertsCmd renews SSL certificates
var runCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Renew SSL certificates",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("Renewing SSL certificates...")
		// Implement logic for renewing certificates
		return nil 
	}),
}
// runEosCmd updates the EOS system
var runEosCmd = &cobra.Command{
	Use:   "github.com/CodeMonkeyCybersecurity/eos",
	Short: "Update EOS system",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("Updating EOS system...")
		// Implement logic for updating EOS
		return nil 
	}),
}

// runHttpCmd updates the HTTP server
var runHttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Update HTTP configurations",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("Updating HTTP configurations...")
		// Implement logic for updating HTTP configurations
		return nil 
	}),
}
