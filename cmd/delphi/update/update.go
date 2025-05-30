package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var UpdateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"set", "change", "upgrade", "modify"},
	Short:   "Update Delphi resources",
	Long:    "Update configuration and user information in your Delphi (Wazuh) instance.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("🔄 Updating Delphi configuration or components...")
		return nil
	}),
}

func init() {
	// Will be registered by root or parent{
	// in update/password.go
}
