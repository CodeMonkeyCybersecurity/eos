// cmd/delphi/delete/delete.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete Delphi (Wazuh) resources via API",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {

		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteAgentCmd)
}
