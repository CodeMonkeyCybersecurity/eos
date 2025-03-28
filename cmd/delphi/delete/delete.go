// cmd/delphi/delete/delete.go
package delete

import (
	"github.com/spf13/cobra"
)

var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete Delphi (Wazuh) resources via API",
}

func init() {
	DeleteCmd.AddCommand(DeleteAgentCmd)
}
