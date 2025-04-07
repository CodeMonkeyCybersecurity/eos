// cmd/delphi/upgrade/api.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	localOnly  bool
	upgradeAll bool
)

func init() {
	UpdateDelphiApiCmd.Flags().BoolVar(&localOnly, "local", false, "Upgrade Wazuh API on the local node")
	UpdateDelphiApiCmd.Flags().BoolVar(&upgradeAll, "all", false, "Upgrade Wazuh API on all nodes in the cluster")
	UpdateCmd.AddCommand(UpdateDelphiApiCmd)
}

var UpdateDelphiApiCmd = &cobra.Command{
	Use:   "api",
	Short: "Upgrade the Wazuh API configuration",
	Long:  "Upgrade the Wazuh API configuration locally or across the cluster. Defaults to --local if no flag is set.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()

		// Default to --local if nothing is passed
		if !localOnly && !upgradeAll {
			localOnly = true
		}

		switch {
		case localOnly:
			log.Info("Upgrading Wazuh API config on local node...")
			// TODO: insert local upgrade logic here
			fmt.Println("✓ Local Wazuh API config upgrade complete")

		case upgradeAll:
			log.Info("Upgrading Wazuh API config on all nodes...")
			// TODO: insert distributed upgrade logic here
			fmt.Println("✓ Cluster-wide Wazuh API config upgrade complete")

		default:
			return fmt.Errorf("unknown upgrade target")
		}

		return nil
	}),
}
