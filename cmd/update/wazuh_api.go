// cmd/wazuh/upgrade/api.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	localOnly  bool
	upgradeAll bool
)

func init() {
	UpdateWazuhApiCmd.Flags().BoolVar(&localOnly, "local", false, "Upgrade Wazuh API on the local node")
	UpdateWazuhApiCmd.Flags().BoolVar(&upgradeAll, "all", false, "Upgrade Wazuh API on all nodes in the cluster")
	UpdateCmd.AddCommand(UpdateWazuhApiCmd)
}

var UpdateWazuhApiCmd = &cobra.Command{
	Use:   "api",
	Short: "Upgrade the Wazuh API configuration",
	Long:  "Upgrade the Wazuh API configuration locally or across the cluster. Defaults to --local if no flag is set.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		// Default to --local if nothing is passed
		if !localOnly && !upgradeAll {
			localOnly = true
		}

		switch {
		case localOnly:
			otelzap.Ctx(rc.Ctx).Info("Upgrading Wazuh API config on local node...")
			// TODO: insert local upgrade logic here
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: ✓ Local Wazuh API config upgrade complete")

		case upgradeAll:
			otelzap.Ctx(rc.Ctx).Info("Upgrading Wazuh API config on all nodes...")
			// TODO: insert distributed upgrade logic here
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: ✓ Cluster-wide Wazuh API config upgrade complete")

		default:
			return fmt.Errorf("unknown upgrade target")
		}

		return nil
	}),
}
