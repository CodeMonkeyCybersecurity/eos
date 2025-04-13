// cmd/delphi/configure/firewall.go
package configure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ConfigureFirewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Auto-configure firewall rules for Wazuh on Linux",
	Long:  "Detects Debian or RHEL and configures UFW or Firewalld for Wazuh agent ports.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L().Named("firewall")
		ports := []string{"55000/tcp", "1516/tcp", "1515/tcp", "1514/tcp", "443/tcp"}

		platform.ConfigureFirewalld(log, ports)
		return nil
	}),
}
