// cmd/delphi/configure/configure.go
package configure

import "github.com/spf13/cobra"

var ConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure Delphi (Wazuh) related services",
}

func init() {
	ConfigureCmd.AddCommand(ConfigureFirewallCmd)
}