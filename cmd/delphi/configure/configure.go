// cmd/delphi/configure/configure.go
package configure

import "github.com/spf13/cobra"

var ConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure Delphi (Wazuh) related services",
	Long:  "Run configuration commands such as setting up firewall rules, tuning agent settings, and more.",
}

func init() {
	ConfigureCmd.AddCommand(ConfigureCmd)
}
