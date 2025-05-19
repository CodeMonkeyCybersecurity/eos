// cmd/config/config.go
package config

import (
	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage EOS CLI settings",
	Long:  `Configure telemetry, authentication, environment defaults, and other EOS behaviors.`,
}
