// cmd/config/config.go
package config

import (
	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:     "config",
	Short:   "Manage Eos CLI settings",
	Aliases: []string{"self"},
	Long:    `Configure telemetry, authentication, environment defaults, and other Eos behaviors.`,
}
