package ldap

import (
	"github.com/spf13/cobra"
)

var (
	MaxResults int
)

func InitFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&MaxResults, "max-results", 100, "Maximum number of LDAP results to return")
}
