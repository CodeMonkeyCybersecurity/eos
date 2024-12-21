package cmd

import (
	"github.com/spf13/cobra"
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage user accounts",
	Long:  `Commands for managing and interacting with user accounts on the system.`,
}

func init() {
	rootCmd.AddCommand(usersCmd)
}
