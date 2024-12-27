/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package create

import (
	"fmt"

	"github.com/spf13/cobra"
)

// createBackupCmd represents the createBackup command
var createBackupCmd = &cobra.Command{
	Use:   "eos create backup",
	Short: "Create a new backup",
	Long: `This command allows you to create a new backup for specified resources.
    Use this to ensure your data is securely stored.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("createBackup called")
	},
}

func init() {
	create.AddCommand(createBackupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createBackupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createBackupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
