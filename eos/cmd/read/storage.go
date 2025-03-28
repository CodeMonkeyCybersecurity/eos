// cmd/read/storage.go
package read

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

// readStorageCmd represents the create command for storage
var readStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Retrieve information about storage devices and filesystem usage",
	Long: `The read storage command displays detailed information about block devices 
and the usage of mounted filesystems, combining the functionality of lsblk and df -h.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading storage information...")

		// Run lsblk
		fmt.Println("\nBlock Devices (lsblk):")
		if err := runCommand("lsblk", "--all", "--output", "NAME,SIZE,TYPE,MOUNTPOINT"); err != nil {
			fmt.Printf("Error running lsblk: %v\n", err)
			return
		}

		// Run df -h
		fmt.Println("\nFilesystem Usage (df -h):")
		if err := runCommand("df", "-h"); err != nil {
			fmt.Printf("Error running df -h: %v\n", err)
			return
		}
	},
}

// runCommand executes a system command and prints its output
func runCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v\nOutput: %s", err, string(output))
	}
	fmt.Println(string(output))
	return nil
}

func init() {
	ReadCmd.AddCommand(readStorageCmd)
}
