// cmd/inspect/storage.go
package inspect

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
)

// readStorageCmd represents the create command for storage
var InspectStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Retrieve information about storage devices and filesystem usage",
	Long: `The read storage command displays detailed information about block devices 
and the usage of mounted filesystems, combining the functionality of lsblk and df -h.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("Reading storage information...")

		// Run lsblk
		fmt.Println("\nBlock Devices (lsblk):")
		if err := runCommand("lsblk", "--all", "--output", "NAME,SIZE,TYPE,MOUNTPOINT"); err != nil {
			fmt.Printf("Error running lsblk: %v\n", err)
			return(err)
		}

		// Run df -h
		fmt.Println("\nFilesystem Usage (df -h):")
		if err := runCommand("df", "-h"); err != nil {
			fmt.Printf("Error running df -h: %v\n", err)
			return (err) 
		}
		return nil 
	}),
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

// init registers subcommands for the read command
func init() {

	InspectCmd.AddCommand(InspectStorageCmd)
}
