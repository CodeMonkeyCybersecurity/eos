// cmd/read/processes.go
package read

import (
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/spf13/cobra"
)

// readProcessesCmd represents the command to read processes
var readProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Retrieve information about running processes",
	Long: `This command retrieves a list of all running processes on the system
by reading the /proc directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading processes...")
		processes, err := getRunningProcesses()
		if err != nil {
			fmt.Printf("Error reading processes: %v\n", err)
			return
		}

		fmt.Println("Current running processes:")
		for _, process := range processes {
			fmt.Println(process)
		}
	},
}

// getRunningProcesses retrieves the list of running processes from the /proc directory
func getRunningProcesses() ([]string, error) {
	procDir := "/proc"
	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %w", err)
	}

	var processes []string
	for _, file := range files {
		if file.IsDir() {
			// Check if the directory name is numeric (process ID)
			if _, err := strconv.Atoi(file.Name()); err == nil {
				processes = append(processes, file.Name())
			}
		}
	}

	return processes, nil
}

func init() {
	ReadCmd.AddCommand(readProcessesCmd)
}
