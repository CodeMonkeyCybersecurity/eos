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

		// Print processes in a single line, separated by commas
		fmt.Print("Current running processes: ")
		fmt.Println(strings.Join(processes, ", "))
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
			pid := file.Name()
			if _, err := strconv.Atoi(pid); err == nil {
				// Get process name from /proc/[PID]/comm
				commPath := fmt.Sprintf("%s/%s/comm", procDir, pid)
				comm, err := ioutil.ReadFile(commPath)
				if err == nil {
					processes = append(processes, fmt.Sprintf("%s: %s", pid, string(comm)))
				} else {
					processes = append(processes, pid) // Fallback to just PID
				}
			}
		}
	}

	return processes, nil
}

func init() {
	ReadCmd.AddCommand(readProcessesCmd)
}
