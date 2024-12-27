// cmd/read/processes.go
package read

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	
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
		processes, err := getProcessesDetails()
		if err != nil {
			fmt.Printf("Error reading processes: %v\n", err)
			return
		}

		// Print the table
		printProcessTable(processes)
	},
}

// ProcessInfo holds details about a process
type ProcessInfo struct {
	PID         string
	Name        string
	CPUPercent  string
	MemPercent  string
	RunTime     string
}

// getProcessDetails retrieves process information
func getProcessDetails() ([]ProcessInfo, error) {
	procDir := "/proc"
	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %w", err)
	}

	var processes []ProcessInfo
	for _, file := range files {
		if file.IsDir() {
			pid := file.Name()
			if _, err := strconv.Atoi(pid); err == nil {
				// Get process name from /proc/[PID]/comm
				commPath := fmt.Sprintf("%s/%s/comm", procDir, pid)
				comm, err := ioutil.ReadFile(commPath)
				name := "unknown"
				if err == nil {
					name = strings.TrimSpace(string(comm))
				}

				// Placeholder values for CPU, Memory, and Runtime
				// (Replace these with real system stats if needed)
				cpuPercent := "0.0"
				memPercent := "0.0"
				runTime := "N/A"

				processes = append(processes, ProcessInfo{
					PID:        pid,
					Name:       name,
					CPUPercent: cpuPercent,
					MemPercent: memPercent,
					RunTime:    runTime,
				})
			}
		}
	}
	return processes, nil
}

// printProcessTable prints the process information in a table format
func printProcessTable(processes []ProcessInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "PID\tName\tCPU%\tMemory%\tRunning Time")
	fmt.Fprintln(w, "----\t----\t----\t----\t----")
	for _, proc := range processes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", proc.PID, proc.Name, proc.CPUPercent, proc.MemPercent, proc.RunTime)
	}
	w.Flush()
}

func init() {
	ReadCmd.AddCommand(readProcessesCmd)
}
