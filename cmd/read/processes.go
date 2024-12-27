package read

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// readProcessesCmd represents the command to read processes
var readProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Retrieve detailed information about running processes",
	Long: `This command retrieves detailed information about all running processes on the system
by reading the /proc directory and outputs it in a table format.`,
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
	Comm        string
	State       string
	Name        string
	User        string
	CPUPercent  string
	MemPercent  string
	RunTime     string
}

// getProcessesDetails retrieves process information
func getProcessesDetails() ([]ProcessInfo, error) {
	procDir := "/proc"
	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %w", err)
	}

	var processes []ProcessInfo
	uptime := getSystemUptime()

	for _, file := range files {
		if file.IsDir() {
			pid := file.Name()
			if _, err := strconv.Atoi(pid); err == nil {
				process, err := extractProcessDetails(pid, uptime)
				if err == nil {
					processes = append(processes, process)
				}
			}
		}
	}
	return processes, nil
}

// extractProcessDetails extracts details about a specific process
func extractProcessDetails(pid string, uptime float64) (ProcessInfo, error) {
	procDir := fmt.Sprintf("/proc/%s", pid)

	// Read /proc/[PID]/stat
	statPath := fmt.Sprintf("%s/stat", procDir)
	statContent, err := ioutil.ReadFile(statPath)
	if err != nil {
		return ProcessInfo{}, err
	}
	fields := strings.Fields(string(statContent))

	comm := fields[1]     // Command name
	state := fields[2]    // State
	startTime, _ := strconv.ParseFloat(fields[21], 64)

	// Calculate runtime
	hertz := float64(os.Getpagesize()) / 1024.0
	runTime := fmt.Sprintf("%.2f seconds", uptime-(startTime/hertz))

	// Read /proc/[PID]/comm
	commPath := fmt.Sprintf("%s/comm", procDir)
	commContent, err := ioutil.ReadFile(commPath)
	processName := "unknown"
	if err == nil {
		processName = strings.TrimSpace(string(commContent))
	}

	// Read /proc/[PID]/status to get user info
	statusPath := fmt.Sprintf("%s/status", procDir)
	statusContent, err := ioutil.ReadFile(statusPath)
	userName := "unknown"
	if err == nil {
		for _, line := range strings.Split(string(statusContent), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				uid := strings.Fields(line)[1]
				if user, err := user.LookupId(uid); err == nil {
					userName = user.Username
				}
				break
			}
		}
	}

	// Placeholder for CPU and Memory (implement further logic if needed)
	cpuPercent := "0.0"
	memPercent := "0.0"

	return ProcessInfo{
		PID:        pid,
		Comm:       comm,
		State:      state,
		Name:       processName,
		User:       userName,
		CPUPercent: cpuPercent,
		MemPercent: memPercent,
		RunTime:    runTime,
	}, nil
}

// getSystemUptime retrieves the system uptime
func getSystemUptime() float64 {
	uptimeFile := "/proc/uptime"
	content, err := ioutil.ReadFile(uptimeFile)
	if err != nil {
		return 0.0
	}
	uptime, _ := strconv.ParseFloat(strings.Fields(string(content))[0], 64)
	return uptime
}

// printProcessTable prints the process information in a table format
func printProcessTable(processes []ProcessInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "PID\tComm\tState\tName\tUser\tCPU%\tMemory%\tRunning Time")
	fmt.Fprintln(w, "----\t----\t----\t----\t----\t----\t----\t----")
	for _, proc := range processes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			proc.PID, proc.Comm, proc.State, proc.Name, proc.User, proc.CPUPercent, proc.MemPercent, proc.RunTime)
	}
	w.Flush()
}

func init() {
	ReadCmd.AddCommand(readProcessesCmd)
}
