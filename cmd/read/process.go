package read

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

const hertz = 100.0 // Typically, this is 100 ticks per second; adjust for your system if necessary

// readProcessesCmd represents the command to read processes
var readProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Retrieve detailed information about running processes",
	Long: `This command retrieves detailed information about all running processes on the system
by reading the /proc directory and outputs it in a table format.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading process...")
		process, err := getProcessDetails()
		if err != nil {
			fmt.Printf("Error reading process: %v\n", err)
			return
		}

		// Print the table
		printProcessTable(process)
	},
}

// ProcessInfo holds details about a process
type ProcessInfo struct {
	PID        string
	Comm       string
	State      string
	Name       string
	User       string
	CPUPercent string
	MemPercent string
	RunTime    string
}

// getProcessesDetails retrieves process information
func getProcessDetails() ([]ProcessInfo, error) {
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
					processes = append(process, processes)
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

	comm := strings.Trim(fields[1], "()") // Command name without parentheses
	state := fields[2]                    // State
	startTime, _ := strconv.ParseFloat(fields[21], 64)

	// Calculate runtime
	runTime := fmt.Sprintf("%.2f seconds", uptime-(startTime/hertz))

	// Get process name
	processName := comm

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

	// Get CPU and memory usage
	cpuPercent, _ := getCPUPercent(pid)
	memPercent, _ := getMemoryPercent(pid)

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

func getCPUPercent(pid string) (string, error) {
	statPath := fmt.Sprintf("/proc/%s/stat", pid)
	data, err := ioutil.ReadFile(statPath)
	if err != nil {
		return "Err", nil // Return 0.0 if process is not accessible
	}

	fields := strings.Fields(string(data))
	utime, _ := strconv.ParseFloat(fields[13], 64) // Field 13
	stime, _ := strconv.ParseFloat(fields[14], 64) // Field 14

	// Get system uptime and total CPU time
	uptimeData, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return "Err", nil
	}
	uptimeFields := strings.Fields(string(uptimeData))
	uptime, _ := strconv.ParseFloat(uptimeFields[0], 64)

	totalCPU := uptime * hertz // Total CPU time
	processCPU := (utime + stime) / totalCPU * 100.0
	return fmt.Sprintf("%.2f", processCPU), nil
}

func getMemoryPercent(pid string) (string, error) {
	statusPath := fmt.Sprintf("/proc/%s/status", pid)
	data, err := ioutil.ReadFile(statusPath)
	if err != nil {
		return "Err", nil // Return 0.0 if process is not accessible
	}

	var memUsage float64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			memUsage, _ = strconv.ParseFloat(fields[1], 64) // VmRSS in kB
			break
		}
	}

	memInfo, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return "Err", nil
	}

	totalMem := 0.0
	memLines := strings.Split(string(memInfo), "\n")
	for _, line := range memLines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			totalMem, _ = strconv.ParseFloat(fields[1], 64) // MemTotal in kB
			break
		}
	}

	if totalMem > 0 {
		return fmt.Sprintf("%.2f", (memUsage/totalMem)*100.0), nil
	}
	return "0.0", nil
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
func printProcessTable(process []ProcessInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "PID\tComm\tState\tName\tUser\tCPU%\tMemory%\tRunning Time")
	fmt.Fprintln(w, "----\t----\t----\t----\t----\t----\t----\t----")
	for _, proc := range process {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			proc.PID, proc.Comm, proc.State, proc.Name, proc.User, proc.CPUPercent, proc.MemPercent, proc.RunTime)
	}
	w.Flush()
}

func init() {
	ReadCmd.AddCommand(readProcessCmd)
}
