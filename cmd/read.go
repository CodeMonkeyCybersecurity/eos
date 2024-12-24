// read.go
package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// readCmd represents the "read" subcommand
var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Retrieve information about resources (processes, users, backups, etc.)",
	Long:  `Use eos read to retrieve detailed information about system resources, such as processes, users, hardware, backups, etc.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		object := args[0]
		switch object {
		case "processes":
			readProcesses()
		case "users":
			readUsers()
		case "hardware":
			readHardware()
		case "basic":
			readBasic()
		case "privileges":
			readPrivileges()
		default:
			fmt.Println("Error: Unsupported resource. Use `eos read [processes|users|hardware|basic|privileges]`.")
			os.Exit(1)

		}
	},
}

// Initialize subcommand
func init() {
	rootCmd.AddCommand(readCmd)
}

// Example function for fetching processes
func readProcesses() {
	fmt.Println("Fetching processes...")
	cmd := exec.Command("ps", "-e", "-o", "pid,comm")
	var output bytes.Buffer
	cmd.Stdout = &output
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error fetching processes: %v\n", err)
		return
	}
	fmt.Println("PID   COMMAND")
	fmt.Println(output.String())
}

// Example function for fetching users
func readUsers() {
	fmt.Println("Fetching users...")
	content, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		fmt.Printf("Error reading user list: %v\n", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	fmt.Println("USERNAME")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) > 0 {
			fmt.Println(fields[0])
		}
	}
}

// Example function for fetching hardware details
func readHardware() {
	fmt.Println("Fetching hardware details...")
	cmd := exec.Command("lscpu")
	var output bytes.Buffer
	cmd.Stdout = &output
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error fetching hardware details: %v\n", err)
		return
	}
	if os.Geteuid() != 0 {
		fmt.Println("Warning: Some details may be unavailable without root privileges.")
	}
	fmt.Println(output.String())
}

func readBasic() {
	fmt.Println("  System load:            ", readSystemLoad())
	fmt.Println("  Usage of /:             ", readDiskUsage("/"))
	fmt.Println("  Memory usage:           ", readMemoryUsage())
	fmt.Println("  Swap usage:             ", readSwapUsage())
	fmt.Println("  Processes:              ", readProcessCount())
	fmt.Println("  Users logged in:        ", readLoggedInUsers())
	fmt.Println("  IPv4 address:           ", readIPAddress("ens18", false))
	fmt.Println("  IPv6 address:           ", readIPAddress("ens18", true))
}

// Helper functions
func readSystemLoad() string {
	output, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return "N/A"
	}
	return strings.Fields(string(output))[0]
}

func readDiskUsage(path string) string {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return "N/A"
	}
	used := (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
	total := stat.Blocks * uint64(stat.Bsize)
	percent := float64(used) / float64(total) * 100
	return fmt.Sprintf("%.1f%% of %.2fGB", percent, float64(total)/(1024*1024*1024))
}

func readMemoryUsage() string {
	memInfo, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return "N/A"
	}
	lines := strings.Split(string(memInfo), "\n")
	total := parseMemValue(lines[0])
	available := parseMemValue(lines[2])
	used := total - available
	percent := float64(used) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", percent)
}

func readSwapUsage() string {
	memInfo, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return "N/A"
	}
	lines := strings.Split(string(memInfo), "\n")
	total := parseMemValue(lines[14])
	free := parseMemValue(lines[15])
	used := total - free
	percent := float64(used) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", percent)
}

func readProcessCount() string {
	output, err := exec.Command("sh", "-c", "ps -e | wc -l").Output()
	if err != nil {
		return "N/A"
	}
	count, _ := strconv.Atoi(strings.TrimSpace(string(output)))
	return strconv.Itoa(count)
}

func readLoggedInUsers() string {
	output, err := exec.Command("who").Output()
	if err != nil {
		return "N/A"
	}
	return strconv.Itoa(len(strings.Split(strings.TrimSpace(string(output)), "\n")))
}

func readIPAddress(ifaceName string, isIPv6 bool) string {
	if ifaceName == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return "N/A"
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				ifaceName = iface.Name
				break
			}
		}
	}
	if ifaceName == "" {
		return "No active interfaces found"
	}
	// read interface by name
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Sprintf("Error: Interface %s not found", ifaceName)
	}
	// read IP addresses for the interface
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Sprintf("Error retrieving addresses for %s", ifaceName)
	}
	// Filter for IPv4 or IPv6 addresses
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if isIPv6 && ipNet.IP.To4() == nil { // IPv6
			return ipNet.IP.String()
		} else if !isIPv6 && ipNet.IP.To4() != nil { // IPv4
			return ipNet.IP.String()
		}
	}
	return "No suitable IP address found"
}

func parseMemValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	value, _ := strconv.ParseUint(fields[1], 10, 64)
	return value * 1024 // kB to Bytes
}

func readPrivileges() {
	fmt.Println("Fetching privileges is not implemented yet.")
}
