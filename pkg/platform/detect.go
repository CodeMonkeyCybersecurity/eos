// pkg/platform/detect.go

package platform

import (
	"runtime"
	"bufio"
	"os"
	"strings"
)

//
//---------------------------- OPERATING SYSTEMS ---------------------------- //
//

// GetOSPlatform returns a string representing the OS platform.
func GetOSPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return "unknown"
	}
}

// DetectLinuxDistro returns "debian", "rhel", or "unknown"
func DetectLinuxDistro() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ID=debian") || strings.Contains(line, "ID=ubuntu") {
			return "debian"
		}
		if strings.Contains(line, "ID=rhel") || strings.Contains(line, "ID=\"centos\"") {
			return "rhel"
		}
	}
	return "unknown"
}