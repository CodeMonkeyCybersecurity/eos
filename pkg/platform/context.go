/* pkg/platform/context.go */

package platform

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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

func RequireLinuxDistro(allowed []string) error {
	if GetOSPlatform() != "linux" {
		return fmt.Errorf("unsupported platform: %s (only 'linux' is supported)", GetOSPlatform())
	}

	distro := DetectLinuxDistro()
	for _, d := range allowed {
		if distro == d {
			return nil
		}
	}

	return fmt.Errorf("unsupported Linux distribution: %s", distro)
}

func GetArch() string {
	return runtime.GOARCH
}

// IsCommandAvailable checks if a command exists in the system PATH.
func IsCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
