// pkg/platform/process.go

package platform

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

// IsProcessRunning returns true if a process with the given name appears to be running
func IsProcessRunning(name string) bool {
	switch runtime.GOOS {
	case "darwin":
		return isRunningMacOS(name)
	case "windows":
		return isRunningWindows(name)
	default: // Unix/Linux
		return isRunningUnix(name)
	}
}

func isRunningMacOS(name string) bool {
	cmd := exec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return bytes.Contains(output, []byte(name))
}

func isRunningWindows(name string) bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}

func isRunningUnix(name string) bool {
	cmd := exec.Command("ps", "-A")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}
