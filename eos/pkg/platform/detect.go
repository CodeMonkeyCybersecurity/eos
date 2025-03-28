// pkg/platform/detect.go

package platform

import (
	"runtime"
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
