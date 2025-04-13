/* pkg/logger/paths.go */

package logger

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// PlatformLogPaths returns all fallback log paths in order of priority for the platform.
func PlatformLogPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			xdg.XDGStatePath("cyberMonkey", "eos.log"),
			"/tmp/cyberMonkey/eos.log",
			"./eos.log",
		}
	case "linux":
		return []string{
			"/var/log/cyberMonkey/eos.log",
			"/tmp/cyberMonkey/eos.log",
			"./eos.log",
		}
	case "windows":
		return []string{
			filepath.Join(os.Getenv("ProgramData"), "cyberMonkey", "eos.log"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "cyberMonkey", "eos.log"),
			".\\eos.log",
		}
	default:
		return []string{"./eos.log"}
	}
}
