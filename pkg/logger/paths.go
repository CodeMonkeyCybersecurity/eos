/* pkg/logger/paths.go */

package logger

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// PlatformLogPaths returns fallback log paths in order of priority for the platform.
func PlatformLogPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			xdg.XDGStatePath(shared.EosIdentity, "eos.log"),
			"/tmp/eos/eos.log",
			"./eos.log",
		}
	case "linux":
		return []string{
			"/var/log/eos/eos.log",
			"/run/eos/eos.log",
			xdg.XDGStatePath(shared.EosIdentity, "eos.log"),
			"/tmp/eos/eos.log",
			"./eos.log",
		}
	case "windows":
		return []string{
			filepath.Join(os.Getenv("ProgramData"), shared.EosIdentity, "eos.log"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), shared.EosIdentity, "eos.log"),
			".\\eos.log",
		}
	default:
		return []string{"./eos.log"}
	}
}
