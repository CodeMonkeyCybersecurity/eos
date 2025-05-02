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
			xdg.XDGStatePath(shared.EosID, "eos.log"),
			shared.EosLogsPWD,
			"/tmp/eos/eos.log",
		}
	case "linux":
		return []string{
			shared.EosLogs, // best if writable (via sudo or eos user)
			xdg.XDGStatePath(shared.EosID, "eos.log"), // user-local fallback (e.g., ~/.local/state/eos/eos.log)
			shared.EosLogsPWD,                         // current working dir – ideal for devs
			"/tmp/eos/eos.log",                        // ephemeral
		}
	case "windows":
		return []string{
			filepath.Join(os.Getenv("ProgramData"), shared.EosID, "eos.log"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), shared.EosID, "eos.log"),
			".\\eos.log",
		}
	default:
		return []string{shared.EosLogsPWD}
	}
}
