// pkg/logger/paths.go
package logger

import "runtime"

// PlatformLogPaths returns all fallback log paths in order of priority for the platform.
func platformLogPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"$HOME/Library/Logs/cyberMonkey/eos.log",
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
			"%ProgramData%\\cyberMonkey\\github.com\\CodeMonkeyCybersecurity\\eos.log",
			"%LOCALAPPDATA%\\cyberMonkey\\github.com\\CodeMonkeyCybersecurity\\eos.log",
			".\\eos.log",
		}
	default:
		return []string{"./eos.log"}
	}
}
