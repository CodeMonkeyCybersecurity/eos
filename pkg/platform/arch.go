// pkg/platform/architecture.go
package platform

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

//
//---------------------------- OS + ARCH DETECTION ----------------------------//
//

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

func IsMacOS() bool           { return runtime.GOOS == "darwin" }
func IsLinux() bool           { return runtime.GOOS == "linux" }
func IsWindows() bool         { return runtime.GOOS == "windows" }
func IsUnknownPlatform() bool { return GetOSPlatform() == "unknown" }

func GetArch() string { return runtime.GOARCH }
func IsARM() bool     { return strings.HasPrefix(runtime.GOARCH, "arm") }

func IsCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

//
//---------------------------- SHELL DETECTION ----------------------------//
//

func GetShellType() string {
	shell := os.Getenv("SHELL")
	switch {
	case strings.Contains(shell, "zsh"):
		return "zsh"
	case strings.Contains(shell, "bash"):
		return "bash"
	case strings.Contains(shell, "fish"):
		return "fish"
	default:
		return "unknown"
	}
}

func GetHomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return "/root"
}

func GetShellInitFile() string {
	if override := os.Getenv("Eos_SHELL_RC"); override != "" {
		return override
	}

	home := GetHomeDir()
	shell := GetShellType()

	switch shell {
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	default:
		// Try fallback order
		if _, err := os.Stat(filepath.Join(home, ".zshrc")); err == nil {
			return filepath.Join(home, ".zshrc")
		}
		if _, err := os.Stat(filepath.Join(home, ".bashrc")); err == nil {
			return filepath.Join(home, ".bashrc")
		}
		return filepath.Join(home, ".profile")
	}
}
