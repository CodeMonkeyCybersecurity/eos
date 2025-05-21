// pkg/platform/architecture.go
package platform

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"go.uber.org/zap"
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
//---------------------------- LINUX DISTRO DETECTION ----------------------------//
//

func DetectLinuxDistro() string {
	if !IsLinux() {
		return "unknown"
	}

	file, err := os.Open("/etc/os-release")
	if err != nil {
		zap.L().Warn("Failed to open /etc/os-release", zap.Error(err))
		return "unknown"
	}
	defer file.Close()

	var distroID string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			distroID = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			break
		}
	}

	switch distroID {
	case "debian", "ubuntu":
		return "debian"
	case "rhel", "centos":
		return "rhel"
	case "alpine":
		return "alpine"
	case "sles", "suse":
		return "suse"
	default:
		return "unknown"
	}
}

func RequireLinuxDistro(allowed []string) error {
	if !IsLinux() {
		return fmt.Errorf("unsupported platform: %s (Linux required)", GetOSPlatform())
	}
	distro := DetectLinuxDistro()
	for _, allowedDistro := range allowed {
		if distro == allowedDistro {
			return nil
		}
	}
	return fmt.Errorf("unsupported Linux distribution: %s (expected one of %v)", distro, allowed)
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
	if override := os.Getenv("EOS_SHELL_RC"); override != "" {
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
