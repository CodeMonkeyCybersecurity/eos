// pkg/platform/arch_linux.go

package platform

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

func IsDebian() bool {
	return DetectLinuxDistro() == "debian"
}

func IsRHEL() bool {
	return DetectLinuxDistro() == "rhel"
}

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
