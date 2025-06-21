// pkg/platform/arch_linux.go

package platform

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func IsDebian(rc *eos_io.RuntimeContext) bool {
	return DetectLinuxDistro(rc) == "debian"
}

func IsRHEL(rc *eos_io.RuntimeContext) bool {
	return DetectLinuxDistro(rc) == "rhel"
}

func DetectLinuxDistro(rc *eos_io.RuntimeContext) string {
	if !IsLinux() {
		return "unknown"
	}

	file, err := os.Open("/etc/os-release")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to open /etc/os-release", zap.Error(err))
		return "unknown"
	}
	defer func() {
		if err := file.Close(); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to close /etc/os-release", zap.Error(err))
		}
	}()

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

func RequireLinuxDistro(rc *eos_io.RuntimeContext, allowed []string) error {
	if !IsLinux() {
		return fmt.Errorf("unsupported platform: %s (Linux required)", GetOSPlatform())
	}
	distro := DetectLinuxDistro(rc)
	for _, allowedDistro := range allowed {
		if distro == allowedDistro {
			return nil
		}
	}
	return fmt.Errorf("unsupported Linux distribution: %s (expected one of %v)", distro, allowed)
}
