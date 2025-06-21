// pkg/packer/lifecycle.go
package packer

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// tracer is unused but kept for potential future tracing instrumentation
var _ = otel.Tracer("eos/pkg/packer")

// EnsureInstalled installs Packer cross-platform with full logging, tracing, and error wrapping
func EnsureInstalled(rc *eos_io.RuntimeContext, log *zap.Logger) error {

	if platform.IsCommandAvailable("packer") {
		log.Info("✅ Packer already installed")
		return nil
	}

	switch {
	case platform.IsMacOS():
		return installPackerMacOS(rc, log)
	case platform.IsDebian(rc):
		return installPackerDebian(rc, log)
	case platform.IsRHEL(rc):
		return installPackerRHEL(rc, log)
	default:
		err := errors.Newf("unsupported platform: %s", platform.GetOSPlatform())
		log.Error("❌ Packer installation unsupported", zap.Error(err))
		return err
	}
}

func installPackerDebian(rc *eos_io.RuntimeContext, log *zap.Logger) error {
	log.Info("📦 Installing Packer (Debian/Ubuntu)")
	cmd := `
		wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg &&
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list &&
		sudo apt update &&
		sudo apt install -y packer`
	_, err := execute.Run(rc.Ctx, execute.Options{
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}

func installPackerRHEL(rc *eos_io.RuntimeContext, log *zap.Logger) error {
	log.Info("📦 Installing Packer (RHEL/CentOS)")
	cmd := `
		sudo yum install -y yum-utils &&
		sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo &&
		sudo yum install -y packer`
	_, err := execute.Run(rc.Ctx, execute.Options{
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}

func installPackerMacOS(rc *eos_io.RuntimeContext, log *zap.Logger) error {
	log.Info("📦 Installing Packer (macOS via Homebrew)")
	cmd := `
		brew tap hashicorp/tap &&
		brew install hashicorp/tap/packer`
	_, err := execute.Run(rc.Ctx, execute.Options{
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}
