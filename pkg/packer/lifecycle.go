// pkg/packer/lifecycle.go
package packer

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

var tracer = otel.Tracer("eos/pkg/packer")

// EnsureInstalled installs Packer cross-platform with full logging, tracing, and error wrapping
func EnsureInstalled(log *zap.Logger) error {
	ctx, span := tracer.Start(context.Background(), "EnsurePackerInstalled")
	defer span.End()

	if platform.IsCommandAvailable("packer") {
		log.Info("✅ Packer already installed")
		return nil
	}

	switch {
	case platform.IsMacOS():
		return installPackerMacOS(ctx, log)
	case platform.IsDebian():
		return installPackerDebian(ctx, log)
	case platform.IsRHEL():
		return installPackerRHEL(ctx, log)
	default:
		err := errors.Newf("unsupported platform: %s", platform.GetOSPlatform())
		log.Error("❌ Packer installation unsupported", zap.Error(err))
		return err
	}
}

func installPackerDebian(ctx context.Context, log *zap.Logger) error {
	log.Info("📦 Installing Packer (Debian/Ubuntu)")
	cmd := `
		wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg &&
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list &&
		sudo apt update &&
		sudo apt install -y packer`
	_, err := execute.Run(execute.Options{
		Ctx:     ctx,
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}

func installPackerRHEL(ctx context.Context, log *zap.Logger) error {
	log.Info("📦 Installing Packer (RHEL/CentOS)")
	cmd := `
		sudo yum install -y yum-utils &&
		sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo &&
		sudo yum install -y packer`
	_, err := execute.Run(execute.Options{
		Ctx:     ctx,
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}

func installPackerMacOS(ctx context.Context, log *zap.Logger) error {
	log.Info("📦 Installing Packer (macOS via Homebrew)")
	cmd := `
		brew tap hashicorp/tap &&
		brew install hashicorp/tap/packer`
	_, err := execute.Run(execute.Options{
		Ctx:     ctx,
		Logger:  log,
		Command: "bash",
		Args:    []string{"-c", cmd},
		Shell:   true,
	})
	return err
}
