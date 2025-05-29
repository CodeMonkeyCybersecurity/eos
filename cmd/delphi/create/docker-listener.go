// cmd/delphi/create/docker-listener.go
package create

import (
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var DockerListenerCmd = &cobra.Command{
	Use:   "docker-listener",
	Short: "Installs and configures the Delphi DockerListener for Wazuh",
	Long:  "Sets up a Python virtual environment and configures Wazuh's DockerListener integration.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("🚀 Setting up Delphi DockerListener...")

		steps := []struct {
			desc string
			fn   func() error
		}{
			{"🔧 apt update", func() error { _, err := execute.RunShell(rc.Ctx, "apt update"); return err }},
			{"🔧 install python3-venv + pip", func() error {
				_, err := execute.RunShell(rc.Ctx, "apt install -y python3-venv python3-pip")
				return err
			}},
			{"📂 create venv dir", func() error {
				return execute.RunSimple(rc.Ctx, "mkdir", "-p", shared.VenvPath)
			}},
			{"🐍 create venv", func() error {
				return execute.RunSimple(rc.Ctx, "python3", "-m", "venv", shared.VenvPath)
			}},
			{"📦 pip install requirements", func() error {
				return execute.RunSimple(rc.Ctx, shared.VenvPath+"/bin/pip", "install",
					"docker==7.1.0", "urllib3==1.26.20", "requests==2.32.2")
			}},
			{"✏️ patch DockerListener", func() error {
				return patchDockerListener(rc)
			}},
			{"🔄 restart wazuh-agent", func() error {
				return execute.RunSimple(rc.Ctx, "systemctl", "restart", "wazuh-agent")
			}},
		}

		for _, step := range steps {
			otelzap.Ctx(rc.Ctx).Info(step.desc)
			if err := step.fn(); err != nil {
				otelzap.Ctx(rc.Ctx).Error("❌ Failed: "+step.desc, zap.Error(err))
				return err
			}
		}

		otelzap.Ctx(rc.Ctx).Info("✅ DockerListener setup complete.")
		return nil
	}),
}

func patchDockerListener(rc *eos_io.RuntimeContext) error {
	path := shared.DockerListener
	if _, err := os.Stat(path); os.IsNotExist(err) {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ DockerListener script not found", zap.String("path", path))
		return nil
	}

	backup := path + ".bak"
	if err := execute.RunSimple(rc.Ctx, "cp", path, backup); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to backup DockerListener", zap.Error(err))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		return nil // malformed or empty script
	}

	shebang := "#!" + shared.VenvPath + "/bin/python3"
	newContent := shebang + "\n" + strings.Join(lines[1:], "\n")

	if err := os.WriteFile(path, []byte(newContent), shared.DirPermStandard); err != nil {
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("✅ DockerListener script patched", zap.String("path", path))
	return nil
}
