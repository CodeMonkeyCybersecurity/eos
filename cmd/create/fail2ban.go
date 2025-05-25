// cmd/create/fail2ban.go

package create

import (
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateFail2banCmd = &cobra.Command{
	Use:   "fail2ban",
	Short: "Deploy and configure Fail2Ban",
	Long:  "Install Fail2Ban, apply secure jail.local settings, and enable basic SSH protection.",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("🚧 Starting Fail2Ban setup...")

		steps := []struct {
			desc string
			fn   func() error
		}{
			{"Update apt", func() error {
				_, err := execute.RunShell("apt update")
				return err
			}},
			{"Install fail2ban", func() error {
				_, err := execute.RunShell("apt install -y fail2ban")
				return err
			}},
			{"Backup jail.conf", func() error {
				return execute.RunSimple("cp", "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.conf.bak")
			}},
			{"Write jail.local", createJailLocal},
			{"Restart fail2ban", func() error {
				return execute.RunSimple("systemctl", "restart", "fail2ban")
			}},
			{"Enable fail2ban", func() error {
				return execute.RunSimple("systemctl", "enable", "fail2ban")
			}},
			{"Check fail2ban status", func() error {
				return execute.RunSimple("fail2ban-client", "status")
			}},
			{"Check sshd jail status", func() error {
				return execute.RunSimple("fail2ban-client", "status", "sshd")
			}},
		}

		for _, step := range steps {
			zap.L().Info("▶ "+step.desc, zap.String("step", step.desc))
			if err := step.fn(); err != nil {
				zap.L().Error("❌ Failed: "+step.desc, zap.Error(err))
				return err
			}
		}

		zap.L().Info("✅ Fail2Ban deployed successfully!")
		return nil
	}),
}

func createJailLocal() error {
	config := `[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
`

	tmpFile := "/tmp/jail.local" // Replace with os.CreateTemp() if safety is a concern

	if err := os.WriteFile(tmpFile, []byte(config), 0644); err != nil {
		return err
	}
	return execute.RunSimple("mv", tmpFile, "/etc/fail2ban/jail.local")
}

func init() {
	CreateCmd.AddCommand(CreateFail2banCmd)
}
