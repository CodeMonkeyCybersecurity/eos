// cmd/deploy/fail2ban.go

package deploy

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var fail2banCmd = &cobra.Command{
	Use:   "fail2ban",
	Short: "Deploy and configure Fail2Ban",
	Long:  "Install Fail2Ban, apply secure jail.local settings, and enable basic SSH protection.",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("Starting Fail2Ban setup...")

		steps := []struct {
			desc string
			fn   func() error
		}{
			{"Update apt", func() error { return execute.Execute("sudo", "apt", "update") }},
			{"Install fail2ban", func() error { return execute.Execute("sudo", "apt", "install", "-y", "fail2ban") }},
			{"Backup jail.conf", func() error {
				return execute.Execute("sudo", "cp", "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.conf.bak")
			}},
			{"Write jail.local", createJailLocal},
			{"Restart fail2ban", func() error { return execute.Execute("sudo", "systemctl", "restart", "fail2ban") }},
			{"Enable fail2ban", func() error { return execute.Execute("sudo", "systemctl", "enable", "fail2ban") }},
			{"Check fail2ban status", func() error { return execute.Execute("sudo", "fail2ban-client", "status") }},
			{"Check sshd jail status", func() error { return execute.Execute("sudo", "fail2ban-client", "status", "sshd") }},
		}

		for _, step := range steps {
			log.Info("▶ " + step.desc)
			if err := step.fn(); err != nil {
				log.Error("❌ Failed: "+step.desc, zap.Error(err))
				os.Exit(1)
			}
		}

		log.Info("✅ Fail2Ban deployed successfully!")
	},
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
	tmpFile := "/tmp/jail.local"
	if err := os.WriteFile(tmpFile, []byte(config), 0644); err != nil {
		return err
	}
	return execute.Execute("sudo", "mv", tmpFile, "/etc/fail2ban/jail.local")
}

func init() {
	DeployCmd.AddCommand(fail2banCmd)
}
