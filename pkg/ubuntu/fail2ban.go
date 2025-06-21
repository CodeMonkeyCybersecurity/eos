package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const fail2banConfig = `[DEFAULT]
# Ban time (in seconds)
bantime = 3600
# Number of failures before ban
maxretry = 5
# Time window for failures (in seconds)
findtime = 600

# Email notifications (configure if needed)
destemail = root@localhost
sendername = Fail2Ban
mta = sendmail

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10

# Add more jails as needed for other services
`

func configureFail2ban(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install fail2ban
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "fail2ban"); err != nil {
		return fmt.Errorf("install fail2ban: %w", err)
	}

	// Create local jail configuration
	configPath := "/etc/fail2ban/jail.local"
	if err := os.WriteFile(configPath, []byte(fail2banConfig), 0644); err != nil {
		return fmt.Errorf("write fail2ban config: %w", err)
	}
	logger.Info("Fail2ban configuration written", zap.String("path", configPath))

	// Restart and enable fail2ban
	if err := execute.RunSimple(rc.Ctx, "systemctl", "restart", "fail2ban"); err != nil {
		return fmt.Errorf("restart fail2ban: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "systemctl", "enable", "fail2ban"); err != nil {
		return fmt.Errorf("enable fail2ban: %w", err)
	}

	logger.Info("✅ Fail2ban configured for brute force protection")
	return nil
}
