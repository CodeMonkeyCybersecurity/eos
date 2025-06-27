// cmd/create/fail2ban.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ubuntu"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	enableEmail    bool
	emailAddr      string
	banTime        string
	findTime       string
	maxRetry       int
	ignoreIPs      []string
	enableServices []string
)

var CreateFail2banCmd = &cobra.Command{
	Use:   "fail2ban",
	Short: "Deploy and configure Fail2Ban with comprehensive protection",
	Long: `Install and configure Fail2Ban with enhanced security settings.

This command installs Fail2Ban and configures it with:
- SSH brute force protection (sshd, sshd-ddos)
- Optional web server protection (nginx, apache)
- Optional application protection (docker, postgresql, etc.)
- Customizable ban times and retry limits
- Email notifications (optional)
- IP whitelist management

Examples:
  # Basic installation with SSH protection
  eos create fail2ban

  # With email notifications
  eos create fail2ban --enable-email --email security@example.com

  # With custom ban time and additional services
  eos create fail2ban --ban-time 24h --enable-services nginx,docker

  # With IP whitelist
  eos create fail2ban --ignore-ips "10.0.0.0/8,192.168.0.0/16"`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting enhanced Fail2Ban setup",
			zap.String("user", os.Getenv("USER")),
			zap.String("command_line", strings.Join(os.Args, " ")),
			zap.Bool("enable_email", enableEmail),
			zap.Strings("additional_services", enableServices))

		// Parse duration flags
		banDuration, err := parseDuration(banTime)
		if err != nil {
			logger.Error(" Invalid ban time duration", zap.String("ban_time", banTime), zap.Error(err))
			return fmt.Errorf("invalid ban time: %w", err)
		}

		findDuration, err := parseDuration(findTime)
		if err != nil {
			logger.Error(" Invalid find time duration", zap.String("find_time", findTime), zap.Error(err))
			return fmt.Errorf("invalid find time: %w", err)
		}

		logger.Info(" Configuration parameters",
			zap.Duration("ban_duration", banDuration),
			zap.Duration("find_duration", findDuration),
			zap.Int("max_retry", maxRetry),
			zap.Strings("ignore_ips", ignoreIPs))

		// Create configuration object
		config := &ubuntu.Fail2banConfig{
			BanDuration:    banDuration,
			FindDuration:   findDuration,
			MaxRetry:       maxRetry,
			EnableEmail:    enableEmail,
			EmailAddr:      emailAddr,
			IgnoreIPs:      ignoreIPs,
			EnableServices: enableServices,
		}

		// Use the shared enhanced implementation
		return ubuntu.ConfigureFail2banEnhanced(rc, config)
	}),
}

func parseDuration(s string) (time.Duration, error) {
	// Handle common duration formats
	switch s {
	case "10m", "30m", "1h", "2h", "6h", "12h", "24h", "48h", "72h":
		return time.ParseDuration(s)
	case "1d":
		return 24 * time.Hour, nil
	case "2d":
		return 48 * time.Hour, nil
	case "3d":
		return 72 * time.Hour, nil
	case "7d", "1w":
		return 7 * 24 * time.Hour, nil
	case "14d", "2w":
		return 14 * 24 * time.Hour, nil
	case "30d", "1mo":
		return 30 * 24 * time.Hour, nil
	}

	// If it's a plain number, assume seconds
	var num int
	if _, err := fmt.Sscanf(s, "%d", &num); err == nil && s == fmt.Sprintf("%d", num) {
		return time.Duration(num) * time.Second, nil
	}

	// Try parsing as standard Go duration
	return time.ParseDuration(s)
}

func init() {
	CreateFail2banCmd.Flags().BoolVar(&enableEmail, "enable-email", false, "Enable email notifications for bans")
	CreateFail2banCmd.Flags().StringVar(&emailAddr, "email", "", "Email address for notifications")
	CreateFail2banCmd.Flags().StringVar(&banTime, "ban-time", "1h", "Ban duration (e.g., 1h, 24h, 7d)")
	CreateFail2banCmd.Flags().StringVar(&findTime, "find-time", "10m", "Time window for failures (e.g., 10m, 1h)")
	CreateFail2banCmd.Flags().IntVar(&maxRetry, "max-retry", 5, "Number of failures before ban")
	CreateFail2banCmd.Flags().StringSliceVar(&ignoreIPs, "ignore-ips", []string{}, "Additional IPs to whitelist (comma-separated)")
	CreateFail2banCmd.Flags().StringSliceVar(&enableServices, "enable-services", []string{}, "Additional services to protect (nginx,apache,docker,postgresql,mysql,keycloak,nextcloud)")

	CreateCmd.AddCommand(CreateFail2banCmd)
}