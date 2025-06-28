package ubuntu

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Fail2banConfig holds the configuration for fail2ban setup
type Fail2banConfig struct {
	BanDuration    time.Duration
	FindDuration   time.Duration
	MaxRetry       int
	EnableEmail    bool
	EmailAddr      string
	IgnoreIPs      []string
	EnableServices []string
}

// DefaultFail2banConfig returns the default configuration for fail2ban
func DefaultFail2banConfig() *Fail2banConfig {
	return &Fail2banConfig{
		BanDuration:    1 * time.Hour,
		FindDuration:   10 * time.Minute,
		MaxRetry:       5,
		EnableEmail:    false,
		EmailAddr:      "",
		IgnoreIPs:      []string{},
		EnableServices: []string{}, // Only SSH protection by default
	}
}

// ConfigureFail2banEnhanced installs and configures fail2ban with basic default settings
func ConfigureFail2banEnhanced(rc *eos_io.RuntimeContext, config *Fail2banConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting basic Fail2Ban setup")

	steps := []struct {
		desc string
		fn   func() error
	}{
		{"Update package lists", func() error {
			logger.Info(" Updating package lists")
			return execute.RunSimple(rc.Ctx, "apt-get", "update")
		}},
		{"Install fail2ban", func() error {
			logger.Info(" Installing fail2ban")
			return execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "fail2ban")
		}},
		{"Copy default jail configuration", func() error {
			logger.Info(" Copying default jail configuration")
			return execute.RunSimple(rc.Ctx, "cp", "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local")
		}},
		{"Start fail2ban service", func() error {
			logger.Info(" Starting fail2ban service")
			return execute.RunSimple(rc.Ctx, "systemctl", "start", "fail2ban")
		}},
		{"Enable fail2ban service", func() error {
			logger.Info(" Enabling fail2ban service at boot")
			return execute.RunSimple(rc.Ctx, "systemctl", "enable", "fail2ban")
		}},
		{"Check fail2ban status", func() error {
			logger.Info(" Checking fail2ban status")
			return execute.RunSimple(rc.Ctx, "fail2ban-client", "status")
		}},
		{"Test fail2ban configuration", func() error {
			logger.Info(" Testing fail2ban configuration")
			return execute.RunSimple(rc.Ctx, "fail2ban-client", "-t")
		}},
	}

	startTime := time.Now()
	for i, step := range steps {
		logger.Info(" Executing step",
			zap.Int("step_number", i+1),
			zap.Int("total_steps", len(steps)),
			zap.String("description", step.desc))
		
		stepStart := time.Now()
		if err := step.fn(); err != nil {
			logger.Error(" Step failed",
				zap.String("step", step.desc),
				zap.Error(err),
				zap.Duration("step_duration", time.Since(stepStart)))
			return fmt.Errorf("%s: %w", step.desc, err)
		}
		
		logger.Info(" Step completed",
			zap.String("step", step.desc),
			zap.Duration("step_duration", time.Since(stepStart)))
	}

	logger.Info(" Fail2Ban installation completed successfully",
		zap.Duration("total_duration", time.Since(startTime)),
		zap.String("config_location", "/etc/fail2ban/jail.local"))
	
	return nil
}