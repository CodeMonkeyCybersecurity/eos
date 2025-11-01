package hecate

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikEmailConfig controls how Authentik email configuration is applied.
type AuthentikEmailConfig struct {
	DryRun bool
}

type tenantEmailSettings struct {
	EmailHost     string `json:"email_host"`
	EmailPort     int    `json:"email_port"`
	EmailUsername string `json:"email_username"`
	EmailUseTLS   bool   `json:"email_use_tls"`
	EmailUseSSL   bool   `json:"email_use_ssl"`
	EmailTimeout  int    `json:"email_timeout"`
	EmailFrom     string `json:"email_from"`
}

// ConfigureAuthentikEmail updates tenant-level SMTP settings using values from /opt/hecate/.env.
func ConfigureAuthentikEmail(rc *eos_io.RuntimeContext, cfg *AuthentikEmailConfig) error {
	if cfg == nil {
		cfg = &AuthentikEmailConfig{}
	}

	logger := otelzap.Ctx(rc.Ctx)

	if os.Geteuid() != 0 {
		return eos_err.NewUserError(
			"permission denied: %s requires root access\n\n"+
				"Run with sudo:\n  sudo eos update hecate --add authentik-email", EnvFilePath)
	}

	envVars, err := shared.ParseEnvFile(EnvFilePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", EnvFilePath, err)
	}

	requiredKeys := []string{
		"AUTHENTIK_EMAIL_HOST",
		"AUTHENTIK_EMAIL_PORT",
		"AUTHENTIK_EMAIL_USERNAME",
		"AUTHENTIK_EMAIL_PASSWORD",
		"AUTHENTIK_EMAIL_USE_TLS",
		"AUTHENTIK_EMAIL_USE_SSL",
		"AUTHENTIK_EMAIL_TIMEOUT",
		"AUTHENTIK_EMAIL_FROM",
	}

	var missing []string
	for _, key := range requiredKeys {
		if val, ok := envVars[key]; !ok || strings.TrimSpace(val) == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return eos_err.NewUserError(
			"missing Authentik email configuration in %s:\n  %s\n\n"+
				"Set these variables and rerun:\n  sudo eos update hecate --add authentik-email",
			EnvFilePath, strings.Join(missing, "\n  "))
	}

	host := envVars["AUTHENTIK_EMAIL_HOST"]
	username := envVars["AUTHENTIK_EMAIL_USERNAME"]
	password := envVars["AUTHENTIK_EMAIL_PASSWORD"]
	emailFrom := envVars["AUTHENTIK_EMAIL_FROM"]

	port, err := strconv.Atoi(envVars["AUTHENTIK_EMAIL_PORT"])
	if err != nil {
		return eos_err.NewUserError("invalid AUTHENTIK_EMAIL_PORT %q: must be an integer", envVars["AUTHENTIK_EMAIL_PORT"])
	}

	timeout, err := strconv.Atoi(envVars["AUTHENTIK_EMAIL_TIMEOUT"])
	if err != nil {
		return eos_err.NewUserError("invalid AUTHENTIK_EMAIL_TIMEOUT %q: must be an integer (seconds)", envVars["AUTHENTIK_EMAIL_TIMEOUT"])
	}

	useTLS, err := strconv.ParseBool(envVars["AUTHENTIK_EMAIL_USE_TLS"])
	if err != nil {
		return eos_err.NewUserError("invalid AUTHENTIK_EMAIL_USE_TLS %q: use true or false", envVars["AUTHENTIK_EMAIL_USE_TLS"])
	}

	useSSL, err := strconv.ParseBool(envVars["AUTHENTIK_EMAIL_USE_SSL"])
	if err != nil {
		return eos_err.NewUserError("invalid AUTHENTIK_EMAIL_USE_SSL %q: use true or false", envVars["AUTHENTIK_EMAIL_USE_SSL"])
	}

	payload := map[string]interface{}{
		"email_host":     host,
		"email_port":     port,
		"email_username": username,
		"email_password": password,
		"email_use_tls":  useTLS,
		"email_use_ssl":  useSSL,
		"email_timeout":  timeout,
		"email_from":     emailFrom,
	}

	logger.Info("Configuring Authentik email settings",
		zap.String("email_host", host),
		zap.Int("email_port", port),
		zap.String("email_username_masked", maskSensitive(username)),
		zap.Bool("email_use_tls", useTLS),
		zap.Bool("email_use_ssl", useSSL),
		zap.Int("email_timeout", timeout),
		zap.String("email_from", emailFrom),
		zap.Bool("dry_run", cfg.DryRun))

	if cfg.DryRun {
		logger.Info("[dry-run] Skipping Authentik tenant update")
		return nil
	}

	token, baseURL, err := discoverAuthentikCredentials(rc)
	if err != nil {
		return err
	}

	client := authentik.NewUnifiedClient(baseURL, token)

	respBody, err := client.Patch(rc.Ctx, "/core/tenants/current/", payload)
	if err != nil {
		return fmt.Errorf("failed to update Authentik tenant email settings: %w", err)
	}

	var updated tenantEmailSettings
	if err := json.Unmarshal(respBody, &updated); err != nil {
		logger.Warn("Authentik email update succeeded but response could not be parsed",
			zap.Error(err))
	} else {
		logger.Info("Authentik email settings updated",
			zap.String("email_host", updated.EmailHost),
			zap.Int("email_port", updated.EmailPort),
			zap.String("email_username_masked", maskSensitive(updated.EmailUsername)),
			zap.Bool("email_use_tls", updated.EmailUseTLS),
			zap.Bool("email_use_ssl", updated.EmailUseSSL),
			zap.Int("email_timeout", updated.EmailTimeout),
			zap.String("email_from", updated.EmailFrom))
	}

	return nil
}

func maskSensitive(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 3 {
		return "***"
	}
	return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
}
