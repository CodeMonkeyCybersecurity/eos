// pkg/hecate/authentik_email.go
// Authentik email configuration via interactive wizard
// RATIONALE: Configures SMTP settings for Authentik 2025.x multi-tenant email
// ARCHITECTURE: Assess → Intervene → Evaluate pattern with .env file management

package hecate

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikEmailConfig controls how Authentik email configuration is applied
type AuthentikEmailConfig struct {
	DryRun      bool   // Preview changes without applying
	TestEmail   string // Optional: send test email to this address after configuration
	SkipRestart bool   // Update .env but don't restart containers
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

type tenantSummary struct {
	PK         string `json:"pk"`
	TenantUUID string `json:"tenant_uuid"`
	UUID       string `json:"uuid"`
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	Default    bool   `json:"default"`
}

func (t *tenantSummary) identifier() string {
	if t == nil {
		return ""
	}
	switch {
	case strings.TrimSpace(t.PK) != "":
		return t.PK
	case strings.TrimSpace(t.TenantUUID) != "":
		return t.TenantUUID
	case strings.TrimSpace(t.UUID) != "":
		return t.UUID
	case strings.TrimSpace(t.ID) != "":
		return t.ID
	default:
		return ""
	}
}

// ConfigureAuthentikEmail configures Authentik email settings via interactive wizard
// ASSESS: Check current .env for email variables
// INTERVENE: Prompt for missing values, update .env, restart containers
// EVALUATE: Verify config loaded in Authentik, optionally test email delivery
func ConfigureAuthentikEmail(rc *eos_io.RuntimeContext, cfg *AuthentikEmailConfig) error {
	if cfg == nil {
		cfg = &AuthentikEmailConfig{}
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Require root access for .env file modification
	if os.Geteuid() != 0 {
		return eos_err.NewUserError(
			"permission denied: email configuration requires root access\n\n" +
				"Run with sudo:\n  sudo eos update hecate --add authentik-email")
	}

	logger.Info("Configuring Authentik email settings",
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("skip_restart", cfg.SkipRestart),
		zap.String("test_email", cfg.TestEmail))

	// ASSESS: Load .env file and check for missing variables
	envManager, err := NewEnvManager(EnvFilePath)
	if err != nil {
		return fmt.Errorf("failed to initialize .env manager: %w", err)
	}

	// Define required email variables with validation
	requiredVars := []*EnvVariable{
		{
			Key:          AuthentikEmailHostKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateHostname,
			HelpText:     "SMTP server hostname (e.g., smtp.gmail.com, mail.example.com)",
			DefaultValue: "",
		},
		{
			Key:          AuthentikEmailPortKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidatePort,
			HelpText:     "SMTP port (587 for TLS, 465 for SSL, 25 for plain)",
			DefaultValue: AuthentikEmailDefaultPort,
		},
		{
			Key:          AuthentikEmailUsernameKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateEmailAddress,
			HelpText:     "SMTP username (typically your email address)",
			DefaultValue: "",
		},
		{
			Key:          AuthentikEmailPasswordKey,
			Required:     true,
			IsSecret:     true, // Hide input during prompting
			Validator:    nil,  // No validation - any password is valid
			HelpText:     "SMTP password (will not be echoed)",
			DefaultValue: "",
		},
		{
			Key:          AuthentikEmailUseTLSKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateBoolean,
			HelpText:     "Enable TLS encryption (true/false)",
			DefaultValue: AuthentikEmailDefaultUseTLS,
		},
		{
			Key:          AuthentikEmailUseSSLKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateBoolean,
			HelpText:     "Enable SSL encryption (true/false) - mutually exclusive with TLS",
			DefaultValue: AuthentikEmailDefaultUseSSL,
		},
		{
			Key:          AuthentikEmailTimeoutKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateTimeout,
			HelpText:     "SMTP connection timeout in seconds (1-300)",
			DefaultValue: AuthentikEmailDefaultTimeout,
		},
		{
			Key:          AuthentikEmailFromKey,
			Required:     true,
			IsSecret:     false,
			Validator:    ValidateEmailAddress,
			HelpText:     "Sender email address (e.g., noreply@example.com)",
			DefaultValue: "",
		},
	}

	// Load existing .env file
	if err := envManager.LoadEnv(rc); err != nil {
		return fmt.Errorf("failed to load .env file: %w", err)
	}

	// Check for missing variables
	missing, err := envManager.CheckMissingVariables(requiredVars)
	if err != nil {
		return fmt.Errorf("failed to check missing variables: %w", err)
	}

	if len(missing) > 0 {
		logger.Info("Email configuration wizard",
			zap.Int("missing_variables", len(missing)),
			zap.String("env_file", EnvFilePath))

		logger.Info("WHY: Authentik requires SMTP settings to send password reset emails, 2FA codes, and notifications")
	} else {
		logger.Info("All email variables already configured",
			zap.String("env_file", EnvFilePath))
	}

	// INTERVENE: Prompt for missing variables
	if len(missing) > 0 && !cfg.DryRun {
		if err := envManager.PromptForVariables(rc, missing); err != nil {
			return fmt.Errorf("failed to collect email variables: %w", err)
		}

		// Write updated .env file (with backup)
		logger.Info("Updating .env file with email configuration",
			zap.String("path", EnvFilePath))

		if err := envManager.WriteEnv(rc); err != nil {
			logger.Error("Failed to write .env file",
				zap.Error(err),
				zap.String("backup", envManager.BackupPath))

			// Offer to restore backup
			logger.Info("Backup available for restore",
				zap.String("backup_path", envManager.BackupPath))

			return fmt.Errorf("failed to write .env file: %w", err)
		}

		logger.Info("Email configuration written to .env",
			zap.String("env_file", EnvFilePath),
			zap.String("backup", envManager.BackupPath))
	} else if cfg.DryRun {
		logger.Info("[dry-run] Would prompt for missing variables and update .env",
			zap.Int("missing_count", len(missing)))
	}

	// INTERVENE: Restart Authentik containers to load new config
	if !cfg.SkipRestart && !cfg.DryRun {
		logger.Info("Restarting Authentik containers to load new email configuration",
			zap.String("project", "hecate"),
			zap.Strings("services", []string{"server", "worker"}))

		restartCfg := &docker.RestartComposeServicesConfig{
			ProjectName:  "hecate",
			ServiceNames: []string{"server", "worker"},
			Timeout:      30 * time.Second,
			HealthCheck:  true,
		}

		if err := docker.RestartComposeServices(rc, restartCfg); err != nil {
			return fmt.Errorf("failed to restart Authentik containers: %w\n\n"+
				"Email configuration was written to .env, but containers failed to restart.\n"+
				"Try manually restarting: cd /opt/hecate && docker compose restart server worker", err)
		}

		logger.Info("Authentik containers restarted successfully")
	} else if cfg.SkipRestart {
		logger.Info("Skipping container restart (--skip-restart flag set)")
	} else if cfg.DryRun {
		logger.Info("[dry-run] Would restart Authentik containers")
	}

	// EVALUATE: Update Authentik admin settings via API (global email configuration)
	if !cfg.DryRun && !cfg.SkipRestart {
		logger.Info("Updating Authentik global email settings via API")

		// Parse values from envManager for API update
		host := envManager.Variables[AuthentikEmailHostKey].Value
		portStr := envManager.Variables[AuthentikEmailPortKey].Value
		port, _ := strconv.Atoi(portStr)
		username := envManager.Variables[AuthentikEmailUsernameKey].Value
		password := envManager.Variables[AuthentikEmailPasswordKey].Value
		emailFrom := envManager.Variables[AuthentikEmailFromKey].Value
		useTLSStr := envManager.Variables[AuthentikEmailUseTLSKey].Value
		useSSLStr := envManager.Variables[AuthentikEmailUseSSLKey].Value
		timeoutStr := envManager.Variables[AuthentikEmailTimeoutKey].Value

		useTLS, _ := strconv.ParseBool(useTLSStr)
		useSSL, _ := strconv.ParseBool(useSSLStr)
		timeout, _ := strconv.Atoi(timeoutStr)

		// Build payload for admin settings endpoint
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

		logger.Info("Updating Authentik admin settings",
			zap.String("email_host", host),
			zap.Int("email_port", port),
			zap.String("email_username_masked", maskSensitive(username)),
			zap.Bool("email_use_tls", useTLS),
			zap.Bool("email_use_ssl", useSSL),
			zap.Int("email_timeout", timeout),
			zap.String("email_from", emailFrom))

		token, baseURL, err := discoverAuthentikCredentials(rc)
		if err != nil {
			logger.Warn("Failed to discover Authentik credentials for API update",
				zap.Error(err))
			logger.Info("Email configuration written to .env and containers restarted")
			logger.Info("Settings will be loaded from .env on next container start")
		} else {
			client := authentik.NewUnifiedClient(baseURL, token)

			// Update global admin settings (not tenant settings)
			// RATIONALE: /admin/settings/ is the global email configuration endpoint
			// This is what email stages with use_global_settings=true will use
			respBody, err := client.Patch(rc.Ctx, "/admin/settings/", payload)
			if err != nil {
				logger.Warn("Failed to update Authentik admin settings via API",
					zap.Error(err))
				logger.Info("Email configuration written to .env and containers restarted")
				logger.Info("Settings will be loaded from .env on next container start")
			} else {
				var updated tenantEmailSettings
				if err := json.Unmarshal(respBody, &updated); err != nil {
					logger.Debug("Admin settings response could not be parsed (this is normal)",
						zap.Error(err))
					logger.Info("Authentik admin settings updated successfully")
				} else {
					logger.Info("Authentik admin settings updated successfully",
						zap.String("email_host", updated.EmailHost),
						zap.Int("email_port", updated.EmailPort),
						zap.String("email_username_masked", maskSensitive(updated.EmailUsername)),
						zap.Bool("email_use_tls", updated.EmailUseTLS),
						zap.Bool("email_use_ssl", updated.EmailUseSSL),
						zap.Int("email_timeout", updated.EmailTimeout),
						zap.String("email_from", updated.EmailFrom))
				}
			}
		}
	}

	// EVALUATE: Configure all email stages to use global settings
	if !cfg.DryRun && !cfg.SkipRestart {
		logger.Info("Configuring email stages to use global settings")

		token, baseURL, err := discoverAuthentikCredentials(rc)
		if err != nil {
			logger.Warn("Failed to discover Authentik credentials for email stage configuration",
				zap.Error(err))
			logger.Info("Email configuration complete, but email stages not updated")
			logger.Info("Manually configure email stages to use global settings in Authentik UI")
		} else {
			client := authentik.NewUnifiedClient(baseURL, token)

			// Update all email stages to use global settings
			if err := configureEmailStagesToUseGlobalSettings(rc, client); err != nil {
				logger.Warn("Failed to configure email stages",
					zap.Error(err))
				logger.Info("Email configuration complete, but email stages may need manual configuration")
				logger.Info("In Authentik UI: Flows & Stages → Stages → Edit each email stage → Enable 'Use global settings'")
			} else {
				logger.Info("Email stages configured successfully")
			}
		}
	}

	// EVALUATE: Send test email if requested
	if cfg.TestEmail != "" && !cfg.DryRun {
		logger.Info("Sending test email",
			zap.String("recipient", cfg.TestEmail))

		token, baseURL, err := discoverAuthentikCredentials(rc)
		if err != nil {
			logger.Warn("Failed to discover Authentik credentials for test email",
				zap.Error(err))
			logger.Info("To test email manually, trigger a password reset in Authentik UI")
		} else {
			client := authentik.NewUnifiedClient(baseURL, token)

			// Find an email stage to use for testing
			if err := sendTestEmail(rc, client, cfg.TestEmail); err != nil {
				logger.Warn("Failed to send test email",
					zap.Error(err))
				logger.Info("Email configuration is complete, but test email failed")
				logger.Info("Check SMTP credentials and firewall rules")
				logger.Info("To test manually, trigger a password reset in Authentik UI")
			} else {
				logger.Info("Test email sent successfully",
					zap.String("recipient", cfg.TestEmail))
			}
		}
	}

	logger.Info("Authentik email configuration complete")

	return nil
}

// sendTestEmail sends a test email via an Authentik email stage
func sendTestEmail(rc *eos_io.RuntimeContext, client *authentik.UnifiedClient, recipient string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// List all email stages to find one we can use for testing
	data, err := client.Get(rc.Ctx, "/stages/email/")
	if err != nil {
		return fmt.Errorf("failed to list email stages: %w", err)
	}

	var stagesResponse struct {
		Results []struct {
			PK                string `json:"pk"`
			Name              string `json:"name"`
			UseGlobalSettings bool   `json:"use_global_settings"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &stagesResponse); err != nil {
		return fmt.Errorf("failed to parse email stages response: %w", err)
	}

	if len(stagesResponse.Results) == 0 {
		return fmt.Errorf("no email stages found - cannot send test email")
	}

	// Find a stage that uses global settings (preferred) or use the first one
	var selectedStage *struct {
		PK                string `json:"pk"`
		Name              string `json:"name"`
		UseGlobalSettings bool   `json:"use_global_settings"`
	}

	for i := range stagesResponse.Results {
		if stagesResponse.Results[i].UseGlobalSettings {
			selectedStage = &stagesResponse.Results[i]
			break
		}
	}

	if selectedStage == nil {
		selectedStage = &stagesResponse.Results[0]
	}

	logger.Info("Using email stage for test",
		zap.String("stage_name", selectedStage.Name),
		zap.String("stage_pk", selectedStage.PK),
		zap.Bool("uses_global_settings", selectedStage.UseGlobalSettings))

	// Send test email via the stage's test endpoint
	testPayload := map[string]interface{}{
		"to": recipient,
	}

	testPath := fmt.Sprintf("/stages/email/%s/test/", selectedStage.PK)
	_, err = client.Post(rc.Ctx, testPath, testPayload)
	if err != nil {
		return fmt.Errorf("failed to send test email via stage %s: %w", selectedStage.Name, err)
	}

	return nil
}

// configureEmailStagesToUseGlobalSettings updates all email stages to use global SMTP settings
// RATIONALE: Email stages can have individual settings OR use global settings from .env
// SECURITY: Global settings ensure consistent email configuration across all flows
func configureEmailStagesToUseGlobalSettings(rc *eos_io.RuntimeContext, client *authentik.UnifiedClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	// List all email stages
	data, err := client.Get(rc.Ctx, "/stages/email/")
	if err != nil {
		return fmt.Errorf("failed to list email stages: %w", err)
	}

	// Parse email stages list response
	var stagesResponse struct {
		Results []struct {
			PK                    string `json:"pk"`
			Name                  string `json:"name"`
			UseGlobalSettings     bool   `json:"use_global_settings"`
			ActivateUserOnSuccess bool   `json:"activate_user_on_success"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &stagesResponse); err != nil {
		return fmt.Errorf("failed to parse email stages response: %w", err)
	}

	if len(stagesResponse.Results) == 0 {
		logger.Info("No email stages found - skipping email stage configuration")
		return nil
	}

	logger.Info("Found email stages to configure",
		zap.Int("count", len(stagesResponse.Results)))

	// Update each email stage
	updatedCount := 0
	for _, stage := range stagesResponse.Results {
		// Skip if already using global settings
		if stage.UseGlobalSettings {
			logger.Debug("Email stage already using global settings",
				zap.String("stage_name", stage.Name),
				zap.String("stage_pk", stage.PK))
			continue
		}

		logger.Info("Updating email stage to use global settings",
			zap.String("stage_name", stage.Name),
			zap.String("stage_pk", stage.PK))

		// PATCH the email stage to use global settings
		payload := map[string]interface{}{
			"use_global_settings":      true,
			"activate_user_on_success": true, // Also ensure users are activated on email verification
		}

		patchPath := fmt.Sprintf("/stages/email/%s/", stage.PK)
		_, err := client.Patch(rc.Ctx, patchPath, payload)
		if err != nil {
			logger.Warn("Failed to update email stage",
				zap.String("stage_name", stage.Name),
				zap.String("stage_pk", stage.PK),
				zap.Error(err))
			continue
		}

		logger.Info("Email stage updated successfully",
			zap.String("stage_name", stage.Name),
			zap.String("stage_pk", stage.PK))
		updatedCount++
	}

	if updatedCount > 0 {
		logger.Info("Email stages configured to use global settings",
			zap.Int("updated_count", updatedCount),
			zap.Int("total_count", len(stagesResponse.Results)))
	} else {
		logger.Info("All email stages already using global settings")
	}

	return nil
}

type tenantEndpointCandidate struct {
	ListPath       string
	BuildPatchPath func(string) string
	Description    string
}

func resolveAuthentikTenant(rc *eos_io.RuntimeContext, client *authentik.UnifiedClient) (*tenantSummary, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	candidates := []tenantEndpointCandidate{
		{
			ListPath: "/core/tenants/",
			BuildPatchPath: func(id string) string {
				return fmt.Sprintf("/core/tenants/%s/", id)
			},
			Description: "Authentik ≤2024.12 core tenants endpoint",
		},
		{
			ListPath: "/tenants/tenants/",
			BuildPatchPath: func(id string) string {
				return fmt.Sprintf("/tenants/tenants/%s/", id)
			},
			Description: "Authentik 2025 tenants endpoint",
		},
		{
			ListPath: "/tenants/",
			BuildPatchPath: func(id string) string {
				return fmt.Sprintf("/tenants/%s/", id)
			},
			Description: "Authentik 2025 short tenants endpoint",
		},
	}

	var lastErr error

	for _, candidate := range candidates {
		logger.Debug("Attempting Authentik tenant discovery",
			zap.String("endpoint", candidate.ListPath),
			zap.String("description", candidate.Description))

		data, err := client.Get(rc.Ctx, candidate.ListPath)
		if err != nil {
			logger.Debug("Tenant endpoint request failed",
				zap.String("endpoint", candidate.ListPath),
				zap.Error(err))
			lastErr = err
			continue
		}

		tenants, err := parseTenantListResponse(data)
		if err != nil {
			logger.Debug("Failed to parse tenant list response",
				zap.String("endpoint", candidate.ListPath),
				zap.Error(err))
			lastErr = err
			continue
		}

		if len(tenants) == 0 {
			logger.Debug("Tenant endpoint returned no tenants",
				zap.String("endpoint", candidate.ListPath))
			lastErr = fmt.Errorf("no tenants returned from %s", candidate.ListPath)
			continue
		}

		selected := selectTenant(tenants)
		id := selected.identifier()
		if id == "" {
			logger.Debug("Tenant missing identifier fields",
				zap.Any("tenant", selected))
			lastErr = fmt.Errorf("tenant has no identifier in %s", candidate.ListPath)
			continue
		}

		patchPath := candidate.BuildPatchPath(id)
		logger.Debug("Tenant resolved",
			zap.String("endpoint", candidate.ListPath),
			zap.String("tenant_identifier", id),
			zap.String("patch_endpoint", patchPath))

		return selected, patchPath, nil
	}

	if lastErr != nil {
		return nil, "", fmt.Errorf("failed to list Authentik tenants: %w", lastErr)
	}

	return nil, "", fmt.Errorf("failed to list Authentik tenants: no endpoints succeeded")
}

func parseTenantListResponse(data []byte) ([]*tenantSummary, error) {
	type tenantEnvelope struct {
		Results []*tenantSummary `json:"results"`
		Tenants []*tenantSummary `json:"tenants"`
	}

	var envelope tenantEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil {
		switch {
		case len(envelope.Results) > 0:
			return envelope.Results, nil
		case len(envelope.Tenants) > 0:
			return envelope.Tenants, nil
		}
	}

	var arr []*tenantSummary
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	// If both attempts failed, return last error for context.
	if len(envelope.Results) == 0 && len(envelope.Tenants) == 0 && len(arr) == 0 {
		return nil, fmt.Errorf("unexpected tenant response format")
	}

	return arr, nil
}

func selectTenant(tenants []*tenantSummary) *tenantSummary {
	if len(tenants) == 0 {
		return nil
	}

	for _, tenant := range tenants {
		if tenant != nil && tenant.Default {
			return tenant
		}
	}

	return tenants[0]
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
