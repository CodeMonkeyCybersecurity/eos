package hecate

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// DefaultFlowsConfig configures the default Authentik flow deployment.
type DefaultFlowsConfig struct {
	App            string // Application slug (e.g., "bionicgpt")
	Domain         string // Optional domain override
	DryRun         bool   // Preview changes without applying
	UpdateExisting bool   // Replace existing flows with new templates
}

// EnableDefaultFlows deploys opinionated 2025.10 Authentik flows for the given app.
func EnableDefaultFlows(rc *eos_io.RuntimeContext, cfg *DefaultFlowsConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cfg == nil {
		return fmt.Errorf("config is required")
	}

	appSlug := strings.ToLower(strings.TrimSpace(cfg.App))
	if appSlug == "" {
		appSlug = BionicGPTApplicationSlug
	}
	appTitle := formatAppTitle(appSlug)

	logger.Info("Enabling Authentik default flows",
		zap.String("app_slug", appSlug),
		zap.String("app_title", appTitle),
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("update_existing", cfg.UpdateExisting))

	// Discover Authentik credentials (shared helper ensures consistent behavior).
	apiToken, baseURL, err := discoverAuthentikCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to discover Authentik credentials: %w", err)
	}

	client := authentik.NewClient(baseURL, apiToken)

	// Ensure the default user group exists (BionicGPT Users).
	groupAttrs := map[string]interface{}{
		"description": "Default group for " + appTitle + " authenticated users",
	}

	var group *authentik.GroupResponse
	if cfg.DryRun {
		group, err = client.GetGroupByName(rc.Ctx, BionicGPTUserGroupName)
		if err != nil || group == nil {
			logger.Info("[dry-run] Would create Authentik group",
				zap.String("group", BionicGPTUserGroupName))
		} else {
			logger.Info("[dry-run] Authentik group already exists",
				zap.String("group", group.Name),
				zap.String("pk", group.PK))
		}
	} else {
		group, err = client.CreateGroupIfNotExists(rc.Ctx, BionicGPTUserGroupName, groupAttrs)
		if err != nil {
			return fmt.Errorf("failed to ensure Authentik group %q: %w", BionicGPTUserGroupName, err)
		}
		logger.Info("✓ Authentik group ensured",
			zap.String("group", group.Name),
			zap.String("pk", group.PK))
	}

	groupUUID := ""
	if group != nil {
		groupUUID = group.PK
	}

	templateData := flowTemplateData{
		AppSlug:   appSlug,
		AppTitle:  appTitle,
		GroupUUID: groupUUID,
		GroupName: BionicGPTUserGroupName,
	}

	flows := []flowDefinition{
		{
			Name:           "Invalidation (Global)",
			Slug:           fmt.Sprintf("%s-invalidation-global", appSlug),
			Template:       invalidationGlobalTemplate,
			RequiresGroup:  false,
			UpdateExisting: cfg.UpdateExisting,
		},
		{
			Name:           "Invalidation (Provider)",
			Slug:           fmt.Sprintf("%s-invalidation-provider", appSlug),
			Template:       invalidationProviderTemplate,
			RequiresGroup:  false,
			UpdateExisting: cfg.UpdateExisting,
		},
		{
			Name:           "Recovery",
			Slug:           fmt.Sprintf("%s-recovery", appSlug),
			Template:       recoveryFlowTemplate,
			RequiresGroup:  false,
			UpdateExisting: cfg.UpdateExisting,
		},
		{
			Name:           "Enrollment",
			Slug:           fmt.Sprintf("%s-enrollment", appSlug),
			Template:       enrollmentFlowTemplate,
			RequiresGroup:  true,
			UpdateExisting: cfg.UpdateExisting,
		},
		{
			Name:           "Authentication",
			Slug:           fmt.Sprintf("%s-authentication", appSlug),
			Template:       authenticationFlowTemplate,
			RequiresGroup:  false,
			UpdateExisting: cfg.UpdateExisting,
		},
		{
			Name:           "Unenrollment",
			Slug:           fmt.Sprintf("%s-unenrollment", appSlug),
			Template:       unenrollmentFlowTemplate,
			RequiresGroup:  false,
			UpdateExisting: cfg.UpdateExisting,
		},
	}

	importedSlugs := make([]string, 0, len(flows))

	for _, flow := range flows {
		if flow.RequiresGroup && groupUUID == "" {
			logger.Warn("Skipping flow (missing group UUID)",
				zap.String("flow", flow.Name))
			continue
		}

		rendered, err := renderFlowTemplate(flow.Template, templateData)
		if err != nil {
			return fmt.Errorf("failed to render flow template %q: %w", flow.Name, err)
		}

		// CRITICAL: Log rendered YAML preview to verify template interpolation
		logger.Debug("Rendered flow YAML",
			zap.String("flow", flow.Name),
			zap.Int("yaml_size", len(rendered)),
			zap.String("yaml_preview", string(rendered[:min(500, len(rendered))]))) // First 500 chars

		if cfg.DryRun {
			logger.Info("[dry-run] Would import Authentik flow",
				zap.String("flow", flow.Name),
				zap.String("slug", flow.Slug))
			continue
		}

		if flow.UpdateExisting {
			if err := client.DeleteFlowBySlug(rc.Ctx, flow.Slug); err != nil {
				logger.Warn("Failed to delete existing flow before update",
					zap.String("slug", flow.Slug),
					zap.Error(err))
			}
		}

		logger.Info("Importing flow to Authentik",
			zap.String("flow", flow.Name),
			zap.String("slug", flow.Slug))

		if err := client.ImportFlow(rc.Ctx, rendered); err != nil {
			return fmt.Errorf("failed to import flow %q: %w", flow.Name, err)
		}

		// CRITICAL: Verify flow actually exists after import
		// RATIONALE: Authentik may return 200 OK but not create the flow (validation errors, etc.)
		// Use retry to handle eventual consistency (API indexing lag)
		// RETRY STRATEGY: 5 attempts with 2s initial delay (2s, 4s, 8s, 16s, 32s = max 62s wait)
		verifiedFlow := getFlowWithRetry(rc, client, logger, flow.Slug, 5, 2*time.Second)
		if verifiedFlow == nil {
			logger.Error("Flow import reported success but flow does not exist",
				zap.String("flow_name", flow.Name),
				zap.String("slug", flow.Slug),
				zap.String("remediation", "Check Authentik logs and YAML syntax"))
			return fmt.Errorf("flow import verification failed: flow %q does not exist after import", flow.Name)
		}

		logger.Info("✓ Flow imported and verified",
			zap.String("flow", flow.Name),
			zap.String("slug", flow.Slug),
			zap.String("uuid", verifiedFlow.PK))
		importedSlugs = append(importedSlugs, flow.Slug)
	}

	if cfg.DryRun {
		logger.Info("[dry-run] Skipping brand configuration and provider updates")
		return nil
	}

	// Configure brand flows.
	domain := strings.TrimSpace(cfg.Domain)
	if domain == "" {
		autoDomain, autoErr := getDomainForApp(rc, appSlug)
		if autoErr != nil {
			logger.Warn("Could not auto-detect domain for brand configuration",
				zap.Error(autoErr))
		} else {
			domain = autoDomain
			logger.Info("Auto-detected domain for brand configuration",
				zap.String("domain", domain))
		}
	}

	if domain != "" {
		brand, err := findOrCreateAppBrand(rc, client, domain, appSlug)
		if err != nil {
			logger.Warn("Failed to ensure Authentik brand for default flows",
				zap.String("domain", domain),
				zap.Error(err))
		} else {
			// CRITICAL: Brand API requires flow UUIDs, not slugs
			// Lookup each flow to get its PK (UUID) with retry logic for eventual consistency
			// RATIONALE: Freshly imported flows may not be immediately queryable due to Authentik indexing
			// RETRY STRATEGY: 5 attempts with exponential backoff (1s, 2s, 4s, 8s, 16s = max 31s wait)
			authFlow := getFlowWithRetry(rc, client, logger, fmt.Sprintf("%s-authentication", appSlug), 5, 1*time.Second)
			enrollmentFlow := getFlowWithRetry(rc, client, logger, fmt.Sprintf("%s-enrollment", appSlug), 5, 1*time.Second)
			invalidationGlobalFlow := getFlowWithRetry(rc, client, logger, fmt.Sprintf("%s-invalidation-global", appSlug), 5, 1*time.Second)
			recoveryFlow := getFlowWithRetry(rc, client, logger, fmt.Sprintf("%s-recovery", appSlug), 5, 1*time.Second)
			unenrollmentFlow := getFlowWithRetry(rc, client, logger, fmt.Sprintf("%s-unenrollment", appSlug), 5, 1*time.Second)

			// Only update brand if we successfully looked up all flow UUIDs
			if authFlow != nil && enrollmentFlow != nil && invalidationGlobalFlow != nil && recoveryFlow != nil && unenrollmentFlow != nil {
				updates := map[string]interface{}{
					"flow_authentication":                authFlow.PK,                                      // UUID required
					"flow_enrollment":                    enrollmentFlow.PK,                                // UUID required
					"flow_invalidation":                  invalidationGlobalFlow.PK,                        // UUID required
					"default_provider_invalidation_flow": fmt.Sprintf("%s-invalidation-provider", appSlug), // Slug accepted
					"flow_recovery":                      recoveryFlow.PK,                                  // UUID required
					"flow_unenrollment":                  unenrollmentFlow.PK,                              // UUID required
				}

				logger.Debug("Updating brand with flow UUIDs",
					zap.String("brand_pk", brand.PK),
					zap.String("auth_flow_uuid", authFlow.PK),
					zap.String("enrollment_flow_uuid", enrollmentFlow.PK),
					zap.String("invalidation_flow_uuid", invalidationGlobalFlow.PK),
					zap.String("recovery_flow_uuid", recoveryFlow.PK),
					zap.String("unenrollment_flow_uuid", unenrollmentFlow.PK))

				if _, err := client.UpdateBrand(rc.Ctx, brand.PK, updates); err != nil {
					logger.Warn("Failed to update brand flows",
						zap.String("brand_pk", brand.PK),
						zap.Error(err))
				} else {
					logger.Info("✓ Brand configured with new default flows",
						zap.String("brand_pk", brand.PK),
						zap.String("domain", brand.Domain))
				}
			} else {
				logger.Warn("Skipping brand update - failed to lookup one or more flow UUIDs",
					zap.Bool("auth_flow_found", authFlow != nil),
					zap.Bool("enrollment_flow_found", enrollmentFlow != nil),
					zap.Bool("invalidation_flow_found", invalidationGlobalFlow != nil),
					zap.Bool("recovery_flow_found", recoveryFlow != nil),
					zap.Bool("unenrollment_flow_found", unenrollmentFlow != nil))
			}
		}
	} else {
		logger.Warn("Brand configuration skipped (no domain provided or discovered)")
	}

	// Update proxy provider invalidation flow if BionicGPT provider exists.
	invalidationFlow, err := client.GetFlow(rc.Ctx, fmt.Sprintf("%s-invalidation-provider", appSlug))
	if err == nil && invalidationFlow != nil {
		providers, listErr := client.ListProxyProviders(rc.Ctx)
		if listErr != nil {
			logger.Warn("Failed to list Authentik proxy providers",
				zap.Error(listErr))
		} else {
			for _, provider := range providers {
				if provider.Name != BionicGPTProxyProviderName {
					continue
				}

				update := &authentik.ProxyProviderConfig{
					Name:              provider.Name,
					Mode:              provider.Mode,
					ExternalHost:      provider.ExternalHost,
					InternalHost:      provider.InternalHost,
					AuthorizationFlow: provider.AuthorizationFlow,
					InvalidationFlow:  invalidationFlow.PK,
				}

				if err := client.UpdateProxyProvider(rc.Ctx, provider.PK, update); err != nil {
					logger.Warn("Failed to update proxy provider invalidation flow",
						zap.Int("provider_pk", provider.PK),
						zap.Error(err))
				} else {
					logger.Info("✓ Proxy provider updated with new invalidation flow",
						zap.Int("provider_pk", provider.PK),
						zap.String("flow_slug", invalidationFlow.Slug))
				}
			}
		}
	}

	logger.Info("Default Authentik flows deployment complete",
		zap.Strings("flows", importedSlugs))

	return nil
}

type flowTemplateData struct {
	AppSlug   string
	AppTitle  string
	GroupUUID string
	GroupName string
}

type flowDefinition struct {
	Name           string
	Slug           string
	Template       string
	RequiresGroup  bool
	UpdateExisting bool
}

func renderFlowTemplate(tmpl string, data flowTemplateData) ([]byte, error) {
	parsed, err := template.New("flow").Parse(tmpl)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := parsed.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func formatAppTitle(slug string) string {
	switch strings.ToLower(slug) {
	case "bionicgpt":
		return "BionicGPT"
	default:
		title := cases.Title(language.English, cases.NoLower).String(strings.ReplaceAll(slug, "-", " "))
		return strings.ReplaceAll(title, " ", "")
	}
}

const invalidationGlobalTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - Global Invalidation (with SLO)
entries:
  - identifiers:
      slug: {{ .AppSlug }}-invalidation-global
    model: authentik_flows.flow
    id: flow
    attrs:
      name: {{ .AppTitle }} Global Logout
      title: Logging you out...
      designation: invalidation
      authentication: require_authenticated

  - identifiers:
      name: {{ .AppSlug }}-logout
    id: logout-stage
    model: authentik_stages_user_logout.userlogoutstage

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf logout-stage
      order: 10
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry
`

const invalidationProviderTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - Provider Invalidation (with SLO)
entries:
  - identifiers:
      slug: {{ .AppSlug }}-invalidation-provider
    model: authentik_flows.flow
    id: flow
    attrs:
      name: {{ .AppTitle }} Provider Logout
      title: Application logout options
      designation: invalidation
      authentication: require_authenticated

  - identifiers:
      name: {{ .AppSlug }}-logout-provider
    id: logout-stage-provider
    model: authentik_stages_user_logout.userlogoutstage

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf logout-stage-provider
      order: 10
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry
`

const recoveryFlowTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - Recovery with Rate Limiting
entries:
  - identifiers:
      slug: {{ .AppSlug }}-recovery
    id: flow
    model: authentik_flows.flow
    attrs:
      name: {{ .AppTitle }} Password Recovery
      title: Reset your password
      designation: recovery
      authentication: require_unauthenticated

  - identifiers:
      name: {{ .AppSlug }}-recovery-field-password
    id: prompt-field-password
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: password
      label: Password
      type: password
      required: true
      placeholder: Password
      order: 0
      placeholder_expression: false

  - identifiers:
      name: {{ .AppSlug }}-recovery-field-password-repeat
    id: prompt-field-password-repeat
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: password_repeat
      label: Password (repeat)
      type: password
      required: true
      placeholder: Password (repeat)
      order: 1
      placeholder_expression: false

  - identifiers:
      name: {{ .AppSlug }}-recovery-skip-if-restored
    id: recovery-skip-policy
    model: authentik_policies_expression.expressionpolicy
    attrs:
      expression: |
        return bool(request.context.get('is_restored', True))

  - identifiers:
      name: {{ .AppSlug }}-recovery-email
    id: recovery-email
    model: authentik_stages_email.emailstage
    attrs:
      use_global_settings: true
      template: email/password_reset.html
      activate_user_on_success: true
      token_expiry: hours=1
      rate_limit_count: 3
      rate_limit_duration: hours=24
      recovery_max_attempts: 3
      recovery_cache_timeout: hours=24

  - identifiers:
      name: {{ .AppSlug }}-recovery-user-write
    id: recovery-user-write
    model: authentik_stages_user_write.userwritestage
    attrs:
      user_creation_mode: never_create

  - identifiers:
      name: {{ .AppSlug }}-recovery-identification
    id: recovery-identification
    model: authentik_stages_identification.identificationstage
    attrs:
      user_fields:
        - email
        - username

  - identifiers:
      name: {{ .AppSlug }}-recovery-user-login
    id: recovery-login
    model: authentik_stages_user_login.userloginstage
    attrs:
      session_duration: seconds=0
      remember_me_offset: weeks=4

  - identifiers:
      name: {{ .AppSlug }}-recovery-prompt-password
    id: recovery-prompt
    model: authentik_stages_prompt.promptstage
    attrs:
      fields:
        - !KeyOf prompt-field-password
        - !KeyOf prompt-field-password-repeat
      validation_policies: []

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf recovery-identification
      order: 10
    model: authentik_flows.flowstagebinding
    id: flow-binding-identification
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: true
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf recovery-email
      order: 20
    model: authentik_flows.flowstagebinding
    id: flow-binding-email
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: true
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf recovery-prompt
      order: 30
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf recovery-user-write
      order: 40
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf recovery-login
      order: 100
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      policy: !KeyOf recovery-skip-policy
      target: !KeyOf flow-binding-identification
      order: 0
    model: authentik_policies.policybinding
    attrs:
      negate: false
      enabled: true
      timeout: 30
`

const enrollmentFlowTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - Self Registration with 2FA
entries:
  - identifiers:
      slug: {{ .AppSlug }}-enrollment
    model: authentik_flows.flow
    id: flow
    attrs:
      name: {{ .AppTitle }} Self Registration (2FA Required)
      title: Welcome to {{ .AppTitle }}!
      designation: enrollment
      authentication: require_unauthenticated
      compatibility_mode: true

  - id: prompt-field-username
    model: authentik_stages_prompt.prompt
    identifiers:
      name: {{ .AppSlug }}-enrollment-field-username
    attrs:
      field_key: username
      label: Username
      type: username
      required: true
      placeholder: Username
      placeholder_expression: false
      order: 0

  - identifiers:
      name: {{ .AppSlug }}-enrollment-field-password
    id: prompt-field-password
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: password
      label: Password
      type: password
      required: true
      placeholder: Password
      placeholder_expression: false
      order: 0

  - identifiers:
      name: {{ .AppSlug }}-enrollment-field-password-repeat
    id: prompt-field-password-repeat
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: password_repeat
      label: Password (repeat)
      type: password
      required: true
      placeholder: Password (repeat)
      placeholder_expression: false
      order: 1

  - identifiers:
      name: {{ .AppSlug }}-enrollment-field-name
    id: prompt-field-name
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: name
      label: Name
      type: text
      required: true
      placeholder: Name
      placeholder_expression: false
      order: 0

  - identifiers:
      name: {{ .AppSlug }}-enrollment-field-email
    id: prompt-field-email
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: email
      label: Email
      type: email
      required: true
      placeholder: Email
      placeholder_expression: false
      order: 1

  - identifiers:
      name: {{ .AppSlug }}-enrollment-prompt-first
    id: {{ .AppSlug }}-enrollment-prompt-first
    model: authentik_stages_prompt.promptstage
    attrs:
      fields:
        - !KeyOf prompt-field-username
        - !KeyOf prompt-field-password
        - !KeyOf prompt-field-password-repeat

  - identifiers:
      name: {{ .AppSlug }}-enrollment-prompt-second
    id: {{ .AppSlug }}-enrollment-prompt-second
    model: authentik_stages_prompt.promptstage
    attrs:
      fields:
        - !KeyOf prompt-field-name
        - !KeyOf prompt-field-email

  - identifiers:
      name: {{ .AppSlug }}-enrollment-user-write
    id: {{ .AppSlug }}-enrollment-user-write
    model: authentik_stages_user_write.userwritestage
    attrs:
      user_creation_mode: always_create
      create_users_as_inactive: false
      create_users_group: {{ .GroupUUID }}

  - identifiers:
      name: {{ .AppSlug }}-enrollment-mfa-setup
    id: {{ .AppSlug }}-enrollment-mfa-setup
    model: authentik_stages_authenticator_validate.authenticatorvalidatestage
    attrs:
      device_classes:
        - totp
        - webauthn
        - static
      configuration_stages:
        - totp
        - webauthn
        - static
      not_configured_action: configure
      last_validation_threshold: seconds=0

  - identifiers:
      name: {{ .AppSlug }}-enrollment-user-login
    id: {{ .AppSlug }}-enrollment-user-login
    model: authentik_stages_user_login.userloginstage
    attrs:
      session_duration: seconds=0
      remember_me_offset: weeks=4

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-enrollment-prompt-first
      order: 10
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-enrollment-prompt-second
      order: 11
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-enrollment-user-write
      order: 20
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-enrollment-mfa-setup
      order: 30
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-enrollment-user-login
      order: 100
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry
`

const authenticationFlowTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - Authentication with Mandatory 2FA
entries:
  - identifiers:
      slug: {{ .AppSlug }}-authentication
    model: authentik_flows.flow
    id: flow
    attrs:
      name: {{ .AppTitle }} Authentication (2FA Required)
      title: Welcome back to {{ .AppTitle }}!
      designation: authentication
      authentication: require_unauthenticated
      compatibility_mode: true

  - identifiers:
      name: {{ .AppSlug }}-auth-skip-mfa-for-app-password
    id: skip-mfa-app-password
    model: authentik_policies_expression.expressionpolicy
    attrs:
      expression: |
        return context.get("auth_method") != "app_password"

  - identifiers:
      name: {{ .AppSlug }}-auth-identification
    id: {{ .AppSlug }}-auth-identification
    model: authentik_stages_identification.identificationstage
    attrs:
      user_fields:
        - email
        - username
      template: stages/identification/login.html
      enrollment_flow: {{ .AppSlug }}-enrollment
      recovery_flow: {{ .AppSlug }}-recovery
      show_source_labels: true

  - identifiers:
      name: {{ .AppSlug }}-auth-password
    id: {{ .AppSlug }}-auth-password
    model: authentik_stages_password.passwordstage
    attrs:
      backends:
        - authentik.core.auth.InbuiltBackend
        - authentik.core.auth.TokenBackend
      failed_attempts_before_cancel: 5

  - identifiers:
      name: {{ .AppSlug }}-auth-mfa-validation
    id: {{ .AppSlug }}-auth-mfa-validation
    model: authentik_stages_authenticator_validate.authenticatorvalidatestage
    attrs:
      device_classes:
        - totp
        - webauthn
        - static
      not_configured_action: deny
      webauthn_user_verification: preferred

  - identifiers:
      name: {{ .AppSlug }}-auth-login
    id: {{ .AppSlug }}-auth-login
    model: authentik_stages_user_login.userloginstage
    attrs:
      session_duration: seconds=0
      remember_me_offset: weeks=4

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-auth-identification
      order: 10
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-auth-password
      order: 20
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-auth-mfa-validation
      order: 30
    model: authentik_flows.flowstagebinding
    id: flow-binding-mfa
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: true
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf {{ .AppSlug }}-auth-login
      order: 100
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      policy: !KeyOf skip-mfa-app-password
      target: !KeyOf flow-binding-mfa
      order: 0
    model: authentik_policies.policybinding
    attrs:
      negate: false
      enabled: true
      timeout: 30
`

const unenrollmentFlowTemplate = `
version: 1
metadata:
  labels:
    blueprints.goauthentik.io/instantiate: "false"
  name: {{ .AppTitle }} - User Deletion with Confirmation
entries:
  - identifiers:
      slug: {{ .AppSlug }}-unenrollment
    model: authentik_flows.flow
    id: flow
    attrs:
      name: {{ .AppTitle }} Account Deletion
      title: Delete your account
      designation: unenrollment
      authentication: require_authenticated

  - identifiers:
      name: {{ .AppSlug }}-unenroll-confirm-field
    id: confirm-field
    model: authentik_stages_prompt.prompt
    attrs:
      field_key: confirm_deletion
      label: 'Type "DELETE" to confirm account deletion'
      type: text
      required: true
      placeholder: DELETE
      order: 0

  - identifiers:
      name: {{ .AppSlug }}-unenroll-confirm-prompt
    id: confirm-prompt
    model: authentik_stages_prompt.promptstage
    attrs:
      fields:
        - !KeyOf confirm-field

  - identifiers:
      name: {{ .AppSlug }}-unenroll-confirm-policy
    id: confirm-policy
    model: authentik_policies_expression.expressionpolicy
    attrs:
      expression: |
        return request.context.get('prompt_data', {}).get('confirm_deletion') == 'DELETE'

  - identifiers:
      name: {{ .AppSlug }}-unenroll-delete
    id: delete-stage
    model: authentik_stages_user_delete.userdeletestage

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf confirm-prompt
      order: 5
    model: authentik_flows.flowstagebinding
    id: flow-binding-confirm
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      target: !KeyOf flow
      stage: !KeyOf delete-stage
      order: 10
    model: authentik_flows.flowstagebinding
    attrs:
      evaluate_on_plan: true
      re_evaluate_policies: false
      policy_engine_mode: any
      invalid_response_action: retry

  - identifiers:
      policy: !KeyOf confirm-policy
      target: !KeyOf flow-binding-confirm
      order: 0
    model: authentik_policies.policybinding
    attrs:
      negate: false
      enabled: true
      timeout: 30
`

// getFlowWithRetry attempts to retrieve a flow with retry logic and exponential backoff
// RATIONALE: Freshly imported flows may not be immediately queryable in Authentik due to indexing lag
// This is a timing issue - the flow exists but the API index hasn't updated yet
// RETRY STRATEGY: Exponential backoff (1s, 2s, 4s, 8s, 16s) for up to 5 attempts (max 31s wait)
func getFlowWithRetry(rc *eos_io.RuntimeContext, client *authentik.APIClient, logger otelzap.LoggerWithCtx, slug string, maxRetries int, initialDelay time.Duration) *authentik.FlowResponse {
	currentDelay := initialDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		flow, err := client.GetFlow(rc.Ctx, slug)
		if err != nil {
			logger.Warn("Failed to lookup flow UUID (API error)",
				zap.String("slug", slug),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries),
				zap.Error(err))
		} else if flow != nil {
			// Success - flow found
			logger.Debug("Flow UUID resolved",
				zap.String("slug", slug),
				zap.String("uuid", flow.PK),
				zap.String("flow_name", flow.Name),
				zap.Int("attempt", attempt))
			return flow
		}

		// Flow not found yet (flow == nil, err == nil means "not found" per GetFlow contract)
		if attempt < maxRetries {
			logger.Debug("Flow not indexed yet, retrying with exponential backoff",
				zap.String("slug", slug),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries),
				zap.Duration("retry_delay", currentDelay),
				zap.String("reason", "Authentik API eventual consistency"))
			time.Sleep(currentDelay)
			currentDelay *= 2 // Exponential backoff: 1s → 2s → 4s → 8s → 16s
		}
	}

	// All retries exhausted - flow may not exist or API is very slow
	logger.Warn("Flow not found after all retries (may not exist or API indexing is slow)",
		zap.String("slug", slug),
		zap.Int("max_retries", maxRetries),
		zap.Duration("total_wait_time", initialDelay*(1<<uint(maxRetries)-1)), // Sum of geometric series
		zap.String("remediation", "Check if flow was actually imported successfully"))
	return nil
}
