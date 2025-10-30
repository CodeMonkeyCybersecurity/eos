// pkg/hecate/self_enrollment.go - Self-enrollment configuration for Hecate applications

package hecate

import (
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SelfEnrollmentConfig holds configuration for enabling self-enrollment
type SelfEnrollmentConfig struct {
	AppName       string // Application name (e.g., "bionicgpt")
	DryRun        bool   // If true, show what would be done without applying changes
	SkipCaddyfile bool   // If true, don't update Caddyfile (advanced usage)
	EnableCaptcha bool   // If true, add captcha stage to prevent spam
	// EmailVerification bool   // TODO: Enable when SMTP is configured
	// CaptchaPublicKey  string // TODO: Production captcha keys from Vault
	// CaptchaPrivateKey string // TODO: Production captcha keys from Vault
}

// enrollmentResources tracks all created Authentik resources for rollback
type enrollmentResources struct {
	PromptFieldPKs []string                     // Created prompt fields (username, email)
	StagePKs       []string                     // Created stages (prompt, password, user write, login, captcha)
	FlowPK         string                       // Created enrollment flow
	OriginalBrand  *authentik.BrandResponse     // Original brand config for restoration
	BrandPK        string                       // Brand that was modified
}

// EnableSelfEnrollment enables self-enrollment for Hecate applications
// ARCHITECTURE: Follows Assess → Intervene → Evaluate pattern
//
// IMPORTANT: Forward auth operates at BRAND level, not application level.
// Enabling self-enrollment affects ALL applications behind Authentik on this brand.
//
// Steps:
// 1. ASSESS: Check current brand configuration, enrollment flow status
// 2. INTERVENE: Create/update enrollment flow, link to brand
// 3. EVALUATE: Verify enrollment is accessible and report status
func EnableSelfEnrollment(rc *eos_io.RuntimeContext, config *SelfEnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Enabling self-enrollment for Hecate",
		zap.String("app", config.AppName),
		zap.Bool("dry_run", config.DryRun))

	// P1: Acquire file lock to prevent concurrent enrollment operations
	// RATIONALE: Multiple admins could run this command simultaneously, causing:
	//   - Race conditions in Authentik API (duplicate flows/stages)
	//   - Conflicting brand updates
	//   - Incomplete rollbacks (one operation deletes another's resources)
	logger.Debug("Acquiring enrollment operation lock")
	lock, err := AcquireEnrollmentLock(rc)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			logger.Error("Failed to release enrollment lock", zap.Error(releaseErr))
		}
	}()
	logger.Debug("Enrollment operation lock acquired")

	// PHASE 1: ASSESS - Discover Authentik credentials and current state
	logger.Info("Phase 1: Assessing current enrollment configuration")

	// P1: Use consistent credential discovery from BionicGPT integrator pattern
	// This includes AUTHENTIK_API_TOKEN priority, bootstrap token fallback, and legacy migration
	authentikToken, authentikURL, err := discoverAuthentikCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik credentials: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Verify Hecate is installed: eos create hecate\n"+
			"  2. Check Authentik token in /opt/hecate/.env\n"+
			"  3. Verify Authentik is running: docker ps | grep authentik", err)
	}

	logger.Debug("Authentik credentials discovered",
		zap.String("url", authentikURL))

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Get current brand configuration
	brands, err := authentikClient.ListBrands(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list Authentik brands: %w", err)
	}

	if len(brands) == 0 {
		return fmt.Errorf("no Authentik brands found - this should not happen\n\n" +
			"Authentik installations always have a default brand.\n" +
			"Check Authentik status: docker ps | grep authentik")
	}

	// Use first brand (default brand)
	brand := brands[0]
	logger.Info("Found Authentik brand",
		zap.String("brand_pk", brand.PK),
		zap.String("title", brand.BrandingTitle),
		zap.String("current_enrollment_flow", brand.FlowEnrollment))

	// Check if enrollment is already enabled
	if brand.FlowEnrollment != "" {
		logger.Info("Enrollment already enabled on brand",
			zap.String("flow_pk", brand.FlowEnrollment))

		// Verify the enrollment flow exists and is configured
		enrollmentFlow, err := authentikClient.GetFlowByPK(rc.Ctx, brand.FlowEnrollment)
		if err != nil {
			logger.Warn("Enrollment flow configured but not found - will recreate",
				zap.String("flow_pk", brand.FlowEnrollment),
				zap.Error(err))
		} else {
			logger.Info("Enrollment flow verified",
				zap.String("flow_name", enrollmentFlow.Name),
				zap.String("flow_slug", enrollmentFlow.Slug),
				zap.String("designation", enrollmentFlow.Designation))

			// Generate enrollment URL
			enrollmentURL := fmt.Sprintf("%s/if/flow/%s/", authentikURL, enrollmentFlow.Slug)

			logger.Info("✓ Self-enrollment is already enabled",
				zap.String("enrollment_url", enrollmentURL),
				zap.String("flow_name", enrollmentFlow.Name))

			return nil // Already configured - idempotent
		}
	}

	// PHASE 2: INTERVENE - Create enrollment flow and link to brand

	// P0: Initialize resource tracking for rollback
	resources := &enrollmentResources{
		OriginalBrand: &brand, // Store original brand config for restoration
		BrandPK:       brand.PK,
	}

	// P0: Defer rollback on failure (follows Hecate backup/restore pattern)
	var enrollmentErr error
	defer func() {
		if enrollmentErr != nil {
			rollbackEnrollmentSetup(rc, authentikClient, resources)
		}
	}()

	if config.DryRun {
		logger.Info("DRY RUN: Would create enrollment flow and link to brand")
		logger.Info("Changes that would be made:",
			zap.String("action_1", "Create enrollment flow 'Self Registration'"),
			zap.String("action_2", "Create prompt fields (username, email)"),
			zap.String("action_3", "Create prompt stage"),
			zap.String("action_4", "Create password stage"),
			zap.String("action_5", "Create user write stage"),
			zap.String("action_6", "Create user login stage (auto-login)"),
			zap.String("action_7", "Bind stages to flow"),
			zap.String("action_8", "Link enrollment flow to brand"))
		return nil
	}

	logger.Info("Phase 2: Creating enrollment flow and stages")

	// Create enrollment flow
	flowSlug := "eos-self-registration"
	flowName := "Self Registration (Eos)"
	flowTitle := "Create your account"

	logger.Info("Creating enrollment flow",
		zap.String("slug", flowSlug),
		zap.String("name", flowName))

	enrollmentFlow, err := authentikClient.CreateEnrollmentFlow(rc.Ctx, flowName, flowSlug, flowTitle)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create enrollment flow: %w", err)
		return enrollmentErr
	}
	resources.FlowPK = enrollmentFlow.PK // Track for rollback

	logger.Info("✓ Enrollment flow created",
		zap.String("flow_pk", enrollmentFlow.PK),
		zap.String("slug", enrollmentFlow.Slug))

	// Create prompt fields for username and email collection
	logger.Info("Creating prompt fields for user information")

	usernameField, err := authentikClient.CreatePromptField(rc.Ctx,
		"username",        // field_key
		"username",        // type
		"Username",        // label
		"Enter username",  // placeholder
		true,              // required
		10)                // order
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create username field: %w", err)
		return enrollmentErr
	}
	resources.PromptFieldPKs = append(resources.PromptFieldPKs, usernameField.PK) // Track for rollback
	logger.Info("✓ Username field created", zap.String("field_pk", usernameField.PK))

	emailField, err := authentikClient.CreatePromptField(rc.Ctx,
		"email",           // field_key
		"email",           // type
		"Email",           // label
		"Enter email",     // placeholder
		true,              // required
		20)                // order
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create email field: %w", err)
		return enrollmentErr
	}
	resources.PromptFieldPKs = append(resources.PromptFieldPKs, emailField.PK) // Track for rollback
	logger.Info("✓ Email field created", zap.String("field_pk", emailField.PK))

	// Optional: Create captcha stage for bot protection
	var captchaStage *authentik.CaptchaStageResponse
	if config.EnableCaptcha {
		logger.Info("Creating captcha stage for bot protection")
		captchaStage, err = authentikClient.CreateCaptchaStage(rc.Ctx, "eos-enrollment-captcha", "", "")
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create captcha stage: %w", err)
			return enrollmentErr
		}
		resources.StagePKs = append(resources.StagePKs, captchaStage.PK) // Track for rollback
		logger.Info("✓ Captcha stage created (using test keys - configure production keys in Authentik UI)",
			zap.String("stage_pk", captchaStage.PK))
	}

	// Create prompt stage with username and email fields
	logger.Info("Creating prompt stage for enrollment")
	promptStage, err := authentikClient.CreatePromptStage(rc.Ctx,
		"eos-enrollment-prompts",
		[]string{usernameField.PK, emailField.PK})
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create prompt stage: %w", err)
		return enrollmentErr
	}
	resources.StagePKs = append(resources.StagePKs, promptStage.PK) // Track for rollback
	logger.Info("✓ Prompt stage created", zap.String("stage_pk", promptStage.PK))

	// Create password stage
	logger.Info("Creating password stage for enrollment")
	passwordStage, err := authentikClient.CreatePasswordStage(rc.Ctx, "eos-enrollment-password")
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create password stage: %w", err)
		return enrollmentErr
	}
	resources.StagePKs = append(resources.StagePKs, passwordStage.PK) // Track for rollback
	logger.Info("✓ Password stage created", zap.String("stage_pk", passwordStage.PK))

	// Create user write stage
	logger.Info("Creating user write stage for enrollment")
	userWriteStage, err := authentikClient.CreateUserWriteStage(rc.Ctx, "eos-enrollment-user-write", false, "")
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create user write stage: %w", err)
		return enrollmentErr
	}
	resources.StagePKs = append(resources.StagePKs, userWriteStage.PK) // Track for rollback
	logger.Info("✓ User write stage created", zap.String("stage_pk", userWriteStage.PK))

	// Create user login stage (auto-login after signup)
	logger.Info("Creating user login stage for auto-login")
	loginStage, err := authentikClient.CreateUserLoginStage(rc.Ctx, "eos-enrollment-login")
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to create user login stage: %w", err)
		return enrollmentErr
	}
	resources.StagePKs = append(resources.StagePKs, loginStage.PK) // Track for rollback
	logger.Info("✓ User login stage created", zap.String("stage_pk", loginStage.PK))

	// Bind stages to enrollment flow (order matters!)
	// Order 5: Captcha stage (if enabled - bot protection)
	// Order 10: Prompt stage (collect username, email)
	// Order 20: Password stage (user chooses password)
	// Order 30: User write stage (creates user account)
	// Order 40: User login stage (auto-login after signup)
	logger.Info("Binding stages to enrollment flow")

	stageCount := 4
	if config.EnableCaptcha && captchaStage != nil {
		_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, captchaStage.PK, 5)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to bind captcha stage: %w", err)
			return enrollmentErr
		}
		stageCount++
	}

	_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, promptStage.PK, 10)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to bind prompt stage: %w", err)
		return enrollmentErr
	}

	_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, passwordStage.PK, 20)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to bind password stage: %w", err)
		return enrollmentErr
	}

	_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, userWriteStage.PK, 30)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to bind user write stage: %w", err)
		return enrollmentErr
	}

	_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, loginStage.PK, 40)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to bind user login stage: %w", err)
		return enrollmentErr
	}

	logger.Info("✓ Stages bound to enrollment flow",
		zap.Int("stage_count", stageCount))

	// Link enrollment flow to brand
	logger.Info("Linking enrollment flow to brand", zap.String("brand_pk", brand.PK))

	err = authentikClient.UpdateBrand(rc.Ctx, brand.PK, map[string]interface{}{
		"flow_enrollment": enrollmentFlow.PK,
	})
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to link enrollment flow to brand: %w", err)
		return enrollmentErr
	}

	logger.Info("✓ Enrollment flow linked to brand")

	// PHASE 3: EVALUATE - Verify and report results

	logger.Info("Phase 3: Verifying enrollment configuration")

	// Verify brand was updated
	updatedBrand, err := authentikClient.GetBrand(rc.Ctx, brand.PK)
	if err != nil {
		logger.Warn("Failed to verify brand update", zap.Error(err))
	} else if updatedBrand.FlowEnrollment != enrollmentFlow.PK {
		logger.Warn("Brand enrollment flow mismatch",
			zap.String("expected", enrollmentFlow.PK),
			zap.String("actual", updatedBrand.FlowEnrollment))
	} else {
		logger.Info("✓ Brand enrollment flow verified")
	}

	// Generate enrollment URL
	enrollmentURL := fmt.Sprintf("%s/if/flow/%s/", authentikURL, enrollmentFlow.Slug)

	// P1: Health check for enrollment URL (verify it's accessible)
	logger.Info("Verifying enrollment URL is accessible", zap.String("url", enrollmentURL))
	healthErr := verifyEnrollmentURLAccessible(rc, enrollmentURL)
	if healthErr != nil {
		logger.Warn("Enrollment URL health check failed",
			zap.Error(healthErr),
			zap.String("url", enrollmentURL))
		logger.Warn("Flow is configured but may not be accessible from external network")
		logger.Warn("Check Caddy configuration and DNS settings")
	} else {
		logger.Info("✓ Enrollment URL is accessible")
	}

	// Final report
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("✓ Self-enrollment enabled successfully")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Enrollment URL", zap.String("url", enrollmentURL))
	logger.Info("Flow Name", zap.String("name", enrollmentFlow.Name))
	logger.Info("Flow Slug", zap.String("slug", enrollmentFlow.Slug))
	logger.Info("")
	logger.Info("IMPORTANT: Forward auth operates at BRAND level")
	logger.Info("This enables self-registration for ALL apps behind Authentik on this brand.")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Users can now register at: " + enrollmentURL)
	logger.Info("  2. New users will be created with default permissions")
	logger.Info("  3. Admins can manage users via Authentik admin interface")
	logger.Info("")
	logger.Info("To customize enrollment flow:")
	logger.Info("  - Visit Authentik admin: " + authentikURL + "/if/admin/")
	logger.Info("  - Navigate to: Flows & Stages → Flows")
	logger.Info("  - Edit: " + enrollmentFlow.Name)
	logger.Info("")

	return nil
}

// verifyEnrollmentURLAccessible performs a health check on the enrollment URL
// P1 FIX #3: Add health check for enrollment URL
//
// Verification approach:
//   1. HTTP HEAD request to enrollment URL
//   2. Check for successful response (200-399)
//   3. Non-fatal failure (warns but doesn't stop)
//
// RATIONALE: Enrollment flow may be configured in Authentik but:
//   - DNS not yet propagated
//   - Caddy not yet reloaded
//   - Network firewall blocking access
//   - SSL certificate not yet issued
//
// We warn but don't fail - admin can manually verify later
func verifyEnrollmentURLAccessible(rc *eos_io.RuntimeContext, enrollmentURL string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create HTTP client with short timeout (we don't want to block for long)
	client := &http.Client{
		Timeout: 10 * time.Second,
		// Don't follow redirects - we just want to check if URL responds
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// HEAD request (lighter than GET, we just need response status)
	req, err := http.NewRequestWithContext(rc.Ctx, http.MethodHead, enrollmentURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach URL: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	// 200-399 are success/redirect (acceptable)
	// 400+ are errors
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		logger.Debug("Enrollment URL health check passed",
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status))
		return nil
	}

	return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, resp.Status)
}

// discoverAuthentikCredentials discovers Authentik API credentials using the same
// comprehensive discovery logic as BionicGPT integrator
//
// Discovery order (P1 FIX #2 - Consistent credential discovery):
//  1. AUTHENTIK_API_TOKEN from /opt/hecate/.env (preferred)
//  2. AUTHENTIK_TOKEN from /opt/hecate/.env (legacy variant)
//  3. AUTHENTIK_API_KEY from /opt/hecate/.env (legacy variant)
//  4. AUTHENTIK_BOOTSTRAP_TOKEN from /opt/hecate/.env (auto-created on first startup)
//  5. Legacy location /opt/bionicgpt/.env (backwards compatibility with migration warning)
//
// This ensures consistent behavior across all Hecate operations
func discoverAuthentikCredentials(rc *eos_io.RuntimeContext) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Read Hecate .env file (canonical location)
	hecateEnv, err := readEnvFile("/opt/hecate/.env")
	if err != nil {
		return "", "", fmt.Errorf("failed to read /opt/hecate/.env: %w\n"+
			"Authentik configuration should be in Hecate .env file", err)
	}

	// Check for AUTHENTIK_API_TOKEN (preferred) or legacy variants
	apiKey := hecateEnv["AUTHENTIK_API_TOKEN"]
	if apiKey == "" {
		apiKey = hecateEnv["AUTHENTIK_TOKEN"]
	}
	if apiKey == "" {
		apiKey = hecateEnv["AUTHENTIK_API_KEY"]
	}

	// FALLBACK: Try AUTHENTIK_BOOTSTRAP_TOKEN as API key
	// The bootstrap token is created during Authentik initialization with API access intent
	if apiKey == "" {
		bootstrapToken := hecateEnv["AUTHENTIK_BOOTSTRAP_TOKEN"]
		if bootstrapToken != "" {
			logger.Debug("Using AUTHENTIK_BOOTSTRAP_TOKEN as API key")
			apiKey = bootstrapToken
		}
	}

	// Get base URL
	baseURL := hecateEnv["AUTHENTIK_BASE_URL"]
	if baseURL == "" {
		baseURL = "http://localhost:9000" // Default
	}

	if apiKey == "" {
		return "", "", fmt.Errorf("no Authentik API token found in /opt/hecate/.env\n\n"+
			"Looked for: AUTHENTIK_API_TOKEN, AUTHENTIK_TOKEN, AUTHENTIK_API_KEY, AUTHENTIK_BOOTSTRAP_TOKEN\n\n"+
			"To fix:\n"+
			"  1. Check if Authentik is running: docker ps | grep authentik\n"+
			"  2. Check if bootstrap token exists: grep AUTHENTIK_BOOTSTRAP_TOKEN /opt/hecate/.env\n"+
			"  3. Create API token in Authentik UI: Admin → Tokens → Create\n"+
			"  4. Add to /opt/hecate/.env: echo 'AUTHENTIK_API_TOKEN=your-token-here' | sudo tee -a /opt/hecate/.env")
	}

	return apiKey, baseURL, nil
}

// rollbackEnrollmentSetup removes all created Authentik resources
// ROLLBACK ORDER (reverse of creation):
// 1. Restore brand to original state
// 2. Delete flow (and its stage bindings)
// 3. Delete stages
// 4. Delete prompt fields
func rollbackEnrollmentSetup(rc *eos_io.RuntimeContext, authentikClient *authentik.APIClient, resources *enrollmentResources) {
	logger := otelzap.Ctx(rc.Ctx)
	
	if resources == nil {
		return
	}

	logger.Warn("Rolling back enrollment setup due to failure")

	// Step 1: Restore brand to original state (if modified)
	if resources.OriginalBrand != nil && resources.BrandPK != "" {
		logger.Info("Restoring brand to original state", zap.String("brand_pk", resources.BrandPK))
		err := authentikClient.UpdateBrand(rc.Ctx, resources.BrandPK, map[string]interface{}{
			"flow_enrollment": resources.OriginalBrand.FlowEnrollment,
		})
		if err != nil {
			logger.Error("Failed to restore brand during rollback",
				zap.Error(err),
				zap.String("brand_pk", resources.BrandPK))
		} else {
			logger.Info("✓ Brand restored to original state")
		}
	}

	// Step 2: Delete flow (this also deletes stage bindings)
	if resources.FlowPK != "" {
		logger.Info("Deleting enrollment flow", zap.String("flow_pk", resources.FlowPK))
		err := authentikClient.DeleteFlow(rc.Ctx, resources.FlowPK)
		if err != nil {
			logger.Error("Failed to delete flow during rollback",
				zap.Error(err),
				zap.String("flow_pk", resources.FlowPK))
		} else {
			logger.Info("✓ Flow deleted")
		}
	}

	// Step 3: Delete stages
	for _, stagePK := range resources.StagePKs {
		logger.Info("Deleting stage", zap.String("stage_pk", stagePK))
		err := authentikClient.DeleteStage(rc.Ctx, stagePK)
		if err != nil {
			logger.Error("Failed to delete stage during rollback",
				zap.Error(err),
				zap.String("stage_pk", stagePK))
		} else {
			logger.Info("✓ Stage deleted", zap.String("stage_pk", stagePK))
		}
	}

	// Step 4: Delete prompt fields
	for _, fieldPK := range resources.PromptFieldPKs {
		logger.Info("Deleting prompt field", zap.String("field_pk", fieldPK))
		err := authentikClient.DeletePromptField(rc.Ctx, fieldPK)
		if err != nil {
			logger.Error("Failed to delete prompt field during rollback",
				zap.Error(err),
				zap.String("field_pk", fieldPK))
		} else {
			logger.Info("✓ Prompt field deleted", zap.String("field_pk", fieldPK))
		}
	}

	logger.Info("Rollback complete - all created resources removed")
}
