// pkg/hecate/self_enrollment.go - Self-enrollment configuration for Hecate applications

package hecate

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SelfEnrollmentConfig holds configuration for enabling self-enrollment
type SelfEnrollmentConfig struct {
	AppName         string // Application name (e.g., "bionicgpt")
	DryRun          bool   // If true, show what would be done without applying changes
	SkipCaddyfile   bool   // If true, don't update Caddyfile (advanced usage)
	EnableCaptcha   bool   // If true, add captcha stage to prevent spam
	RequireApproval bool   // If true, new users inactive until admin approves (default: active immediately)
	// EmailVerification bool   // TODO: Enable when SMTP is configured
	// CaptchaPublicKey  string // TODO: Production captcha keys from Vault
	// CaptchaPrivateKey string // TODO: Production captcha keys from Vault
}

// enrollmentResources tracks all created Authentik resources for rollback
// P0 FIX: Only track resources WE CREATED, not reused existing resources
type enrollmentResources struct {
	PromptFieldPKs []string                 // Created prompt fields (username, email) - NOT reused
	StagePKs       []string                 // Created stages (prompt, password, user write, login, captcha) - NOT reused
	FlowPK         string                   // Created enrollment flow - NOT reused
	OriginalBrand  *authentik.BrandResponse // Original brand config for restoration
	BrandPK        string                   // Brand that was modified
}

// enrollmentStats tracks what was reused vs created for transparency
// P2 REC: Provide visibility into what actions were taken
type enrollmentStats struct {
	FlowsReused     int
	FlowsCreated    int
	StagesReused    int
	StagesCreated   int
	FieldsReused    int
	FieldsCreated   int
	BindingsReused  int
	BindingsCreated int
}

// getDomainForApp discovers the DNS domain for an application by querying Caddy routes
// and matching against Authentik application metadata.
//
// Discovery strategy:
// 1. List all routes from Caddy Admin API
// 2. Fetch all Authentik applications
// 3. Match app name to Authentik application slug/name
// 4. Find Caddy route where domain prefix matches application slug
//
// Example: appName="bionicgpt" → finds app with slug "bionicgpt" → matches domain "chat.codemonkey.net.au"
func getDomainForApp(rc *eos_io.RuntimeContext, appName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Auto-detecting DNS domain for application",
		zap.String("app_name", appName))

	// 1. Get all Caddy routes
	routes, err := ListAPIRoutes(rc)
	if err != nil {
		return "", fmt.Errorf("failed to list Caddy routes: %w\n\n"+
			"Ensure Caddy is running and Admin API is accessible at %s", CaddyAdminAPIHost)
	}

	if len(routes) == 0 {
		return "", fmt.Errorf("no Caddy routes found\n\n"+
			"Add routes first with: eos update hecate --add %s --dns <domain> --upstream <ip:port>", appName)
	}

	logger.Debug("Retrieved Caddy routes",
		zap.Int("route_count", len(routes)))

	// 2. Get Authentik API token
	token, err := getAuthentikAPIToken(rc)
	if err != nil {
		return "", fmt.Errorf("failed to get Authentik API token: %w\n\n"+
			"Set AUTHENTIK_BOOTSTRAP_TOKEN or AUTHENTIK_API_TOKEN in /opt/hecate/.env", err)
	}

	// 3. Fetch Authentik applications
	applications, err := fetchAuthentikApplications(rc, "localhost", AuthentikPort, token)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Authentik applications: %w", err)
	}

	logger.Debug("Retrieved Authentik applications",
		zap.Int("app_count", len(applications)))

	// 4. Find application by name/slug (case-insensitive)
	var targetApp *AuthentikApplication
	for i := range applications {
		app := &applications[i]
		if strings.EqualFold(app.Slug, appName) || strings.EqualFold(app.Name, appName) {
			targetApp = app
			logger.Debug("Found matching Authentik application",
				zap.String("slug", app.Slug),
				zap.String("name", app.Name))
			break
		}
	}

	if targetApp == nil {
		// List available apps for helpful error message
		availableApps := make([]string, 0, len(applications))
		for _, app := range applications {
			availableApps = append(availableApps, app.Slug)
		}

		return "", fmt.Errorf("no Authentik application found matching: %s\n\n"+
			"Available applications: %s\n\n"+
			"Create application in Authentik first, then add route with:\n"+
			"  eos update hecate --add %s --dns <domain> --upstream <ip:port>",
			appName, strings.Join(availableApps, ", "), appName)
	}

	// 5. Find Caddy route matching application slug
	// Strategy: Extract domain prefix (e.g., "chat" from "chat.codemonkey.net.au")
	//           and match against application slug
	for _, route := range routes {
		domainPrefix := extractDomainPrefix(route.DNS)

		// Check if domain prefix matches app slug or app name
		if strings.EqualFold(domainPrefix, targetApp.Slug) ||
			strings.EqualFold(domainPrefix, appName) ||
			strings.EqualFold(route.DNS, targetApp.Name) {

			logger.Info("Auto-detected domain from application name",
				zap.String("app_name", appName),
				zap.String("authentik_slug", targetApp.Slug),
				zap.String("domain", route.DNS),
				zap.String("domain_prefix", domainPrefix))

			return route.DNS, nil
		}
	}

	// No matching route found - provide helpful error
	availableDomains := make([]string, 0, len(routes))
	for _, route := range routes {
		availableDomains = append(availableDomains, route.DNS)
	}

	return "", fmt.Errorf("found Authentik application '%s' but no matching Caddy route\n\n"+
		"Application slug: %s\n"+
		"Available domains: %s\n\n"+
		"Add route for this application:\n"+
		"  eos update hecate --add %s --dns <domain> --upstream <ip:port>\n\n"+
		"Or manually specify domain:\n"+
		"  eos update hecate --enable self-enrollment --app %s --dns <domain>",
		appName, targetApp.Slug, strings.Join(availableDomains, ", "), appName, appName)
}

// findBrandByDomain finds the Authentik brand that serves a specific domain
// Returns the brand if found, or error with helpful troubleshooting steps
func findBrandByDomain(rc *eos_io.RuntimeContext, client *authentik.APIClient, domain string) (*authentik.BrandResponse, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Finding Authentik brand for domain",
		zap.String("domain", domain))

	// List all brands
	brands, err := client.ListBrands(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list Authentik brands: %w", err)
	}

	if len(brands) == 0 {
		return nil, fmt.Errorf("no Authentik brands found - this should not happen\n\n"+
			"Authentik installations always have a default brand.\n"+
			"Check Authentik status: docker ps | grep authentik")
	}

	// Try exact domain match first
	for i := range brands {
		brand := &brands[i]
		if strings.EqualFold(brand.Domain, domain) {
			logger.Info("Found brand with exact domain match",
				zap.String("brand_title", brand.BrandingTitle),
				zap.String("brand_pk", brand.PK),
				zap.String("brand_domain", brand.Domain))
			return brand, nil
		}
	}

	// Try wildcard/subdomain matching
	// Example: brand.Domain="codemonkey.net.au" matches domain="chat.codemonkey.net.au"
	for i := range brands {
		brand := &brands[i]
		if strings.HasSuffix(domain, brand.Domain) {
			logger.Info("Found brand with wildcard domain match",
				zap.String("brand_title", brand.BrandingTitle),
				zap.String("brand_pk", brand.PK),
				zap.String("brand_domain", brand.Domain),
				zap.String("requested_domain", domain))
			return brand, nil
		}
	}

	// No match found - provide helpful error with available brands
	brandInfo := make([]string, 0, len(brands))
	for _, brand := range brands {
		brandInfo = append(brandInfo, fmt.Sprintf("%s (domain: %s)", brand.BrandingTitle, brand.Domain))
	}

	// If only one brand exists, use it (most common case)
	if len(brands) == 1 {
		logger.Warn("No exact domain match, using default brand",
			zap.String("brand_domain", brands[0].Domain),
			zap.String("requested_domain", domain))
		return &brands[0], nil
	}

	return nil, fmt.Errorf("no Authentik brand found for domain: %s\n\n"+
		"Available brands:\n  %s\n\n"+
		"Configure brand domain in Authentik:\n"+
		"  1. Go to http://localhost:9000/if/admin/#/core/brands\n"+
		"  2. Edit brand and set Domain field to: %s\n"+
		"  3. Re-run: eos update hecate --enable self-enrollment --app <app>",
		domain, strings.Join(brandInfo, "\n  "), domain)
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

	// P0 FIX: Log connection details at INFO level for visibility
	logger.Info("Connecting to Authentik API",
		zap.String("url", authentikURL),
		zap.String("source", "credential discovery"))

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// P1 REC: Health check before attempting operations
	// RATIONALE: Distinguishes "Authentik not running" from "wrong credentials" from "wrong API endpoint"
	// BENEFIT: Faster diagnosis and better error messages
	logger.Info("Verifying Authentik API health")
	if err := verifyAuthentikHealth(rc, authentikURL); err != nil {
		return fmt.Errorf("Authentik health check failed: %w\n\n"+
			"This usually means:\n"+
			"  1. Authentik container is not running\n"+
			"  2. Wrong URL in /opt/hecate/.env (check AUTHENTIK_BASE_URL)\n"+
			"  3. Port 9000 not published in docker-compose.yml\n\n"+
			"ARCHITECTURE NOTE:\n"+
			"  Eos runs on HOST, Authentik in CONTAINER\n"+
			"  Use: AUTHENTIK_BASE_URL=http://localhost:9000\n"+
			"  NOT: AUTHENTIK_BASE_URL=http://hecate-server-1:9000\n\n"+
			"Troubleshooting:\n"+
			"  docker ps | grep authentik\n"+
			"  curl %s/-/health/live/\n"+
			"  docker port hecate-server-1", err, authentikURL)
	}
	logger.Info("✓ Authentik API is responding")

	// Auto-detect DNS domain from application name
	// This queries Caddy Admin API and Authentik API to find the matching domain
	logger.Info("Auto-detecting DNS domain from application name")
	domain, err := getDomainForApp(rc, config.AppName)
	if err != nil {
		return fmt.Errorf("failed to auto-detect domain: %w", err)
	}

	logger.Info("✓ Domain auto-detected",
		zap.String("app", config.AppName),
		zap.String("domain", domain))

	// P3 FIX: Validate API token by listing brands
	// RATIONALE: Health check only verifies service is up, not that token is valid
	// BENEFIT: Detect auth issues before attempting to create resources
	logger.Info("Validating API token via brand listing")
	_, err = authentikClient.ListBrands(rc.Ctx)
	if err != nil {
		return fmt.Errorf("Authentik API token invalid or failed to fetch brands: %w\n\n"+
			"Check token in /opt/hecate/.env\n"+
			"Looked for: AUTHENTIK_API_TOKEN, AUTHENTIK_TOKEN, AUTHENTIK_API_KEY, AUTHENTIK_BOOTSTRAP_TOKEN\n\n"+
			"To fix:\n"+
			"  1. Verify token exists: grep AUTHENTIK /opt/hecate/.env\n"+
			"  2. Test token: curl -H 'Authorization: Bearer <token>' %s/api/v3/core/brands/\n"+
			"  3. Create new token in Authentik UI: Admin → Tokens → Create\n"+
			"  4. Update /opt/hecate/.env with new token", err, authentikURL)
	}
	logger.Info("✓ API token validated")

	// Find brand by domain (domain-aware brand selection)
	// This replaces the old "brands[0]" logic with intelligent domain matching
	brand, err := findBrandByDomain(rc, authentikClient, domain)
	if err != nil {
		return fmt.Errorf("failed to find brand for domain: %w", err)
	}

	logger.Info("Selected Authentik brand for domain",
		zap.String("brand_pk", brand.PK),
		zap.String("brand_title", brand.BrandingTitle),
		zap.String("brand_domain", brand.Domain),
		zap.String("requested_domain", domain),
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
		OriginalBrand: brand, // Store original brand config for restoration
		BrandPK:       brand.PK,
	}

	// P2: Initialize stats tracking for transparency
	stats := &enrollmentStats{}

	// P0: Defer rollback on failure (follows Hecate backup/restore pattern)
	var enrollmentErr error
	defer func() {
		if enrollmentErr != nil {
			// P2 FIX: Include error context in rollback message
			rollbackEnrollmentSetup(rc, authentikClient, resources, enrollmentErr)
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

	// P0 SECURITY FIX: Create or get default group for self-enrolled users
	// RATIONALE: Self-enrolled users must be assigned to a group for proper access control
	// WITHOUT THIS: Users may get unpredictable access or no access at all
	logger.Info("Ensuring default group exists for self-enrolled users")
	groupName := "eos-self-enrolled-users"
	var selfEnrolledGroup *authentik.GroupResponse

	// Check if group already exists
	existingGroup, err := authentikClient.GetGroupByName(rc.Ctx, groupName)
	if err != nil && err.Error() != fmt.Sprintf("group not found: %s", groupName) {
		enrollmentErr = fmt.Errorf("failed to check for existing group: %w", err)
		return enrollmentErr
	}

	if existingGroup != nil {
		// Group exists, reuse it
		logger.Info("✓ Self-enrolled users group already exists",
			zap.String("group_pk", existingGroup.PK),
			zap.String("group_name", existingGroup.Name))
		selfEnrolledGroup = existingGroup
	} else {
		// Group doesn't exist, create it
		logger.Info("Creating default group for self-enrolled users",
			zap.String("group_name", groupName))

		selfEnrolledGroup, err = authentikClient.CreateGroup(rc.Ctx, groupName, map[string]interface{}{
			"eos_managed":  true,
			"description":  "Users who self-registered via Eos enrollment flow",
			"created_by":   "eos",
			"created_date": time.Now().Format(time.RFC3339),
		})
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create self-enrolled users group: %w", err)
			return enrollmentErr
		}

		logger.Info("✓ Self-enrolled users group created",
			zap.String("group_pk", selfEnrolledGroup.PK),
			zap.String("group_name", selfEnrolledGroup.Name))
	}

	// P0 FIX: Check if enrollment flow already exists (idempotency)
	flowSlug := "eos-self-registration"
	flowName := "Self Registration (Eos)"
	flowTitle := "Create your account"

	logger.Debug("Checking for existing enrollment flow", zap.String("slug", flowSlug))
	var enrollmentFlow *authentik.FlowResponse
	existingFlow, err := authentikClient.GetFlow(rc.Ctx, flowSlug)
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to check for existing flow: %w", err)
		return enrollmentErr
	}

	if existingFlow != nil {
		// P2 FIX: Validate flow has correct designation before reusing
		// RATIONALE: Authentik flows can have different designations (authentication, enrollment, invalidation, recovery, etc.)
		// RISK: If someone creates flow with same slug but wrong designation, enrollment will fail mysteriously
		// BENEFIT: Fail-fast with clear error message instead of cryptic runtime failures
		if existingFlow.Designation != "enrollment" {
			enrollmentErr = fmt.Errorf("existing flow '%s' has wrong designation: %s (expected: enrollment)\n\n"+
				"A flow with slug '%s' already exists but is not an enrollment flow.\n"+
				"Either:\n"+
				"  1. Delete the conflicting flow: visit Authentik UI → Flows → '%s' → Delete\n"+
				"  2. Use a different slug by modifying the code (not recommended)\n\n"+
				"Flow details:\n"+
				"  PK: %s\n"+
				"  Name: %s\n"+
				"  Designation: %s",
				existingFlow.Slug, existingFlow.Designation,
				flowSlug, existingFlow.Name,
				existingFlow.PK, existingFlow.Name, existingFlow.Designation)
			return enrollmentErr
		}

		// Flow already exists with correct designation, reuse it
		logger.Info("✓ Enrollment flow already exists, reusing",
			zap.String("flow_pk", existingFlow.PK),
			zap.String("slug", existingFlow.Slug),
			zap.String("designation", existingFlow.Designation))
		enrollmentFlow = existingFlow
		stats.FlowsReused++
		// P0 FIX: Do NOT track for rollback - we didn't create it
	} else {
		// Flow doesn't exist, create it
		logger.Info("Creating enrollment flow",
			zap.String("slug", flowSlug),
			zap.String("name", flowName))

		enrollmentFlow, err = authentikClient.CreateEnrollmentFlow(rc.Ctx, flowName, flowSlug, flowTitle)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create enrollment flow: %w", err)
			return enrollmentErr
		}
		resources.FlowPK = enrollmentFlow.PK // P0 FIX: Only track if WE created it
		stats.FlowsCreated++
		logger.Info("✓ Enrollment flow created",
			zap.String("flow_pk", enrollmentFlow.PK),
			zap.String("slug", enrollmentFlow.Slug))
	}

	// Create prompt fields for username and email collection
	logger.Info("Creating prompt fields for user information")

	// Rec #3: Check for existing fields first (idempotency)
	logger.Debug("Checking for existing prompt fields")
	existingFields, err := authentikClient.ListPromptFields(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to list existing prompt fields, will attempt creation",
			zap.Error(err))
		existingFields = []authentik.PromptFieldResponse{} // Continue with empty list
	}

	// Helper to find existing field by name
	findFieldByName := func(name string) *authentik.PromptFieldResponse {
		for i := range existingFields {
			if existingFields[i].Name == name {
				return &existingFields[i]
			}
		}
		return nil
	}

	// Create or reuse username field
	var usernameField *authentik.PromptFieldResponse
	if existing := findFieldByName("eos-username-field"); existing != nil {
		logger.Info("✓ Username field already exists, reusing",
			zap.String("field_pk", existing.PK),
			zap.String("field_key", existing.FieldKey))
		usernameField = existing
		stats.FieldsReused++ // P2: Track reuse
	} else {
		usernameField, err = authentikClient.CreatePromptField(rc.Ctx,
			"username",       // field_key
			"username",       // type
			"Username",       // label
			"Enter username", // placeholder
			true,             // required
			10)               // order
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create username field: %w", err)
			return enrollmentErr
		}
		resources.PromptFieldPKs = append(resources.PromptFieldPKs, usernameField.PK) // Track for rollback
		stats.FieldsCreated++                                                         // P2: Track creation
		logger.Info("✓ Username field created", zap.String("field_pk", usernameField.PK))
	}

	// Create or reuse email field
	var emailField *authentik.PromptFieldResponse
	if existing := findFieldByName("eos-email-field"); existing != nil {
		logger.Info("✓ Email field already exists, reusing",
			zap.String("field_pk", existing.PK),
			zap.String("field_key", existing.FieldKey))
		emailField = existing
		stats.FieldsReused++ // P2: Track reuse
	} else {
		emailField, err = authentikClient.CreatePromptField(rc.Ctx,
			"email",       // field_key
			"email",       // type
			"Email",       // label
			"Enter email", // placeholder
			true,          // required
			20)            // order
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create email field: %w", err)
			return enrollmentErr
		}
		resources.PromptFieldPKs = append(resources.PromptFieldPKs, emailField.PK) // Track for rollback
		stats.FieldsCreated++                                                      // P2: Track creation
		logger.Info("✓ Email field created", zap.String("field_pk", emailField.PK))
	}

	// P0 FIX: Check for existing stages first (idempotency)
	logger.Debug("Checking for existing stages")
	existingStages, err := authentikClient.ListStages(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to list existing stages, will attempt creation",
			zap.Error(err))
		existingStages = []authentik.StageResponse{} // Continue with empty list
	}

	// Helper to find existing stage by name
	findStageByName := func(name string) *authentik.StageResponse {
		for i := range existingStages {
			if existingStages[i].Name == name {
				return &existingStages[i]
			}
		}
		return nil
	}

	// Optional: Create or reuse captcha stage for bot protection
	var captchaStage *authentik.CaptchaStageResponse
	if config.EnableCaptcha {
		if existing := findStageByName("eos-enrollment-captcha"); existing != nil {
			logger.Info("✓ Captcha stage already exists, reusing",
				zap.String("stage_pk", existing.PK))
			// Map to CaptchaStageResponse (we only need PK for binding)
			captchaStage = &authentik.CaptchaStageResponse{PK: existing.PK, Name: existing.Name}
			stats.StagesReused++
		} else {
			logger.Info("Creating captcha stage for bot protection")
			captchaStage, err = authentikClient.CreateCaptchaStage(rc.Ctx, "eos-enrollment-captcha", "", "")
			if err != nil {
				enrollmentErr = fmt.Errorf("failed to create captcha stage: %w", err)
				return enrollmentErr
			}
			resources.StagePKs = append(resources.StagePKs, captchaStage.PK) // Track for rollback ONLY if created
			stats.StagesCreated++
			logger.Info("✓ Captcha stage created (using test keys - configure production keys in Authentik UI)",
				zap.String("stage_pk", captchaStage.PK))
		}
	}

	// Create or reuse prompt stage with username and email fields
	var promptStage *authentik.PromptStageResponse
	if existing := findStageByName("eos-enrollment-prompts"); existing != nil {
		logger.Info("✓ Prompt stage already exists, reusing",
			zap.String("stage_pk", existing.PK))
		promptStage = &authentik.PromptStageResponse{PK: existing.PK, Name: existing.Name}
		stats.StagesReused++
	} else {
		logger.Info("Creating prompt stage for enrollment")
		promptStage, err = authentikClient.CreatePromptStage(rc.Ctx,
			"eos-enrollment-prompts",
			[]string{usernameField.PK, emailField.PK})
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create prompt stage: %w", err)
			return enrollmentErr
		}
		resources.StagePKs = append(resources.StagePKs, promptStage.PK) // Track for rollback
		stats.StagesCreated++
		logger.Info("✓ Prompt stage created", zap.String("stage_pk", promptStage.PK))
	}

	// Create or reuse password stage
	var passwordStage *authentik.PasswordStageResponse
	if existing := findStageByName("eos-enrollment-password"); existing != nil {
		logger.Info("✓ Password stage already exists, reusing",
			zap.String("stage_pk", existing.PK))
		passwordStage = &authentik.PasswordStageResponse{PK: existing.PK, Name: existing.Name}
		stats.StagesReused++
	} else {
		logger.Info("Creating password stage for enrollment")
		passwordStage, err = authentikClient.CreatePasswordStage(rc.Ctx, "eos-enrollment-password")
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create password stage: %w", err)
			return enrollmentErr
		}
		resources.StagePKs = append(resources.StagePKs, passwordStage.PK) // Track for rollback
		stats.StagesCreated++
		logger.Info("✓ Password stage created", zap.String("stage_pk", passwordStage.PK))
	}

	// Create or reuse user write stage
	var userWriteStage *authentik.UserWriteStageResponse
	if existing := findStageByName("eos-enrollment-user-write"); existing != nil {
		logger.Info("✓ User write stage already exists, reusing",
			zap.String("stage_pk", existing.PK))
		userWriteStage = &authentik.UserWriteStageResponse{PK: existing.PK, Name: existing.Name}
		stats.StagesReused++
	} else {
		logger.Info("Creating user write stage for enrollment")
		// P0 SECURITY FIX: Assign new users to eos-self-enrolled-users group
		// This ensures proper access control via group-based policies
		// P1 SECURITY OPTION: Support --require-approval flag for admin vetting
		userWriteStage, err = authentikClient.CreateUserWriteStage(rc.Ctx,
			"eos-enrollment-user-write",
			config.RequireApproval,   // If true, users inactive until admin approves
			selfEnrolledGroup.PK)     // ✓ Assign to group!
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create user write stage: %w", err)
			return enrollmentErr
		}
		resources.StagePKs = append(resources.StagePKs, userWriteStage.PK) // Track for rollback
		stats.StagesCreated++
		logger.Info("✓ User write stage created (users assigned to group)",
			zap.String("stage_pk", userWriteStage.PK),
			zap.String("group", groupName))
	}

	// Create or reuse user login stage (auto-login after signup)
	var loginStage *authentik.UserLoginStageResponse
	if existing := findStageByName("eos-enrollment-login"); existing != nil {
		logger.Info("✓ User login stage already exists, reusing",
			zap.String("stage_pk", existing.PK))
		loginStage = &authentik.UserLoginStageResponse{PK: existing.PK, Name: existing.Name}
		stats.StagesReused++
	} else {
		logger.Info("Creating user login stage for auto-login")
		loginStage, err = authentikClient.CreateUserLoginStage(rc.Ctx, "eos-enrollment-login")
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to create user login stage: %w", err)
			return enrollmentErr
		}
		resources.StagePKs = append(resources.StagePKs, loginStage.PK) // Track for rollback
		stats.StagesCreated++
		logger.Info("✓ User login stage created", zap.String("stage_pk", loginStage.PK))
	}

	// P0 FIX: Bind stages to enrollment flow with idempotency check
	// Order 5: Captcha stage (if enabled - bot protection)
	// Order 10: Prompt stage (collect username, email)
	// Order 20: Password stage (user chooses password)
	// Order 30: User write stage (creates user account)
	// Order 40: User login stage (auto-login after signup)
	logger.Info("Binding stages to enrollment flow")

	// Check existing bindings first
	existingBindings, err := authentikClient.ListFlowBindings(rc.Ctx, enrollmentFlow.PK)
	if err != nil {
		logger.Warn("Failed to list existing bindings, will attempt creation",
			zap.Error(err))
		existingBindings = []authentik.StageBindingResponse{}
	}

	// Helper to check if binding already exists
	bindingExists := func(stagePK string) bool {
		for _, binding := range existingBindings {
			if binding.Stage == stagePK {
				return true
			}
		}
		return false
	}

	stageCount := 4
	if config.EnableCaptcha && captchaStage != nil {
		if bindingExists(captchaStage.PK) {
			logger.Info("✓ Captcha stage binding already exists, skipping")
			stats.BindingsReused++
		} else {
			_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, captchaStage.PK, 5)
			if err != nil {
				enrollmentErr = fmt.Errorf("failed to bind captcha stage: %w", err)
				return enrollmentErr
			}
			stats.BindingsCreated++
		}
		stageCount++
	}

	if bindingExists(promptStage.PK) {
		logger.Info("✓ Prompt stage binding already exists, skipping")
		stats.BindingsReused++
	} else {
		_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, promptStage.PK, 10)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to bind prompt stage: %w", err)
			return enrollmentErr
		}
		stats.BindingsCreated++
	}

	if bindingExists(passwordStage.PK) {
		logger.Info("✓ Password stage binding already exists, skipping")
		stats.BindingsReused++
	} else {
		_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, passwordStage.PK, 20)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to bind password stage: %w", err)
			return enrollmentErr
		}
		stats.BindingsCreated++
	}

	if bindingExists(userWriteStage.PK) {
		logger.Info("✓ User write stage binding already exists, skipping")
		stats.BindingsReused++
	} else {
		_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, userWriteStage.PK, 30)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to bind user write stage: %w", err)
			return enrollmentErr
		}
		stats.BindingsCreated++
	}

	if bindingExists(loginStage.PK) {
		logger.Info("✓ User login stage binding already exists, skipping")
		stats.BindingsReused++
	} else {
		_, err = authentikClient.CreateStageBinding(rc.Ctx, enrollmentFlow.PK, loginStage.PK, 40)
		if err != nil {
			enrollmentErr = fmt.Errorf("failed to bind user login stage: %w", err)
			return enrollmentErr
		}
		stats.BindingsCreated++
	}

	logger.Info("✓ Stages bound to enrollment flow",
		zap.Int("stage_count", stageCount))

	// Link enrollment flow to brand
	logger.Info("Linking enrollment flow to brand",
		zap.String("brand_pk", brand.PK),
		zap.String("flow_pk", enrollmentFlow.PK))

	updatedBrand, err := authentikClient.UpdateBrand(rc.Ctx, brand.PK, map[string]interface{}{
		"flow_enrollment": enrollmentFlow.PK,
	})
	if err != nil {
		enrollmentErr = fmt.Errorf("failed to link enrollment flow to brand: %w", err)
		return enrollmentErr
	}

	// PHASE 3: EVALUATE - Verify and report results

	logger.Info("Phase 3: Verifying enrollment configuration")

	// Verify brand was actually updated (immediate verification from API response)
	if updatedBrand.FlowEnrollment != enrollmentFlow.PK {
		logger.Error("Brand enrollment flow update FAILED - API returned success but flow not set",
			zap.String("expected_flow_pk", enrollmentFlow.PK),
			zap.String("actual_flow_enrollment", updatedBrand.FlowEnrollment),
			zap.String("brand_pk", brand.PK),
			zap.String("api_response_brand_pk", updatedBrand.PK))
		enrollmentErr = fmt.Errorf("brand update failed verification: API returned brand with flow_enrollment=%q, expected %q",
			updatedBrand.FlowEnrollment, enrollmentFlow.PK)
		return enrollmentErr
	}

	logger.Info("✓ Brand enrollment flow linked and verified",
		zap.String("brand_pk", brand.PK),
		zap.String("flow_enrollment", updatedBrand.FlowEnrollment))

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

	// P2: Display stats summary (transparency)
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("✓ Self-enrollment enabled successfully")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Resource Summary",
		zap.Int("flows_created", stats.FlowsCreated),
		zap.Int("flows_reused", stats.FlowsReused),
		zap.Int("stages_created", stats.StagesCreated),
		zap.Int("stages_reused", stats.StagesReused),
		zap.Int("fields_created", stats.FieldsCreated),
		zap.Int("fields_reused", stats.FieldsReused),
		zap.Int("bindings_created", stats.BindingsCreated),
		zap.Int("bindings_reused", stats.BindingsReused))
	logger.Info("")
	logger.Info("Enrollment URL", zap.String("url", enrollmentURL))
	logger.Info("Flow Name", zap.String("name", enrollmentFlow.Name))
	logger.Info("Flow Slug", zap.String("slug", enrollmentFlow.Slug))
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("User Permissions for Self-Enrolled Users")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("")
	logger.Info("  Group: " + groupName)
	if config.RequireApproval {
		logger.Info("  Status: INACTIVE until admin approves")
		logger.Info("  Admins must activate users in Authentik UI: Admin → Directory → Users")
	} else {
		logger.Info("  Status: ACTIVE immediately (can log in)")
	}
	logger.Info("  Application Access: Controlled by group policies")
	logger.Info("")
	logger.Info("IMPORTANT: Configure application access policies:")
	logger.Info("  1. Visit: " + authentikURL + "/if/admin/#/policy/policies")
	logger.Info("  2. Create policy binding for '" + groupName + "' group")
	logger.Info("  3. Assign policy to your application (e.g., BionicGPT)")
	logger.Info("  OR")
	logger.Info("  Allow all authenticated users (less secure)")
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("IMPORTANT: Forward auth operates at BRAND level")
	logger.Info("This enables self-registration for ALL apps behind Authentik on this brand.")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Users can now register at: " + enrollmentURL)
	logger.Info("  2. Configure application policies (see above)")
	logger.Info("  3. Test signup with private browser window")
	logger.Info("  4. Admins can manage users via: " + authentikURL + "/if/admin/#/directory/users")
	logger.Info("")
	logger.Info("To customize enrollment flow:")
	logger.Info("  - Visit Authentik admin: " + authentikURL + "/if/admin/")
	logger.Info("  - Navigate to: Flows & Stages → Flows")
	logger.Info("  - Edit: " + enrollmentFlow.Name)
	logger.Info("")

	return nil
}

// verifyAuthentikHealth checks if Authentik API is responding
// P1 REC: Pre-flight health check before attempting operations
//
// ARCHITECTURE: This is called BEFORE authentication to distinguish:
//   - Service not running (connection refused)
//   - Service starting (health endpoint not ready)
//   - Service ready but auth failed (wrong token)
//
// Returns error if health check fails, nil if healthy
func verifyAuthentikHealth(rc *eos_io.RuntimeContext, baseURL string) error {
	logger := otelzap.Ctx(rc.Ctx)

	healthURL := fmt.Sprintf("%s/-/health/live/", baseURL)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(rc.Ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	logger.Debug("Checking Authentik health endpoint", zap.String("url", healthURL))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unhealthy (status %d): %s", resp.StatusCode, string(body))
	}

	logger.Debug("✓ Authentik health check passed", zap.Int("status_code", resp.StatusCode))
	return nil
}

// verifyEnrollmentURLAccessible performs a health check on the enrollment URL
// P1 FIX #3: Add health check for enrollment URL
//
// Verification approach:
//  1. HTTP HEAD request to enrollment URL
//  2. Check for successful response (200-399)
//  3. Non-fatal failure (warns but doesn't stop)
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
		// P0 FIX: Use localhost for host-to-container communication
		// ARCHITECTURE: Eos runs on HOST, Authentik in CONTAINER with published port 9000
		// Container name (hecate-server-1) only works inside Docker network
		// Host must use localhost + published port to reach container
		baseURL = fmt.Sprintf("http://%s:%d", AuthentikHost, AuthentikPort)
		logger.Debug("AUTHENTIK_BASE_URL not set, using default localhost",
			zap.String("default_url", baseURL),
			zap.String("note", "Eos on host -> Authentik container via published port"))
	}

	if apiKey == "" {
		return "", "", fmt.Errorf("no Authentik API token found in /opt/hecate/.env\n\n" +
			"Looked for: AUTHENTIK_API_TOKEN, AUTHENTIK_TOKEN, AUTHENTIK_API_KEY, AUTHENTIK_BOOTSTRAP_TOKEN\n\n" +
			"To fix:\n" +
			"  1. Check if Authentik is running: docker ps | grep authentik\n" +
			"  2. Check if bootstrap token exists: grep AUTHENTIK_BOOTSTRAP_TOKEN /opt/hecate/.env\n" +
			"  3. Create API token in Authentik UI: Admin → Tokens → Create\n" +
			"  4. Add to /opt/hecate/.env: echo 'AUTHENTIK_API_TOKEN=your-token-here' | sudo tee -a /opt/hecate/.env")
	}

	return apiKey, baseURL, nil
}

// rollbackEnrollmentSetup removes all created Authentik resources
// P0 FIX: Only deletes resources WE CREATED (tracked in resources struct)
// P2 FIX: Includes error context for debugging
// ROLLBACK ORDER (reverse of creation):
// 1. Restore brand to original state
// 2. Delete flow (and its stage bindings)
// 3. Delete stages
// 4. Delete prompt fields
func rollbackEnrollmentSetup(rc *eos_io.RuntimeContext, authentikClient *authentik.APIClient, resources *enrollmentResources, triggerError error) {
	logger := otelzap.Ctx(rc.Ctx)

	if resources == nil {
		return
	}

	// P2 FIX: Include error context in rollback message
	logger.Warn("Rolling back enrollment setup due to failure",
		zap.Error(triggerError),
		zap.String("reason", "See error above for root cause"))

	// Step 1: Restore brand to original state (if modified)
	if resources.OriginalBrand != nil && resources.BrandPK != "" {
		logger.Info("Restoring brand to original state", zap.String("brand_pk", resources.BrandPK))
		_, err := authentikClient.UpdateBrand(rc.Ctx, resources.BrandPK, map[string]interface{}{
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
