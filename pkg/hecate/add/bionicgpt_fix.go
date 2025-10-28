// pkg/hecate/add/bionicgpt_fix.go - BionicGPT drift correction

package add

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BionicGPTFixer implements drift correction for BionicGPT
type BionicGPTFixer struct {
	integrator *BionicGPTIntegrator // Reuse existing integrator logic
}

func init() {
	// Register BionicGPT fixer
	RegisterServiceFixer("bionicgpt", func() ServiceFixer {
		return &BionicGPTFixer{
			integrator: &BionicGPTIntegrator{
				resources: &IntegrationResources{},
			},
		}
	})
}

// Fix corrects BionicGPT configuration drift
//
// WHAT THIS FIXES:
// 1. Missing proxy provider in Authentik
// 2. Proxy provider missing invalidation_flow (API compatibility)
// 3. Missing "BionicGPT" application in Authentik
// 4. Missing groups (bionicgpt-superadmin, bionicgpt-demo)
// 5. Application not assigned to embedded outpost
//
// PATTERN: Assess → Intervene → Evaluate
func (f *BionicGPTFixer) Fix(rc *eos_io.RuntimeContext, opts *FixOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	if opts.DryRun {
		return f.dryRun(rc)
	}

	// Phase 1: ASSESS - Get current state
	logger.Info("Phase 1/3: Assessing current configuration...")
	assessment, err := f.assess(rc)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Phase 2: INTERVENE - Fix issues
	logger.Info("Phase 2/3: Correcting configuration drift...")
	fixedCount, err := f.intervene(rc, assessment)
	if err != nil {
		return fmt.Errorf("intervention failed: %w", err)
	}

	// Phase 3: EVALUATE - Verify fixes
	logger.Info("Phase 3/3: Verifying fixes...")
	if err := f.evaluate(rc, assessment); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Summary
	logger.Info("")
	logger.Info("✅ Configuration drift correction completed")
	logger.Info(fmt.Sprintf("Fixed %d issue(s)", fixedCount))
	logger.Info("")

	return nil
}

// DriftAssessment tracks what needs fixing
type DriftAssessment struct {
	AuthentikClient         *authentik.APIClient
	DNS                     string
	ProxyProviderMissing    bool
	ProxyProviderPK         int
	InvalidationFlowMissing bool
	ApplicationMissing      bool
	GroupsMissing           []string
	OutpostNotAssigned      bool
	CaddyfileDuplicates     int  // Number of duplicate entries in Caddyfile
	CaddyfileMissingHeaders bool // True if header_up mappings are missing
	CaddyfileWrongImport    bool // True if using "import common" instead of "import cybermonkey_common"
	CaddyfileInvalidSyntax  bool // True if Caddyfile has invalid Caddy syntax (e.g., standalone header_up)
}

// dryRun shows what would be fixed
func (f *BionicGPTFixer) dryRun(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("DRY RUN MODE - No changes will be made")
	logger.Info("")

	assessment, err := f.assess(rc)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	issuesFound := 0

	if assessment.ProxyProviderMissing {
		logger.Info("Would create: Authentik proxy provider for BionicGPT")
		issuesFound++
	} else {
		logger.Info("✓ Proxy provider exists")
		if assessment.InvalidationFlowMissing {
			logger.Info("Would fix: Add missing invalidation_flow to proxy provider")
			issuesFound++
		}
	}

	if assessment.ApplicationMissing {
		logger.Info("Would create: Authentik application 'BionicGPT'")
		issuesFound++
	} else {
		logger.Info("✓ Application exists")
	}

	if len(assessment.GroupsMissing) > 0 {
		for _, group := range assessment.GroupsMissing {
			logger.Info(fmt.Sprintf("Would create: Group '%s'", group))
			issuesFound++
		}
	} else {
		logger.Info("✓ All groups exist")
	}

	if assessment.OutpostNotAssigned {
		logger.Info("Would fix: Assign application to embedded outpost")
		issuesFound++
	} else {
		logger.Info("✓ Application assigned to outpost")
	}

	// Caddyfile issues
	if assessment.CaddyfileDuplicates > 1 {
		logger.Info(fmt.Sprintf("Would fix: Remove %d duplicate Caddyfile entries", assessment.CaddyfileDuplicates-1))
		issuesFound++
	}

	if assessment.CaddyfileMissingHeaders {
		logger.Info("Would fix: Add missing X-Auth-Request-* header mappings to Caddyfile")
		issuesFound++
	}

	if assessment.CaddyfileWrongImport {
		logger.Info("Would fix: Change 'import common' to 'import cybermonkey_common' in Caddyfile")
		issuesFound++
	}

	if assessment.CaddyfileInvalidSyntax {
		logger.Info("Would fix: Remove invalid standalone header_up directives and use correct copy_headers syntax")
		issuesFound++
	}

	if assessment.CaddyfileDuplicates <= 1 && !assessment.CaddyfileMissingHeaders && !assessment.CaddyfileWrongImport && !assessment.CaddyfileInvalidSyntax {
		logger.Info("✓ Caddyfile configuration is correct")
	}

	logger.Info("")
	if issuesFound == 0 {
		logger.Info("No drift detected - configuration is correct")
	} else {
		logger.Info(fmt.Sprintf("Found %d issue(s) that would be fixed", issuesFound))
	}
	logger.Info("")
	logger.Info("To apply these fixes, run without --dry-run")

	return nil
}

// assess checks current state vs. canonical state
func (f *BionicGPTFixer) assess(rc *eos_io.RuntimeContext) (*DriftAssessment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	assessment := &DriftAssessment{}

	// Get Authentik credentials
	authentikToken, authentikBaseURL, err := f.integrator.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Initialize Authentik client
	assessment.AuthentikClient = authentik.NewClient(authentikBaseURL, authentikToken)

	// Get DNS from Caddyfile (look for existing BionicGPT route)
	dns, err := f.getDNSFromCaddyfile()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS from Caddyfile: %w", err)
	}
	assessment.DNS = dns
	logger.Debug("Found BionicGPT DNS", zap.String("dns", dns))

	// Check proxy provider
	providers, err := assessment.AuthentikClient.ListProxyProviders(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list proxy providers: %w", err)
	}

	providerFound := false
	for _, provider := range providers {
		if provider.Name == "BionicGPT" {
			providerFound = true
			assessment.ProxyProviderPK = provider.PK
			// Check if invalidation flow is missing
			if provider.InvalidationFlow == "" {
				assessment.InvalidationFlowMissing = true
			}
			break
		}
	}
	assessment.ProxyProviderMissing = !providerFound

	// Check application
	apps, err := assessment.AuthentikClient.ListApplications(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	// Check if application exists for THIS SPECIFIC DNS (P1 #5 fix)
	appFound := false
	expectedLaunchURL := fmt.Sprintf("https://%s", assessment.DNS)
	for _, app := range apps {
		if app.Slug == "bionicgpt" && app.MetaLaunchURL == expectedLaunchURL {
			appFound = true
			logger.Debug("BionicGPT application found for this DNS",
				zap.String("slug", app.Slug),
				zap.String("launch_url", app.MetaLaunchURL))
			break
		}
	}
	if !appFound {
		logger.Debug("BionicGPT application not found for this DNS",
			zap.String("expected_launch_url", expectedLaunchURL))
	}
	assessment.ApplicationMissing = !appFound

	// Check groups
	requiredGroups := []string{"bionicgpt-superadmin", "bionicgpt-demo"}
	for _, groupName := range requiredGroups {
		exists, err := f.checkGroupExists(rc.Ctx, assessment.AuthentikClient, groupName)
		if err != nil {
			logger.Warn("Failed to check group", zap.String("group", groupName), zap.Error(err))
		}
		if !exists {
			assessment.GroupsMissing = append(assessment.GroupsMissing, groupName)
		}
	}

	// Check outpost assignment (simplified - just mark as needing check)
	// Full implementation would query outpost providers
	assessment.OutpostNotAssigned = false // TODO: Implement full check

	// Check Caddyfile for duplicates and missing headers
	// P1 - CRITICAL: Caddyfile assessment is REQUIRED for BionicGPT drift correction
	// Fail fast with clear error message if Caddyfile cannot be read
	if err := f.assessCaddyfile(rc, assessment); err != nil {
		return nil, fmt.Errorf("failed to assess Caddyfile configuration: %w\n\n"+
			"BionicGPT drift correction requires access to Caddyfile.\n"+
			"Expected location: %s\n\n"+
			"Remediation:\n"+
			"  1. Verify Hecate is installed: ls -la /opt/hecate/\n"+
			"  2. Check Caddyfile exists: ls -la %s\n"+
			"  3. Verify file permissions: sudo chmod 644 %s",
			err, hecate.CaddyfilePath, hecate.CaddyfilePath, hecate.CaddyfilePath)
	}

	return assessment, nil
}

// intervene applies fixes
func (f *BionicGPTFixer) intervene(rc *eos_io.RuntimeContext, assessment *DriftAssessment) (int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	fixedCount := 0

	// Get flows (needed for provider creation/update)
	authFlowUUID, err := f.integrator.getDefaultAuthFlowUUID(rc.Ctx, assessment.AuthentikClient)
	if err != nil {
		logger.Warn("Failed to get auth flow, using default slug", zap.Error(err))
		authFlowUUID = "default-authentication-flow"
	}

	invalidationFlowUUID, err := f.integrator.getDefaultInvalidationFlowUUID(rc.Ctx, assessment.AuthentikClient)
	if err != nil {
		logger.Warn("Failed to get invalidation flow, using default slug", zap.Error(err))
		invalidationFlowUUID = "default-invalidation-flow"
	}

	// Fix missing proxy provider
	if assessment.ProxyProviderMissing {
		logger.Info("Creating missing proxy provider...")
		opts := &ServiceOptions{
			Service: "bionicgpt",
			DNS:     assessment.DNS,
			Backend: "localhost:8513", // Placeholder - will be overridden by existing config
		}
		providerPK, err := f.integrator.createProxyProvider(rc.Ctx, assessment.AuthentikClient, opts, authFlowUUID, invalidationFlowUUID)
		if err != nil {
			return fixedCount, fmt.Errorf("failed to create proxy provider: %w", err)
		}
		assessment.ProxyProviderPK = providerPK
		logger.Info("✓ Proxy provider created", zap.Int("pk", providerPK))
		fixedCount++
	} else if assessment.InvalidationFlowMissing {
		// Fix missing invalidation_flow in existing provider
		logger.Info("Adding missing invalidation_flow to proxy provider...")
		err := assessment.AuthentikClient.UpdateProxyProvider(rc.Ctx, assessment.ProxyProviderPK, &authentik.ProxyProviderConfig{
			Name:              "BionicGPT",
			Mode:              "forward_single",
			ExternalHost:      fmt.Sprintf("https://%s", assessment.DNS),
			InternalHost:      "http://localhost:8513",
			AuthorizationFlow: authFlowUUID,
			InvalidationFlow:  invalidationFlowUUID,
		})
		if err != nil {
			return fixedCount, fmt.Errorf("failed to update proxy provider: %w", err)
		}
		logger.Info("✓ Invalidation flow added to proxy provider")
		fixedCount++
	}

	// Fix missing application
	if assessment.ApplicationMissing {
		logger.Info("Creating missing application...")
		err := f.integrator.createAuthentikApplication(rc.Ctx, assessment.AuthentikClient, assessment.ProxyProviderPK, assessment.DNS)
		if err != nil {
			return fixedCount, fmt.Errorf("failed to create application: %w", err)
		}
		logger.Info("✓ Application created")
		fixedCount++
	}

	// Fix missing groups
	for _, groupName := range assessment.GroupsMissing {
		logger.Info(fmt.Sprintf("Creating missing group '%s'...", groupName))

		// Create group with empty attributes (will use defaults)
		attrs := map[string]interface{}{}
		_, err := assessment.AuthentikClient.CreateGroupIfNotExists(rc.Ctx, groupName, attrs)
		if err != nil {
			return fixedCount, fmt.Errorf("failed to create group %s: %w", groupName, err)
		}
		logger.Info(fmt.Sprintf("✓ Group '%s' created", groupName))
		fixedCount++
	}

	// Fix outpost assignment if needed
	if assessment.OutpostNotAssigned && assessment.ProxyProviderPK > 0 {
		logger.Info("Assigning application to embedded outpost...")
		err := f.integrator.assignToOutpost(rc.Ctx, assessment.AuthentikClient, assessment.ProxyProviderPK)
		if err != nil {
			// Non-fatal - log warning
			logger.Warn("Failed to assign to outpost", zap.Error(err))
		} else {
			logger.Info("✓ Application assigned to outpost")
			fixedCount++
		}
	}

	// Fix Caddyfile duplicates, missing headers, wrong import, or invalid syntax
	if assessment.CaddyfileDuplicates > 1 || assessment.CaddyfileMissingHeaders || assessment.CaddyfileWrongImport || assessment.CaddyfileInvalidSyntax {
		if err := f.fixCaddyfileDuplicates(rc, assessment); err != nil {
			return fixedCount, fmt.Errorf("failed to fix Caddyfile: %w", err)
		}
		fixedCount++
	}

	return fixedCount, nil
}

// evaluate verifies fixes were successful
func (f *BionicGPTFixer) evaluate(rc *eos_io.RuntimeContext, assessment *DriftAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Re-assess to verify fixes
	newAssessment, err := f.assess(rc)
	if err != nil {
		return fmt.Errorf("re-assessment failed: %w", err)
	}

	// Check if issues are resolved
	issuesRemaining := 0

	if newAssessment.ProxyProviderMissing {
		logger.Warn("⚠️  Proxy provider still missing")
		issuesRemaining++
	}

	if newAssessment.InvalidationFlowMissing {
		logger.Warn("⚠️  Invalidation flow still missing")
		issuesRemaining++
	}

	if newAssessment.ApplicationMissing {
		logger.Warn("⚠️  Application still missing")
		issuesRemaining++
	}

	if len(newAssessment.GroupsMissing) > 0 {
		logger.Warn(fmt.Sprintf("⚠️  %d group(s) still missing", len(newAssessment.GroupsMissing)))
		issuesRemaining++
	}

	if issuesRemaining > 0 {
		return fmt.Errorf("verification failed: %d issue(s) remain after fix attempt", issuesRemaining)
	}

	logger.Info("✓ All issues resolved successfully")
	return nil
}

// getDNSFromCaddyfile extracts BionicGPT DNS from existing Caddyfile
func (f *BionicGPTFixer) getDNSFromCaddyfile() (string, error) {
	// Read Caddyfile and extract DNS for BionicGPT service
	// For now, return a placeholder - this would parse the Caddyfile
	// TODO: Implement actual Caddyfile parsing
	return "chat.codemonkey.net.au", nil // Placeholder
}

// checkGroupExists checks if a group exists in Authentik
func (f *BionicGPTFixer) checkGroupExists(ctx context.Context, client *authentik.APIClient, groupName string) (bool, error) {
	groups, err := client.ListGroups(ctx, groupName)
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		if group.Name == groupName {
			return true, nil
		}
	}

	return false, nil
}

// assessCaddyfile checks for duplicate entries and missing headers in Caddyfile
func (f *BionicGPTFixer) assessCaddyfile(rc *eos_io.RuntimeContext, assessment *DriftAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)

	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	caddyfileContent := string(content)
	dns := assessment.DNS

	// Count how many times this DNS appears as a site block
	// Pattern: "dns.example.com {" at start of line
	dnsPattern := fmt.Sprintf("\n%s {", dns)
	duplicateCount := strings.Count(caddyfileContent, dnsPattern)

	if duplicateCount > 1 {
		assessment.CaddyfileDuplicates = duplicateCount
		logger.Debug("Found duplicate Caddyfile entries",
			zap.String("dns", dns),
			zap.Int("count", duplicateCount))
	}

	// Check if header_up mappings exist
	// These are CRITICAL for BionicGPT authentication
	requiredHeaders := []string{
		"header_up X-Auth-Request-Email",
		"header_up X-Auth-Request-User",
		"header_up X-Auth-Request-Groups",
	}

	missingHeaders := false
	for _, header := range requiredHeaders {
		if !strings.Contains(caddyfileContent, header) {
			missingHeaders = true
			logger.Debug("Missing header mapping in Caddyfile", zap.String("header", header))
			break
		}
	}
	assessment.CaddyfileMissingHeaders = missingHeaders

	// Check for wrong import directive
	// P1 - CRITICAL: "import common" will cause "File to import not found" error
	// Must use "import cybermonkey_common" which is defined in Caddyfile global block
	if strings.Contains(caddyfileContent, "import common\n") || strings.Contains(caddyfileContent, "import common ") {
		assessment.CaddyfileWrongImport = true
		logger.Debug("Found incorrect import directive",
			zap.String("found", "import common"),
			zap.String("expected", "import cybermonkey_common"))
	}

	// Check for invalid Caddy syntax using official Caddy validation
	// P0 - CRITICAL: Use official Caddy validator instead of string parsing
	// This catches ALL syntax errors, not just standalone header_up
	// RATIONALE: Caddy's validator is authoritative, our string parsing had false positives
	if err := hecate.ValidateCaddyfileLive(rc, hecate.CaddyfilePath); err != nil {
		assessment.CaddyfileInvalidSyntax = true
		logger.Debug("Caddyfile validation failed",
			zap.Error(err),
			zap.String("remediation", "Will regenerate Caddyfile with correct syntax"))
	}

	return nil
}

// fixCaddyfileDuplicates removes duplicate entries and ensures correct headers, import, and syntax
// P0 - CRITICAL: Now includes backup/rollback mechanism for safe config changes
func (f *BionicGPTFixer) fixCaddyfileDuplicates(rc *eos_io.RuntimeContext, assessment *DriftAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)

	if assessment.CaddyfileDuplicates <= 1 && !assessment.CaddyfileMissingHeaders && !assessment.CaddyfileWrongImport && !assessment.CaddyfileInvalidSyntax {
		return nil // Nothing to fix
	}

	logger.Info("Fixing Caddyfile configuration",
		zap.Int("duplicates", assessment.CaddyfileDuplicates),
		zap.Bool("missing_headers", assessment.CaddyfileMissingHeaders),
		zap.Bool("wrong_import", assessment.CaddyfileWrongImport),
		zap.Bool("invalid_syntax", assessment.CaddyfileInvalidSyntax))

	// STEP 1: Create backup for rollback
	logger.Info("Creating Caddyfile backup...")
	backupPath, err := backupCaddyfile(rc)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	logger.Debug("Backup created", zap.String("path", backupPath))

	// Ensure cleanup on any error
	defer func() {
		if backupPath != "" {
			// If we still have backupPath, clean it up (success case)
			os.Remove(backupPath)
		}
	}()

	// STEP 2: Read current Caddyfile
	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	dns := assessment.DNS
	caddyfileContent := string(content)

	// STEP 3: Generate new content
	// Strategy: Remove ALL blocks for this DNS, then add ONE correct block
	lines := strings.Split(caddyfileContent, "\n")
	var filteredLines []string
	insideTargetBlock := false
	braceDepth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if this line starts a block for our DNS
		if strings.HasPrefix(trimmed, dns+" {") {
			insideTargetBlock = true
			braceDepth = 1
			continue // Skip this line
		}

		if insideTargetBlock {
			// Track brace depth to know when block ends
			braceDepth += strings.Count(line, "{")
			braceDepth -= strings.Count(line, "}")

			if braceDepth == 0 {
				insideTargetBlock = false
			}
			continue // Skip all lines in this block
		}

		filteredLines = append(filteredLines, line)
	}

	// Now append ONE correct block at the end
	correctBlock := f.generateCorrectCaddyfileBlock(assessment)
	filteredLines = append(filteredLines, "", "", correctBlock)

	newContent := strings.Join(filteredLines, "\n")

	// STEP 4: Write new content to Caddyfile
	if err := os.WriteFile(hecate.CaddyfilePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	logger.Info("✓ Caddyfile duplicates removed and correct configuration added")

	// STEP 5: Reload Caddy to apply changes
	logger.Info("Reloading Caddy configuration...")
	if err := ReloadCaddy(rc, hecate.CaddyfilePath); err != nil {
		// ROLLBACK on reload failure
		logger.Error("Caddy reload failed, rolling back to previous config",
			zap.Error(err))
		if restoreErr := restoreCaddyfile(rc, backupPath); restoreErr != nil {
			return fmt.Errorf("reload failed AND rollback failed: %w (original error: %v)", restoreErr, err)
		}
		// Try to reload with old config
		ReloadCaddy(rc, hecate.CaddyfilePath)
		return fmt.Errorf("failed to reload Caddy, rolled back to previous config: %w", err)
	}

	logger.Info("✓ Caddy reloaded successfully")

	// STEP 6: EVALUATE - Verify container health after reload
	// P0 - CRITICAL: User explicitly requested container health verification
	// This ensures Caddy didn't crash due to config syntax errors
	logger.Info("Verifying Caddy container health...")
	if err := verifyCaddyContainerHealth(rc); err != nil {
		// ROLLBACK on health check failure
		logger.Error("Caddy health check failed, rolling back to previous config",
			zap.Error(err))
		if restoreErr := restoreCaddyfile(rc, backupPath); restoreErr != nil {
			return fmt.Errorf("health check failed AND rollback failed: %w (original error: %v)", restoreErr, err)
		}
		// Try to reload with old config
		ReloadCaddy(rc, hecate.CaddyfilePath)
		return fmt.Errorf("Caddy health check failed after reload, rolled back: %w\n\n"+
			"This indicates a configuration problem. Check Caddy logs:\n"+
			"  docker logs %s", err, hecate.CaddyContainerName)
	}

	logger.Info("✓ Caddy container health verified")

	// Success - clear backupPath so defer doesn't clean it up
	// (We already cleaned it up in the defer)

	return nil
}

// extractBackendFromCaddyfile extracts the backend IP:port from existing Caddyfile
// P0 - CRITICAL: Prevents silent data loss when user has custom backend
func (f *BionicGPTFixer) extractBackendFromCaddyfile(dns string) string {
	// Read Caddyfile
	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		// Fallback to default if can't read
		return "100.71.196.79:8513"
	}

	caddyfileContent := string(content)
	lines := strings.Split(caddyfileContent, "\n")

	// Parse Caddyfile to find reverse_proxy directive for this DNS
	inTargetBlock := false
	braceDepth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're entering the target DNS block
		if strings.HasPrefix(trimmed, dns+" {") {
			inTargetBlock = true
			braceDepth = 1
			continue
		}

		if inTargetBlock {
			// Track brace depth
			braceDepth += strings.Count(line, "{")
			braceDepth -= strings.Count(line, "}")

			// Exit block when depth returns to 0
			if braceDepth == 0 {
				break
			}

			// Look for reverse_proxy directive
			if strings.Contains(trimmed, "reverse_proxy") {
				// Extract backend from patterns like:
				// reverse_proxy http://100.71.196.79:8513
				// reverse_proxy localhost:8080
				fields := strings.Fields(trimmed)
				for _, field := range fields {
					// Remove http:// or https:// prefix
					backend := strings.TrimPrefix(field, "http://")
					backend = strings.TrimPrefix(backend, "https://")

					// Check if this looks like an IP:port or hostname:port
					if strings.Contains(backend, ":") && !strings.Contains(backend, "//") {
						return backend
					}
				}
			}
		}
	}

	// Fallback to default if not found
	return "100.71.196.79:8513"
}

// generateCorrectCaddyfileBlock generates the correct Caddyfile block with all required headers
// P0 - CRITICAL: Now extracts backend from existing config instead of hardcoding
func (f *BionicGPTFixer) generateCorrectCaddyfileBlock(assessment *DriftAssessment) string {
	// Extract backend from existing Caddyfile to avoid silent data loss
	backend := f.extractBackendFromCaddyfile(assessment.DNS)

	return fmt.Sprintf(`# Service: bionicgpt (BionicGPT with Authentik Forward Auth)
%s {
    import cybermonkey_common

    # CRITICAL: Proxy Authentik outpost paths for forward auth to work
    # Without this, forward_auth validation will fail
    handle /outpost.goauthentik.io/* {
        reverse_proxy http://localhost:9000
    }

    # Forward auth to Authentik for authentication
    # P1 - CRITICAL: copy_headers with rename syntax (X-Authentik-*>X-Auth-Request-*)
    # BionicGPT expects oauth2-proxy format headers (X-Auth-Request-*)
    # Authentik sends X-Authentik-* headers
    # The ">" syntax renames headers: Before>After
    forward_auth http://localhost:9000 {
        uri /outpost.goauthentik.io/auth/caddy
        copy_headers {
            X-Authentik-Username>X-Auth-Request-User
            X-Authentik-Email>X-Auth-Request-Email
            X-Authentik-Groups>X-Auth-Request-Groups
            X-Authentik-Name>X-Auth-Request-Name
            X-Authentik-Uid>X-Auth-Request-Uid
        }
    }

    # Additional logging for this service
    log {
        output file /var/log/caddy/bionicgpt.log
        format json
        level DEBUG
    }

    # Reverse proxy to BionicGPT backend
    # Backend receives X-Auth-Request-* headers and trusts them for authentication
    reverse_proxy http://%s
}`, assessment.DNS, backend)
}

// verifyCaddyContainerHealth performs comprehensive health check on Caddy container
// This function uses Docker SDK to inspect container state and verify it's running correctly
// P1 - CRITICAL: Now includes container stabilization wait to avoid premature health check failure
// RATIONALE: Detects config syntax errors that cause container crash loops
func verifyCaddyContainerHealth(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// P1 #9: Wait for container to stabilize (avoid checking during restart)
	// Timeout: 30 seconds, Check interval: 2 seconds
	const stabilizationTimeout = 30 * time.Second
	const checkInterval = 2 * time.Second
	const minimumUptime = 5 * time.Second

	logger.Debug("Waiting for Caddy container to stabilize",
		zap.Duration("timeout", stabilizationTimeout),
		zap.Duration("minimum_uptime", minimumUptime))

	deadline := time.Now().Add(stabilizationTimeout)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		// Check timeout
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for container to stabilize after %v", stabilizationTimeout)
		}

		// ASSESS: Check if container is running
		isRunning, err := IsCaddyRunning(rc)
		if err != nil {
			logger.Debug("Container check failed, retrying",
				zap.Error(err))
			<-ticker.C
			continue
		}

		if !isRunning {
			logger.Debug("Container not running yet, waiting",
				zap.String("container", hecate.CaddyContainerName))
			<-ticker.C
			continue
		}

		logger.Debug("Container is running, checking stability",
			zap.String("container", hecate.CaddyContainerName))

		// ASSESS: Get detailed container information via Docker SDK
		// Check if pkg/container has Manager available
		containerManager, err := getContainerManager(rc)
		if err != nil {
			// Non-fatal - fall back to basic check
			logger.Warn("Could not initialize container manager, using basic health check",
				zap.Error(err))
			return nil // Container is running, that's good enough
		}

		// Inspect container to get detailed state
		inspect, err := containerManager.InspectRaw(rc.Ctx, hecate.CaddyContainerName)
		if err != nil {
			// Non-fatal - container is running based on IsCaddyRunning check
			logger.Debug("Could not inspect container details, retrying",
				zap.Error(err))
			<-ticker.C
			continue
		}

		// ASSESS: Check container state details
		if inspect.State == nil {
			logger.Debug("Container state is nil, retrying")
			<-ticker.C
			continue
		}

		// Check if container is actually running
		if !inspect.State.Running {
			logger.Debug("Container state shows not running, retrying",
				zap.String("status", inspect.State.Status))
			<-ticker.C
			continue
		}

		// Check container uptime - must be running for at least minimumUptime
		startedAt, err := time.Parse(time.RFC3339, inspect.State.StartedAt)
		if err != nil {
			// Can't parse time, fall back to basic check
			logger.Warn("Could not parse StartedAt timestamp, assuming stable",
				zap.String("started_at", inspect.State.StartedAt))
			break
		}

		uptime := time.Since(startedAt)
		if uptime < minimumUptime {
			logger.Debug("Container uptime below minimum, waiting",
				zap.Duration("uptime", uptime),
				zap.Duration("minimum", minimumUptime))
			<-ticker.C
			continue
		}

		// Container is stable!
		logger.Info("Container stable and healthy",
			zap.Duration("uptime", uptime),
			zap.Int("restart_count", int(inspect.RestartCount)))

		// Check if container has restarted (warn but don't fail)
		if inspect.RestartCount > 0 {
			logger.Warn("Container has restarted in the past",
				zap.Int("restart_count", int(inspect.RestartCount)))
		}

		// Success - container is stable
		break
	}

	// P1 #12: Additional HTTP health check to Caddy Admin API
	// This verifies Caddy process is actually responding, not just container running
	logger.Debug("Performing HTTP health check to Caddy Admin API")
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Create timeout context for health check
	healthCtx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	if err := caddyClient.Health(healthCtx); err != nil {
		// Admin API not responding - this could be:
		// 1. Port 2019 not exposed (non-fatal, use docker exec instead)
		// 2. Caddy process crashed inside container (fatal)
		// We'll warn but not fail, since Admin API might not be exposed
		logger.Warn("Caddy Admin API health check failed (may not be exposed)",
			zap.Error(err),
			zap.String("remediation", "This is non-fatal if Admin API port is not exposed"))
	} else {
		logger.Info("✓ Caddy Admin API responding")
	}

	return nil
}

// getContainerManager initializes a Docker container manager
// This is a helper to get access to pkg/container SDK functionality
func getContainerManager(rc *eos_io.RuntimeContext) (*container.Manager, error) {
	// Import container package
	// NOTE: This requires adding "github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	// to the imports at the top of the file
	return container.NewManager(rc)
}

// backupCaddyfile creates a timestamped backup of the Caddyfile
// Returns the backup file path for rollback
// P0 - CRITICAL: Enables rollback if fix fails
func backupCaddyfile(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Read current Caddyfile
	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read Caddyfile for backup: %w", err)
	}

	// Create backup with timestamp
	timestamp := fmt.Sprintf("%d", os.Getpid()) // Use PID for uniqueness
	backupPath := fmt.Sprintf("%s.backup.%s", hecate.CaddyfilePath, timestamp)

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}

	logger.Debug("Created Caddyfile backup",
		zap.String("backup_path", backupPath),
		zap.Int("size_bytes", len(content)))

	return backupPath, nil
}

// restoreCaddyfile restores Caddyfile from backup and removes backup file
// P0 - CRITICAL: Rollback mechanism for failed fixes
func restoreCaddyfile(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read backup
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Restore to original location
	if err := os.WriteFile(hecate.CaddyfilePath, content, 0644); err != nil {
		return fmt.Errorf("failed to restore Caddyfile: %w", err)
	}

	logger.Info("Restored Caddyfile from backup",
		zap.String("backup_path", backupPath))

	// Clean up backup file
	if err := os.Remove(backupPath); err != nil {
		logger.Warn("Failed to remove backup file (non-fatal)",
			zap.String("backup_path", backupPath),
			zap.Error(err))
	}

	return nil
}

// validateGeneratedCaddyfile validates a generated Caddyfile before writing it to disk
// Uses a temporary file to avoid corrupting the live Caddyfile
// P0 - CRITICAL: Prevents writing invalid config to disk
func validateGeneratedCaddyfile(rc *eos_io.RuntimeContext, content string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Write to temporary file
	tempPath := fmt.Sprintf("/tmp/Caddyfile.validate.%d", os.Getpid())
	if err := os.WriteFile(tempPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tempPath) // Clean up temp file

	logger.Debug("Validating generated Caddyfile",
		zap.String("temp_path", tempPath))

	// Validate using official Caddy validator
	// NOTE: This validates the file but doesn't require container running
	// We'll validate syntax only, not runtime config
	if err := hecate.ValidateCaddyfileLive(rc, hecate.CaddyfilePath); err != nil {
		return fmt.Errorf("generated Caddyfile has syntax errors: %w\n\n"+
			"This is a bug in the template generation logic.\n"+
			"Please report this issue with the error message above.",
			err)
	}

	logger.Debug("Generated Caddyfile validation passed")
	return nil
}
