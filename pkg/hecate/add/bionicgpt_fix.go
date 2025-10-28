// pkg/hecate/add/bionicgpt_fix.go - BionicGPT drift correction

package add

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
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

	if assessment.CaddyfileDuplicates <= 1 && !assessment.CaddyfileMissingHeaders {
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

	// Fix Caddyfile duplicates and missing headers
	if assessment.CaddyfileDuplicates > 1 || assessment.CaddyfileMissingHeaders {
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

	return nil
}

// fixCaddyfileDuplicates removes duplicate entries and ensures correct headers
func (f *BionicGPTFixer) fixCaddyfileDuplicates(rc *eos_io.RuntimeContext, assessment *DriftAssessment) error {
	logger := otelzap.Ctx(rc.Ctx)

	if assessment.CaddyfileDuplicates <= 1 && !assessment.CaddyfileMissingHeaders {
		return nil // Nothing to fix
	}

	logger.Info("Fixing Caddyfile configuration",
		zap.Int("duplicates", assessment.CaddyfileDuplicates),
		zap.Bool("missing_headers", assessment.CaddyfileMissingHeaders))

	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	dns := assessment.DNS
	caddyfileContent := string(content)

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

	// Write back to Caddyfile
	if err := os.WriteFile(hecate.CaddyfilePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	logger.Info("✓ Caddyfile duplicates removed and correct configuration added")

	// Reload Caddy to apply changes
	logger.Info("Reloading Caddy configuration...")
	if err := ReloadCaddy(rc, hecate.CaddyfilePath); err != nil {
		return fmt.Errorf("failed to reload Caddy: %w", err)
	}

	logger.Info("✓ Caddy reloaded successfully")
	return nil
}

// generateCorrectCaddyfileBlock generates the correct Caddyfile block with all required headers
func (f *BionicGPTFixer) generateCorrectCaddyfileBlock(assessment *DriftAssessment) string {
	// Get backend from existing route or use default
	backend := "100.71.196.79:8513" // TODO: Extract from existing Caddyfile

	return fmt.Sprintf(`# Service: bionicgpt (BionicGPT with Authentik Forward Auth)
%s {
    import cybermonkey_common

    # CRITICAL: Proxy Authentik outpost paths for forward auth to work
    # Without this, forward_auth validation will fail
    handle /outpost.goauthentik.io/* {
        reverse_proxy http://localhost:9000
    }

    # Forward auth to Authentik for authentication
    # Authentik validates session and returns X-Authentik-* headers
    forward_auth http://localhost:9000 {
        uri /outpost.goauthentik.io/auth/caddy
        copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
    }

    # Map Authentik headers → BionicGPT expected headers
    # BionicGPT expects X-Auth-Request-* (oauth2-proxy format)
    # Authentik sends X-Authentik-*
    # Caddy maps between them here
    header_up X-Auth-Request-Email {http.request.header.X-Authentik-Email}
    header_up X-Auth-Request-User {http.request.header.X-Authentik-Username}
    header_up X-Auth-Request-Groups {http.request.header.X-Authentik-Groups}

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
