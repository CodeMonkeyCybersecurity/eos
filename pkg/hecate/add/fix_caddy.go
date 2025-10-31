// pkg/hecate/add/fix_caddy.go - Drift correction for Caddy configuration
//
// P0 FIX: Connection Reset to Caddy Admin API
// ROOT CAUSE: Two issues preventing host→container Admin API communication
//   1. Network name mismatch: Docker Compose prefixes network names
//   2. Admin API binding: Caddy binds to localhost:2019 (127.0.0.1 only) inside container
//
// SOLUTION: This fixer applies both fixes to existing deployments
//   1. Updates docker-compose.yml with explicit network name
//   2. Updates Caddyfile with admin 0.0.0.0:2019 binding
//   3. Restarts Caddy container to apply changes
//
// ARCHITECTURE: "Shift Left" - Template fixes prevent issue in new deployments
//               This fixer corrects existing deployments
//
// EVIDENCE: User diagnostic showed connection refused to 172.21.0.3:2019
//           Network named "hecate_hecate-net" instead of "hecate-net"

package add

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CaddyFixer implements ServiceFixer for Caddy configuration drift correction
type CaddyFixer struct{}

// init registers the Caddy fixer
func init() {
	RegisterServiceFixer("caddy", func() ServiceFixer {
		return &CaddyFixer{}
	})
}

// Fix corrects Caddy configuration drift
// PATTERN: Assess → Intervene → Evaluate
func (f *CaddyFixer) Fix(rc *eos_io.RuntimeContext, opts *FixOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Caddy configuration drift correction",
		zap.Bool("dry_run", opts.DryRun))

	// ASSESS: Check current configuration state
	issues, err := f.assessCaddyConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to assess Caddy configuration: %w", err)
	}

	if len(issues) == 0 {
		logger.Info("✓ No Caddy configuration drift detected - all checks passed")
		return nil
	}

	// Log detected issues
	logger.Warn("Detected Caddy configuration drift",
		zap.Int("issue_count", len(issues)))
	for i, issue := range issues {
		logger.Warn(fmt.Sprintf("Issue %d: %s", i+1, issue),
			zap.String("type", "drift"))
	}

	if opts.DryRun {
		logger.Info("DRY RUN: Would fix the following issues:")
		for i, issue := range issues {
			logger.Info(fmt.Sprintf("  %d. %s", i+1, issue))
		}
		logger.Info("Run without --dry-run to apply fixes")
		return nil
	}

	// INTERVENE: Apply fixes
	logger.Info("Applying Caddy configuration fixes")

	if err := f.applyCaddyFixes(rc, issues); err != nil {
		return fmt.Errorf("failed to apply Caddy fixes: %w", err)
	}

	// EVALUATE: Verify fixes
	logger.Info("Verifying Caddy configuration fixes")

	remainingIssues, err := f.assessCaddyConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to verify fixes: %w", err)
	}

	if len(remainingIssues) > 0 {
		logger.Warn("Some issues remain after fixes",
			zap.Int("remaining_issues", len(remainingIssues)))
		for i, issue := range remainingIssues {
			logger.Warn(fmt.Sprintf("Remaining issue %d: %s", i+1, issue))
		}
		return fmt.Errorf("configuration drift correction incomplete - %d issues remain", len(remainingIssues))
	}

	logger.Info("✓ Caddy configuration drift correction completed successfully")
	return nil
}

// assessCaddyConfig checks for configuration drift
func (f *CaddyFixer) assessCaddyConfig(rc *eos_io.RuntimeContext) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	var issues []string

	logger.Debug("Assessing Caddy configuration")

	// Check 1: Caddyfile admin API binding
	caddyfilePath := filepath.Join(hecate.BaseDir, "Caddyfile")
	caddyfileContent, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	if !strings.Contains(string(caddyfileContent), "admin 0.0.0.0:2019") {
		issues = append(issues, "Caddyfile missing 'admin 0.0.0.0:2019' binding (Admin API only accessible from localhost)")
	}

	// Check 2: docker-compose.yml network configuration
	composeFilePath := filepath.Join(hecate.BaseDir, "docker-compose.yml")
	composeContent, err := os.ReadFile(composeFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	if !strings.Contains(string(composeContent), "name: hecate-net") {
		issues = append(issues, "docker-compose.yml missing explicit 'name: hecate-net' (Docker Compose will prefix network name)")
	}

	logger.Debug("Configuration assessment complete",
		zap.Int("issues_found", len(issues)))

	return issues, nil
}

// applyCaddyFixes applies configuration fixes
func (f *CaddyFixer) applyCaddyFixes(rc *eos_io.RuntimeContext, issues []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Fix 1: Update Caddyfile
	if f.needsCaddyfileAdminFix(issues) {
		logger.Info("Fixing Caddyfile admin API binding")
		if err := f.fixCaddyfileAdmin(rc); err != nil {
			return fmt.Errorf("failed to fix Caddyfile: %w", err)
		}
		logger.Info("✓ Caddyfile admin API binding fixed")
	}

	// Fix 2: Update docker-compose.yml
	if f.needsDockerComposeNetworkFix(issues) {
		logger.Info("Fixing docker-compose.yml network name")
		if err := f.fixDockerComposeNetwork(rc); err != nil {
			return fmt.Errorf("failed to fix docker-compose.yml: %w", err)
		}
		logger.Info("✓ docker-compose.yml network name fixed")
	}

	// Fix 3: Restart Caddy container to apply changes
	logger.Info("Restarting Caddy container to apply configuration changes")
	if err := f.restartCaddyContainer(rc); err != nil {
		return fmt.Errorf("failed to restart Caddy: %w", err)
	}
	logger.Info("✓ Caddy container restarted successfully")

	return nil
}

// needsCaddyfileAdminFix checks if Caddyfile needs admin binding fix
func (f *CaddyFixer) needsCaddyfileAdminFix(issues []string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, "Caddyfile missing 'admin 0.0.0.0:2019'") {
			return true
		}
	}
	return false
}

// needsDockerComposeNetworkFix checks if docker-compose.yml needs network name fix
func (f *CaddyFixer) needsDockerComposeNetworkFix(issues []string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, "docker-compose.yml missing explicit 'name: hecate-net'") {
			return true
		}
	}
	return false
}

// fixCaddyfileAdmin adds admin 0.0.0.0:2019 to Caddyfile global block
func (f *CaddyFixer) fixCaddyfileAdmin(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	caddyfilePath := filepath.Join(hecate.BaseDir, "Caddyfile")

	// Read existing Caddyfile
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	contentStr := string(content)

	// Find global block opening
	globalBlockStart := strings.Index(contentStr, "{")
	if globalBlockStart == -1 {
		return fmt.Errorf("Caddyfile has no global block - cannot apply fix automatically")
	}

	// Find line after opening brace
	lineAfterBrace := globalBlockStart + 1
	for lineAfterBrace < len(contentStr) && (contentStr[lineAfterBrace] == '\n' || contentStr[lineAfterBrace] == '\r') {
		lineAfterBrace++
	}

	// Insert admin binding with documentation
	adminConfig := `	# Admin API binding (P0 FIX - Connection Reset)
	# ROOT CAUSE: Default binding (localhost:2019) only listens on 127.0.0.1 inside container
	#             Host cannot connect to container's localhost → connection refused
	# SOLUTION: Bind to 0.0.0.0:2019 to listen on all interfaces including bridge network
	# SECURITY: Admin API still protected by Docker network isolation
	#           Only accessible from: container localhost, host machine, same bridge network
	#           NOT accessible from external networks (no port publish in docker-compose)
	# APPLIED: eos update hecate --fix caddy
	admin 0.0.0.0:2019

`

	newContent := contentStr[:lineAfterBrace] + adminConfig + contentStr[lineAfterBrace:]

	// Backup existing Caddyfile
	backupPath := caddyfilePath + ".backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		logger.Warn("Failed to create Caddyfile backup", zap.Error(err))
	} else {
		logger.Debug("Created Caddyfile backup", zap.String("path", backupPath))
	}

	// Write updated Caddyfile
	if err := os.WriteFile(caddyfilePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	logger.Info("Updated Caddyfile with admin 0.0.0.0:2019 binding")

	return nil
}

// fixDockerComposeNetwork adds explicit network name to docker-compose.yml
func (f *CaddyFixer) fixDockerComposeNetwork(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	composeFilePath := filepath.Join(hecate.BaseDir, "docker-compose.yml")

	// Read existing docker-compose.yml
	content, err := os.ReadFile(composeFilePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	contentStr := string(content)

	// Find networks section
	networksSection := "networks:\n  hecate-net:"
	networksIdx := strings.Index(contentStr, networksSection)
	if networksIdx == -1 {
		return fmt.Errorf("docker-compose.yml has no 'networks: hecate-net:' section - cannot apply fix automatically")
	}

	// Find end of hecate-net network definition (next top-level key or end of file)
	insertIdx := networksIdx + len(networksSection)

	// Insert explicit network name with documentation
	networkConfig := `
    # P0 FIX - Network Name Mismatch
    # ROOT CAUSE: Docker Compose prefixes network names with project name
    #   Without explicit name: "hecate_hecate-net" (project_network format)
    #   With explicit name: "hecate-net" (exactly as specified)
    # SOLUTION: Set explicit name to prevent Docker Compose prefixing
    # RATIONALE: Docker SDK code expects "hecate-net", not "hecate_hecate-net"
    # APPLIED: eos update hecate --fix caddy
    name: hecate-net
    driver: bridge`

	newContent := contentStr[:insertIdx] + networkConfig + contentStr[insertIdx:]

	// Backup existing docker-compose.yml
	backupPath := composeFilePath + ".backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		logger.Warn("Failed to create docker-compose.yml backup", zap.Error(err))
	} else {
		logger.Debug("Created docker-compose.yml backup", zap.String("path", backupPath))
	}

	// Write updated docker-compose.yml
	if err := os.WriteFile(composeFilePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	logger.Info("Updated docker-compose.yml with explicit network name")

	return nil
}

// restartCaddyContainer restarts the Caddy container to apply configuration changes
func (f *CaddyFixer) restartCaddyContainer(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use docker compose to restart Caddy service
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", filepath.Join(hecate.BaseDir, "docker-compose.yml"), "restart", "caddy"},
		Dir:     hecate.BaseDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("docker compose restart failed: %w\nOutput: %s", err, output)
	}

	logger.Debug("Docker compose restart output", zap.String("output", strings.TrimSpace(output)))

	return nil
}
