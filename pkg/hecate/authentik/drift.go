// pkg/hecate/authentik/drift.go
// Configuration drift detection and reconciliation

package authentik

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DriftReport represents configuration drift between disk and runtime
type DriftReport struct {
	GeneratedAt     time.Time
	CaddyDrift      *CaddyDrift
	DockerDrift     *DockerDrift
	Summary         DriftSummary
	Recommendations []string
}

// CaddyDrift represents differences between disk Caddyfile and live API config
type CaddyDrift struct {
	DiskRoutes    []string // Routes defined in disk Caddyfile
	LiveRoutes    []string // Routes in Caddy Admin API
	AddedRoutes   []string // Routes added via API (not in disk)
	RemovedRoutes []string // Routes in disk but not live
	Modified      []string // Routes that exist but differ
}

// DockerDrift represents differences between docker-compose.yml and runtime
type DockerDrift struct {
	DiskContainers    []string                  // Containers defined in compose file
	RuntimeContainers []string                  // Running containers
	AddedContainers   []string                  // Containers running but not in compose
	RemovedContainers []string                  // Containers in compose but not running
	EnvDiff           map[string][]EnvVarChange // Per-container env var changes
	VolumeDiff        map[string][]VolumeChange // Per-container volume changes
	PortDiff          map[string][]PortChange   // Per-container port changes
}

// EnvVarChange represents a change in environment variable
type EnvVarChange struct {
	Variable string
	DiskVal  string // Value in docker-compose.yml
	LiveVal  string // Value in running container
	Type     string // "added", "removed", "modified"
}

// VolumeChange represents a change in volume mount
type VolumeChange struct {
	Source      string
	Destination string
	Type        string // "added", "removed", "modified"
}

// PortChange represents a change in port binding
type PortChange struct {
	HostPort      string
	ContainerPort string
	Protocol      string
	Type          string // "added", "removed", "modified"
}

// DriftSummary provides high-level drift statistics
type DriftSummary struct {
	TotalDriftIssues   int
	CaddyDriftCount    int
	DockerDriftCount   int
	CriticalIssues     []string
	RecommendedActions []string
	DriftPercentage    float64 // 0-100, how much configuration has drifted
}

// DetectDrift analyzes exported configuration and generates drift report
func DetectDrift(rc *eos_io.RuntimeContext, exportDir string) (*DriftReport, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting configuration drift analysis",
		zap.String("export_dir", exportDir))

	report := &DriftReport{
		GeneratedAt: time.Now(),
	}

	// Analyze Caddy drift
	caddyDrift, err := analyzeCaddyDrift(rc, exportDir)
	if err != nil {
		logger.Warn("Failed to analyze Caddy drift", zap.Error(err))
		// Continue with Docker analysis even if Caddy fails
	} else {
		report.CaddyDrift = caddyDrift
	}

	// Analyze Docker drift
	dockerDrift, err := analyzeDockerDrift(rc, exportDir)
	if err != nil {
		logger.Warn("Failed to analyze Docker drift", zap.Error(err))
	} else {
		report.DockerDrift = dockerDrift
	}

	// Generate summary
	report.Summary = generateDriftSummary(report)

	// Generate recommendations
	report.Recommendations = generateRecommendations(report)

	logger.Info("Drift analysis complete",
		zap.Int("total_issues", report.Summary.TotalDriftIssues),
		zap.Float64("drift_percentage", report.Summary.DriftPercentage))

	return report, nil
}

// analyzeCaddyDrift compares disk Caddyfile with live Caddy API config
func analyzeCaddyDrift(rc *eos_io.RuntimeContext, exportDir string) (*CaddyDrift, error) {
	logger := otelzap.Ctx(rc.Ctx)

	drift := &CaddyDrift{
		DiskRoutes:    []string{},
		LiveRoutes:    []string{},
		AddedRoutes:   []string{},
		RemovedRoutes: []string{},
		Modified:      []string{},
	}

	// Read disk Caddyfile
	diskPath := filepath.Join(exportDir, "19_Caddyfile.disk")
	diskData, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read disk Caddyfile: %w", err)
	}

	// Parse disk Caddyfile to extract routes (simple line-based parsing)
	drift.DiskRoutes = parseCaddyfileRoutes(string(diskData))

	// Read live Caddy config (JSON format)
	livePath := filepath.Join(exportDir, "19_Caddyfile.live.json")
	liveData, err := os.ReadFile(livePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read live Caddy config: %w", err)
	}

	// Parse JSON to extract routes
	var caddyConfig map[string]interface{}
	if err := json.Unmarshal(liveData, &caddyConfig); err != nil {
		return nil, fmt.Errorf("failed to parse Caddy JSON: %w", err)
	}

	drift.LiveRoutes = extractCaddyAPIRoutes(caddyConfig)

	// Calculate differences
	diskSet := stringSliceToSet(drift.DiskRoutes)
	liveSet := stringSliceToSet(drift.LiveRoutes)

	// Routes added via API (in live but not disk)
	for route := range liveSet {
		if !diskSet[route] {
			drift.AddedRoutes = append(drift.AddedRoutes, route)
		}
	}

	// Routes removed (in disk but not live)
	for route := range diskSet {
		if !liveSet[route] {
			drift.RemovedRoutes = append(drift.RemovedRoutes, route)
		}
	}

	// Sort for consistent output
	sort.Strings(drift.AddedRoutes)
	sort.Strings(drift.RemovedRoutes)

	logger.Info("Caddy drift analysis complete",
		zap.Int("disk_routes", len(drift.DiskRoutes)),
		zap.Int("live_routes", len(drift.LiveRoutes)),
		zap.Int("added", len(drift.AddedRoutes)),
		zap.Int("removed", len(drift.RemovedRoutes)))

	return drift, nil
}

// analyzeDockerDrift compares docker-compose.yml with running containers
func analyzeDockerDrift(rc *eos_io.RuntimeContext, exportDir string) (*DockerDrift, error) {
	logger := otelzap.Ctx(rc.Ctx)

	drift := &DockerDrift{
		DiskContainers:    []string{},
		RuntimeContainers: []string{},
		AddedContainers:   []string{},
		RemovedContainers: []string{},
		EnvDiff:           make(map[string][]EnvVarChange),
		VolumeDiff:        make(map[string][]VolumeChange),
		PortDiff:          make(map[string][]PortChange),
	}

	// Read runtime container data
	runtimePath := filepath.Join(exportDir, "20_docker-compose.runtime.json")
	runtimeData, err := os.ReadFile(runtimePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read runtime container data: %w", err)
	}

	var containers []types.ContainerJSON
	if err := json.Unmarshal(runtimeData, &containers); err != nil {
		return nil, fmt.Errorf("failed to parse runtime container data: %w", err)
	}

	// Extract runtime container names
	for _, c := range containers {
		// Remove leading '/' from container name
		name := strings.TrimPrefix(c.Name, "/")
		drift.RuntimeContainers = append(drift.RuntimeContainers, name)
	}

	// Read disk docker-compose.yml
	diskPath := filepath.Join(exportDir, "20_docker-compose.disk.yml")
	diskData, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read disk docker-compose.yml: %w", err)
	}

	// Parse docker-compose.yml to extract service names (simple line-based parsing)
	drift.DiskContainers = parseComposeServiceNames(string(diskData))

	// Calculate differences
	diskSet := stringSliceToSet(drift.DiskContainers)
	runtimeSet := stringSliceToSet(drift.RuntimeContainers)

	// Containers added (running but not in compose)
	for container := range runtimeSet {
		if !diskSet[container] {
			drift.AddedContainers = append(drift.AddedContainers, container)
		}
	}

	// Containers removed (in compose but not running)
	for container := range diskSet {
		if !runtimeSet[container] {
			drift.RemovedContainers = append(drift.RemovedContainers, container)
		}
	}

	// Analyze environment variable drift for matching containers
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		if diskSet[name] {
			// Container exists in both - check for env changes
			envChanges := detectEnvVarChanges(c.Config.Env, string(diskData), name)
			if len(envChanges) > 0 {
				drift.EnvDiff[name] = envChanges
			}
		}
	}

	// Sort for consistent output
	sort.Strings(drift.AddedContainers)
	sort.Strings(drift.RemovedContainers)

	logger.Info("Docker drift analysis complete",
		zap.Int("disk_services", len(drift.DiskContainers)),
		zap.Int("runtime_containers", len(drift.RuntimeContainers)),
		zap.Int("added", len(drift.AddedContainers)),
		zap.Int("removed", len(drift.RemovedContainers)),
		zap.Int("env_diffs", len(drift.EnvDiff)))

	return drift, nil
}

// parseCaddyfileRoutes extracts domain/route definitions from Caddyfile
func parseCaddyfileRoutes(content string) []string {
	routes := []string{}
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Match lines that look like domain definitions (end with {)
		if strings.Contains(line, "{") && !strings.HasPrefix(line, "#") {
			// Extract domain before '{'
			parts := strings.Split(line, "{")
			if len(parts) > 0 {
				domain := strings.TrimSpace(parts[0])
				// Filter out non-domain lines (handle, log, etc.)
				if !strings.HasPrefix(domain, "handle") &&
					!strings.HasPrefix(domain, "log") &&
					!strings.HasPrefix(domain, "import") &&
					!strings.HasPrefix(domain, "reverse_proxy") &&
					domain != "" {
					routes = append(routes, domain)
				}
			}
		}
	}

	return routes
}

// extractCaddyAPIRoutes extracts route domains from Caddy JSON config
func extractCaddyAPIRoutes(config map[string]interface{}) []string {
	routes := []string{}

	// Navigate to HTTP routes: apps.http.servers.srv0.routes
	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return routes
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return routes
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return routes
	}

	srv0, ok := servers["srv0"].(map[string]interface{})
	if !ok {
		return routes
	}

	routesList, ok := srv0["routes"].([]interface{})
	if !ok {
		return routes
	}

	// Extract domains from routes
	for _, r := range routesList {
		route, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Get match conditions
		matches, ok := route["match"].([]interface{})
		if !ok || len(matches) == 0 {
			continue
		}

		// Extract host from first match
		firstMatch, ok := matches[0].(map[string]interface{})
		if !ok {
			continue
		}

		hosts, ok := firstMatch["host"].([]interface{})
		if !ok || len(hosts) == 0 {
			continue
		}

		// Add first host as route identifier
		if host, ok := hosts[0].(string); ok {
			routes = append(routes, host)
		}
	}

	return routes
}

// parseComposeServiceNames extracts service names from docker-compose.yml
func parseComposeServiceNames(content string) []string {
	services := []string{}
	lines := strings.Split(content, "\n")
	inServicesSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect services: section
		if trimmed == "services:" {
			inServicesSection = true
			continue
		}

		// Exit services section if we hit another top-level key
		if inServicesSection && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
			inServicesSection = false
		}

		// Extract service names (2-space or tab indented, ends with :)
		if inServicesSection && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) {
			parts := strings.Split(trimmed, ":")
			if len(parts) > 0 && !strings.Contains(parts[0], " ") {
				serviceName := strings.TrimSpace(parts[0])
				// Filter out property keys (image, environment, etc.)
				if serviceName != "image" && serviceName != "environment" &&
					serviceName != "ports" && serviceName != "volumes" &&
					serviceName != "depends_on" && serviceName != "container_name" &&
					serviceName != "restart" && serviceName != "command" &&
					serviceName != "networks" && serviceName != "labels" {
					services = append(services, serviceName)
				}
			}
		}
	}

	return services
}

// detectEnvVarChanges compares runtime env vars with disk compose file
// NOTE: This is a simplified comparison - full implementation would parse YAML
func detectEnvVarChanges(runtimeEnv []string, diskContent string, containerName string) []EnvVarChange {
	changes := []EnvVarChange{}

	// Build map of runtime env vars
	runtimeMap := make(map[string]string)
	for _, env := range runtimeEnv {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			runtimeMap[parts[0]] = parts[1]
		}
	}

	// Look for critical env vars that commonly drift
	criticalVars := []string{
		"AUTHENTIK_SECRET_KEY",
		"AUTHENTIK_POSTGRESQL__PASSWORD",
		"AUTHENTIK_BOOTSTRAP_TOKEN",
		"AUTHENTIK_PROXY__TRUSTED_IPS",
		"AUTHENTIK_HOST",
	}

	for _, varName := range criticalVars {
		if val, exists := runtimeMap[varName]; exists {
			// Check if var is in disk compose
			if !strings.Contains(diskContent, varName) {
				changes = append(changes, EnvVarChange{
					Variable: varName,
					DiskVal:  "(not set)",
					LiveVal:  val,
					Type:     "added",
				})
			}
		}
	}

	return changes
}

// generateDriftSummary creates high-level drift statistics
func generateDriftSummary(report *DriftReport) DriftSummary {
	summary := DriftSummary{
		CriticalIssues:     []string{},
		RecommendedActions: []string{},
	}

	// Count Caddy drift issues
	if report.CaddyDrift != nil {
		summary.CaddyDriftCount = len(report.CaddyDrift.AddedRoutes) +
			len(report.CaddyDrift.RemovedRoutes) +
			len(report.CaddyDrift.Modified)
	}

	// Count Docker drift issues
	if report.DockerDrift != nil {
		summary.DockerDriftCount = len(report.DockerDrift.AddedContainers) +
			len(report.DockerDrift.RemovedContainers) +
			len(report.DockerDrift.EnvDiff)
	}

	summary.TotalDriftIssues = summary.CaddyDriftCount + summary.DockerDriftCount

	// Calculate drift percentage (0-100)
	// Simplified calculation: each issue = 10% drift (capped at 100%)
	summary.DriftPercentage = float64(summary.TotalDriftIssues) * 10.0
	if summary.DriftPercentage > 100.0 {
		summary.DriftPercentage = 100.0
	}

	// Identify critical issues
	if report.CaddyDrift != nil && len(report.CaddyDrift.AddedRoutes) > 0 {
		summary.CriticalIssues = append(summary.CriticalIssues,
			fmt.Sprintf("Routes added via Caddy API not in disk Caddyfile (%d routes)", len(report.CaddyDrift.AddedRoutes)))
	}

	if report.DockerDrift != nil && len(report.DockerDrift.EnvDiff) > 0 {
		summary.CriticalIssues = append(summary.CriticalIssues,
			fmt.Sprintf("Environment variables differ between compose and runtime (%d containers)", len(report.DockerDrift.EnvDiff)))
	}

	return summary
}

// generateRecommendations creates actionable remediation steps
func generateRecommendations(report *DriftReport) []string {
	recommendations := []string{}

	if report.CaddyDrift != nil {
		if len(report.CaddyDrift.AddedRoutes) > 0 {
			recommendations = append(recommendations,
				"Add missing routes to /opt/hecate/Caddyfile to prevent loss on reload")
			// PRECIPITATE PATTERN: Query EXISTING RUNNING state → DOCUMENT as declarative .yml
			// For Caddy: GET /config via Admin API → Convert JSON to Caddyfile → DISPLAY (not write)
			// For Docker: docker inspect containers → Generate docker-compose.yml → DISPLAY (not write)
			// GOAL: Show "what's actually running" in declarative format for comparison/documentation
			// NOTE: Does NOT write to disk - purely observability
			recommendations = append(recommendations,
				fmt.Sprintf("Run: eos update hecate --precipitate to document current runtime state"))
		}

		if len(report.CaddyDrift.RemovedRoutes) > 0 {
			recommendations = append(recommendations,
				"Remove stale routes from Caddyfile or reload Caddy to activate them")
			recommendations = append(recommendations,
				"Run: docker exec hecate-caddy caddy reload --config /etc/caddy/Caddyfile")
		}
	}

	if report.DockerDrift != nil {
		if len(report.DockerDrift.EnvDiff) > 0 {
			recommendations = append(recommendations,
				"Update docker-compose.yml with runtime environment variables")
			recommendations = append(recommendations,
				"Or recreate containers: cd /opt/hecate && docker compose up -d --force-recreate")
		}

		if len(report.DockerDrift.AddedContainers) > 0 {
			recommendations = append(recommendations,
				"Document manually-started containers in docker-compose.yml")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "✓ No configuration drift detected - disk and runtime are in sync")
	}

	return recommendations
}

// stringSliceToSet converts string slice to set (map[string]bool)
func stringSliceToSet(slice []string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range slice {
		set[s] = true
	}
	return set
}

// RenderDriftReport generates human-readable markdown report
func RenderDriftReport(report *DriftReport) string {
	var sb strings.Builder

	sb.WriteString("# Configuration Drift Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated**: %s\n\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Drift Issues**: %d\n", report.Summary.TotalDriftIssues))
	sb.WriteString(fmt.Sprintf("- **Drift Percentage**: %.1f%%\n", report.Summary.DriftPercentage))
	sb.WriteString(fmt.Sprintf("- **Caddy Drift**: %d issues\n", report.Summary.CaddyDriftCount))
	sb.WriteString(fmt.Sprintf("- **Docker Drift**: %d issues\n\n", report.Summary.DockerDriftCount))

	// Critical Issues
	if len(report.Summary.CriticalIssues) > 0 {
		sb.WriteString("### Critical Issues\n\n")
		for _, issue := range report.Summary.CriticalIssues {
			sb.WriteString(fmt.Sprintf("- 🔴 %s\n", issue))
		}
		sb.WriteString("\n")
	}

	// Caddy Drift Details
	if report.CaddyDrift != nil {
		sb.WriteString("## Caddy Configuration Drift\n\n")
		sb.WriteString(fmt.Sprintf("- **Disk Routes**: %d\n", len(report.CaddyDrift.DiskRoutes)))
		sb.WriteString(fmt.Sprintf("- **Live Routes**: %d\n\n", len(report.CaddyDrift.LiveRoutes)))

		if len(report.CaddyDrift.AddedRoutes) > 0 {
			sb.WriteString("### Routes Added via API (Not in Disk Caddyfile)\n\n")
			sb.WriteString("These routes exist in the live Caddy configuration but are NOT in `/opt/hecate/Caddyfile`.\n")
			sb.WriteString("**Risk**: Will be lost on `caddy reload` or container restart.\n\n")
			for _, route := range report.CaddyDrift.AddedRoutes {
				sb.WriteString(fmt.Sprintf("- `%s`\n", route))
			}
			sb.WriteString("\n")
		}

		if len(report.CaddyDrift.RemovedRoutes) > 0 {
			sb.WriteString("### Routes Removed from Live Config\n\n")
			sb.WriteString("These routes are in `/opt/hecate/Caddyfile` but NOT in live Caddy API.\n")
			sb.WriteString("**Cause**: Likely removed via Admin API or failed reload.\n\n")
			for _, route := range report.CaddyDrift.RemovedRoutes {
				sb.WriteString(fmt.Sprintf("- `%s`\n", route))
			}
			sb.WriteString("\n")
		}

		if len(report.CaddyDrift.AddedRoutes) == 0 && len(report.CaddyDrift.RemovedRoutes) == 0 {
			sb.WriteString("✓ No Caddy drift detected - disk and live configs match\n\n")
		}
	}

	// Docker Drift Details
	if report.DockerDrift != nil {
		sb.WriteString("## Docker Compose Drift\n\n")
		sb.WriteString(fmt.Sprintf("- **Disk Services**: %d\n", len(report.DockerDrift.DiskContainers)))
		sb.WriteString(fmt.Sprintf("- **Runtime Containers**: %d\n\n", len(report.DockerDrift.RuntimeContainers)))

		if len(report.DockerDrift.AddedContainers) > 0 {
			sb.WriteString("### Containers Running (Not in docker-compose.yml)\n\n")
			sb.WriteString("These containers are running but NOT defined in `/opt/hecate/docker-compose.yml`.\n")
			sb.WriteString("**Risk**: Will not restart on reboot or compose restart.\n\n")
			for _, container := range report.DockerDrift.AddedContainers {
				sb.WriteString(fmt.Sprintf("- `%s`\n", container))
			}
			sb.WriteString("\n")
		}

		if len(report.DockerDrift.RemovedContainers) > 0 {
			sb.WriteString("### Containers Missing from Runtime\n\n")
			sb.WriteString("These containers are in `docker-compose.yml` but NOT running.\n")
			sb.WriteString("**Cause**: Stopped, failed, or not started yet.\n\n")
			for _, container := range report.DockerDrift.RemovedContainers {
				sb.WriteString(fmt.Sprintf("- `%s`\n", container))
			}
			sb.WriteString("\n")
		}

		if len(report.DockerDrift.EnvDiff) > 0 {
			sb.WriteString("### Environment Variable Drift\n\n")
			sb.WriteString("Environment variables differ between compose file and running containers.\n\n")
			for containerName, changes := range report.DockerDrift.EnvDiff {
				sb.WriteString(fmt.Sprintf("#### Container: `%s`\n\n", containerName))
				sb.WriteString("| Variable | Disk Value | Live Value | Type |\n")
				sb.WriteString("|----------|------------|------------|------|\n")
				for _, change := range changes {
					sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n",
						change.Variable, change.DiskVal, change.LiveVal, change.Type))
				}
				sb.WriteString("\n")
			}
		}

		if len(report.DockerDrift.AddedContainers) == 0 &&
			len(report.DockerDrift.RemovedContainers) == 0 &&
			len(report.DockerDrift.EnvDiff) == 0 {
			sb.WriteString("✓ No Docker drift detected - compose and runtime match\n\n")
		}
	}

	// Recommendations
	sb.WriteString("## Recommended Actions\n\n")
	for i, rec := range report.Recommendations {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}
	sb.WriteString("\n")

	// Remediation Commands
	sb.WriteString("## Remediation Commands\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("# Option 1: Document runtime state (COMING SOON)\n")
	sb.WriteString("# PRECIPITATE: Query running state → Display as declarative config\n")
	sb.WriteString("#   - Caddy Admin API (/config) → Convert to Caddyfile format → DISPLAY\n")
	sb.WriteString("#   - Docker inspect → Convert to docker-compose.yml → DISPLAY\n")
	sb.WriteString("#   - Shows what's ACTUALLY running vs what's on disk\n")
	sb.WriteString("#   - Does NOT write files (purely observability/documentation)\n")
	sb.WriteString("eos update hecate --precipitate\n")
	sb.WriteString("# User can then manually copy output to disk files if desired\n\n")
	sb.WriteString("# Option 2: Reload Caddy from disk Caddyfile (loses API changes)\n")
	sb.WriteString("docker exec hecate-caddy caddy reload --config /etc/caddy/Caddyfile\n\n")
	sb.WriteString("# Option 3: Recreate containers from compose file\n")
	sb.WriteString("cd /opt/hecate && docker compose up -d --force-recreate\n")
	sb.WriteString("```\n\n")

	sb.WriteString("---\n")
	sb.WriteString("*Generated by EOS (Enterprise Orchestration System)*\n")

	return sb.String()
}
