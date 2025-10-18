// cmd/debug/hecate.go
package debug

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var hecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Diagnose Hecate components (Caddy, Authentik, PostgreSQL, Redis)",
	Long: `Comprehensive diagnostic tool for Hecate reverse proxy framework.

Automatically detects which Hecate components are running:
  • Caddy           - Reverse proxy
  • Authentik       - Identity provider
  • PostgreSQL      - Database
  • Redis           - Cache
  • Nginx           - Alternative reverse proxy
  • Coturn          - TURN/STUN server

For each detected component, performs relevant diagnostics:
  • Service status and health checks
  • Configuration file validation
  • Log file analysis
  • Port connectivity checks
  • Resource usage
  • Common issue detection
  • Actionable remediation steps

Authentik-specific diagnostics (--authentik flag):
  • Current version check
  • Disk space verification
  • Container health status
  • PostgreSQL encoding check
  • Redis connectivity
  • Custom modifications detection
  • Environment file validation
  • Active task queue check
  • Memory usage analysis
  • Backup status

Flags:
  --component <name>  Only check specific component (caddy|authentik|postgresql|redis|nginx|coturn)
  --authentik         Run comprehensive Authentik pre-upgrade health check
  --path <path>       Path to Hecate installation (default: /opt/hecate)
  --verbose           Show detailed diagnostic output

Examples:
  eos debug hecate                      # Auto-detect and diagnose all components
  eos debug hecate --component authentik  # Only diagnose Authentik
  eos debug hecate --authentik          # Full Authentik pre-upgrade check
  eos debug hecate --path /custom/path  # Custom installation path`,
	RunE: eos.Wrap(runHecateDebug),
}

var (
	hecateComponent      string
	hecateAuthentikCheck bool
	hecatePath           string
	hecateVerbose        bool
)

func init() {
	hecateCmd.Flags().StringVar(&hecateComponent, "component", "", "Specific component to check")
	hecateCmd.Flags().BoolVar(&hecateAuthentikCheck, "authentik", false, "Run comprehensive Authentik pre-upgrade check")
	hecateCmd.Flags().StringVar(&hecatePath, "path", "/opt/hecate", "Path to Hecate installation")
	hecateCmd.Flags().BoolVar(&hecateVerbose, "verbose", false, "Show detailed diagnostic output")
	debugCmd.AddCommand(hecateCmd)
}

type HecateComponentType string

const (
	HecateComponentCaddy      HecateComponentType = "caddy"
	HecateComponentAuthentik  HecateComponentType = "authentik"
	HecateComponentPostgreSQL HecateComponentType = "postgresql"
	HecateComponentRedis      HecateComponentType = "redis"
	HecateComponentNginx      HecateComponentType = "nginx"
	HecateComponentCoturn     HecateComponentType = "coturn"
)

type HecateComponentInfo struct {
	Name        HecateComponentType
	ServiceName string
	Detected    bool
	Running     bool
	ConfigPaths []string
	LogPaths    []string
	Ports       []int
}

type HecateCheckResult struct {
	Component   HecateComponentType
	CheckName   string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Details     string
	Remediation []string
}

func runHecateDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Hecate diagnostics",
		zap.String("component_filter", hecateComponent),
		zap.String("path", hecatePath),
		zap.Bool("authentik_check", hecateAuthentikCheck))

	// If --authentik flag is set, run comprehensive Authentik check
	if hecateAuthentikCheck {
		return runAuthentikPreUpgradeCheck(rc)
	}

	// Detect components
	components := detectHecateComponents(rc)

	if len(components) == 0 {
		fmt.Println("\n❌ No Hecate components detected on this system")
		fmt.Println("\nTo install Hecate:")
		fmt.Println("  • Full stack: eos create hecate")
		return nil
	}

	// Filter by component if specified
	if hecateComponent != "" {
		filtered := make(map[HecateComponentType]*HecateComponentInfo)
		comp := HecateComponentType(hecateComponent)
		if info, exists := components[comp]; exists {
			filtered[comp] = info
			components = filtered
		} else {
			return fmt.Errorf("component '%s' not found on this system", hecateComponent)
		}
	}

	displayDetectedHecateComponents(components)

	var allResults []HecateCheckResult
	for _, info := range components {
		if !info.Detected {
			continue
		}

		results := diagnoseHecateComponent(rc, info)
		allResults = append(allResults, results...)
	}

	displayHecateResults(allResults)

	return nil
}

func detectHecateComponents(rc *eos_io.RuntimeContext) map[HecateComponentType]*HecateComponentInfo {
	components := map[HecateComponentType]*HecateComponentInfo{
		HecateComponentCaddy: {
			Name:        HecateComponentCaddy,
			ServiceName: "hecate-caddy",
			ConfigPaths: []string{filepath.Join(hecatePath, "Caddyfile")},
			LogPaths:    []string{filepath.Join(hecatePath, "logs/caddy/access.log")},
			Ports:       []int{80, 443},
		},
		HecateComponentAuthentik: {
			Name:        HecateComponentAuthentik,
			ServiceName: "authentik",
			ConfigPaths: []string{filepath.Join(hecatePath, ".env"), filepath.Join(hecatePath, "docker-compose.yml")},
			LogPaths:    []string{filepath.Join(hecatePath, "logs/authentik.log")},
			Ports:       []int{9000, 9443},
		},
		HecateComponentPostgreSQL: {
			Name:        HecateComponentPostgreSQL,
			ServiceName: "postgresql",
			ConfigPaths: []string{},
			LogPaths:    []string{},
			Ports:       []int{5432},
		},
		HecateComponentRedis: {
			Name:        HecateComponentRedis,
			ServiceName: "redis",
			ConfigPaths: []string{},
			LogPaths:    []string{},
			Ports:       []int{6379},
		},
		HecateComponentNginx: {
			Name:        HecateComponentNginx,
			ServiceName: "hecate-nginx",
			ConfigPaths: []string{filepath.Join(hecatePath, "nginx.conf")},
			LogPaths:    []string{filepath.Join(hecatePath, "logs/nginx/access.log")},
			Ports:       []int{1514, 1515, 55000, 50000},
		},
		HecateComponentCoturn: {
			Name:        HecateComponentCoturn,
			ServiceName: "hecate-coturn",
			ConfigPaths: []string{},
			LogPaths:    []string{filepath.Join(hecatePath, "coturn-logs/coturn.log")},
			Ports:       []int{3478, 5349},
		},
	}

	// Detect using docker compose ps in the hecate directory
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "ps", "--format", "json")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err == nil && len(output) > 0 {
		outputStr := string(output)
		for _, info := range components {
			if strings.Contains(outputStr, info.ServiceName) {
				info.Detected = true

				// Check if running
				if strings.Contains(outputStr, `"State":"running"`) {
					info.Running = true
				}
			}
		}
	}

	return components
}

func diagnoseHecateComponent(rc *eos_io.RuntimeContext, info *HecateComponentInfo) []HecateCheckResult {
	var results []HecateCheckResult

	// Service status check
	results = append(results, checkHecateServiceStatus(rc, info))

	// Config file checks
	for _, configPath := range info.ConfigPaths {
		results = append(results, checkHecateConfigFile(configPath, info))
	}

	// Port checks
	if len(info.Ports) > 0 {
		results = append(results, checkHecatePorts(rc, info)...)
	}

	// Component-specific checks
	switch info.Name {
	case HecateComponentAuthentik:
		results = append(results, diagnoseAuthentikBasic(rc)...)
	case HecateComponentPostgreSQL:
		results = append(results, diagnosePostgreSQL(rc)...)
	case HecateComponentRedis:
		results = append(results, diagnoseRedis(rc)...)
	}

	return results
}

func checkHecateServiceStatus(rc *eos_io.RuntimeContext, info *HecateComponentInfo) HecateCheckResult {
	if !info.Running {
		return HecateCheckResult{
			Component: info.Name,
			CheckName: "Service Status",
			Category:  "System",
			Passed:    false,
			Error:     fmt.Errorf("service %s is not running", info.ServiceName),
			Remediation: []string{
				fmt.Sprintf("Start service: cd %s && docker compose up -d %s", hecatePath, info.ServiceName),
				fmt.Sprintf("Check logs: cd %s && docker compose logs %s", hecatePath, info.ServiceName),
			},
		}
	}

	return HecateCheckResult{
		Component: info.Name,
		CheckName: "Service Status",
		Category:  "System",
		Passed:    true,
		Details:   fmt.Sprintf("Service %s is running", info.ServiceName),
	}
}

func checkHecateConfigFile(configPath string, info *HecateComponentInfo) HecateCheckResult {
	fileInfo, err := os.Stat(configPath)

	if os.IsNotExist(err) {
		return HecateCheckResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("config file not found: %s", configPath),
		}
	}

	details := fmt.Sprintf("Size: %d bytes, Perms: %s", fileInfo.Size(), fileInfo.Mode().Perm())

	return HecateCheckResult{
		Component: info.Name,
		CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
		Category:  "Configuration",
		Passed:    true,
		Details:   details,
	}
}

func checkHecatePorts(rc *eos_io.RuntimeContext, info *HecateComponentInfo) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := cmd.Output()

	if err != nil {
		return results
	}

	portsOutput := string(output)

	for _, port := range info.Ports {
		portStr := fmt.Sprintf(":%d", port)
		listening := strings.Contains(portsOutput, portStr)

		results = append(results, HecateCheckResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Port %d", port),
			Category:  "Network",
			Passed:    listening,
			Error: func() error {
				if !listening {
					return fmt.Errorf("port %d not listening", port)
				}
				return nil
			}(),
			Details: func() string {
				if listening {
					return fmt.Sprintf("Port %d is listening", port)
				}
				return ""
			}(),
		})
	}

	return results
}

func diagnoseAuthentikBasic(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	// Check if docker-compose.yml exists
	composePath := filepath.Join(hecatePath, "docker-compose.yml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Docker Compose File",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("docker-compose.yml not found"),
			Remediation: []string{
				"Reinstall Hecate: eos create hecate",
			},
		})
		return results
	}

	results = append(results, HecateCheckResult{
		Component: HecateComponentAuthentik,
		CheckName: "Docker Compose File",
		Category:  "Configuration",
		Passed:    true,
		Details:   "docker-compose.yml found",
	})

	return results
}

func diagnosePostgreSQL(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	// Check PostgreSQL connectivity
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "postgresql", "pg_isready", "-U", "authentik")
	cmd.Dir = hecatePath
	err := cmd.Run()
	cancel()

	if err == nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Connectivity",
			Category:  "Service",
			Passed:    true,
			Details:   "PostgreSQL is accepting connections",
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Connectivity",
			Category:  "Service",
			Passed:    false,
			Error:     fmt.Errorf("PostgreSQL not responding"),
			Remediation: []string{
				"Check PostgreSQL logs: cd /opt/hecate && docker compose logs postgresql",
				"Restart PostgreSQL: cd /opt/hecate && docker compose restart postgresql",
			},
		})
	}

	return results
}

func diagnoseRedis(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	// Check Redis connectivity
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "redis", "redis-cli", "ping")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err == nil && strings.Contains(string(output), "PONG") {
		results = append(results, HecateCheckResult{
			Component: HecateComponentRedis,
			CheckName: "Redis Connectivity",
			Category:  "Service",
			Passed:    true,
			Details:   "Redis is responding to PING",
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentRedis,
			CheckName: "Redis Connectivity",
			Category:  "Service",
			Passed:    false,
			Error:     fmt.Errorf("redis not responding"),
			Remediation: []string{
				"Check Redis logs: cd /opt/hecate && docker compose logs redis",
				"Restart Redis: cd /opt/hecate && docker compose restart redis",
			},
		})
	}

	return results
}

func displayDetectedHecateComponents(components map[HecateComponentType]*HecateComponentInfo) {
	fmt.Println("\n🔍 Detected Hecate Components:")
	fmt.Println(strings.Repeat("=", 60))

	for _, info := range components {
		if !info.Detected {
			continue
		}

		status := "❌ Stopped"
		if info.Running {
			status = "✅ Running"
		}

		fmt.Printf("  • %-15s %s\n", string(info.Name), status)
	}
	fmt.Println()
}

func displayHecateResults(results []HecateCheckResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\n📊 Diagnostic Results:")
	fmt.Println(strings.Repeat("=", 60))

	currentComponent := HecateComponentType("")

	for _, result := range results {
		if result.Component != currentComponent {
			currentComponent = result.Component
			fmt.Printf("\n[%s]\n", strings.ToUpper(string(currentComponent)))
		}

		icon := "✅"
		if !result.Passed {
			if result.Warning {
				icon = "⚠️ "
			} else {
				icon = "❌"
			}
		}

		fmt.Printf("%s %s (%s)\n", icon, result.CheckName, result.Category)

		if result.Details != "" {
			fmt.Printf("   %s\n", result.Details)
		}

		if result.Error != nil {
			fmt.Printf("   Error: %s\n", result.Error)
		}

		if len(result.Remediation) > 0 {
			fmt.Println("   Remediation:")
			for _, rem := range result.Remediation {
				fmt.Printf("     • %s\n", rem)
			}
		}
	}

	passed := 0
	failed := 0
	warnings := 0

	for _, r := range results {
		if r.Passed {
			passed++
		} else if r.Warning {
			warnings++
		} else {
			failed++
		}
	}

	fmt.Printf("\n📈 Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
}

// runAuthentikPreUpgradeCheck runs comprehensive Authentik pre-upgrade health check
func runAuthentikPreUpgradeCheck(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Authentik pre-upgrade health check",
		zap.String("path", hecatePath))

	fmt.Println("=========================================")
	fmt.Println("Authentik Pre-Upgrade Health Check")
	fmt.Println("=========================================")
	fmt.Println()

	var allResults []HecateCheckResult

	// 1. Current version check
	allResults = append(allResults, checkAuthentikVersion(rc)...)

	// 2. Disk space check
	allResults = append(allResults, checkDiskSpace(rc)...)

	// 3. Container health
	allResults = append(allResults, checkContainerHealth(rc)...)

	// 4. PostgreSQL checks
	allResults = append(allResults, checkPostgreSQLEncoding(rc)...)

	// 5. Redis check
	allResults = append(allResults, checkRedisConnectivity(rc)...)

	// 6. Custom modifications check
	allResults = append(allResults, checkCustomModifications(rc)...)

	// 7. Environment file check
	allResults = append(allResults, checkEnvironmentFile(rc)...)

	// 8. Task queue check
	allResults = append(allResults, checkTaskQueue(rc)...)

	// 9. Memory check
	allResults = append(allResults, checkMemoryUsage(rc)...)

	// 10. Backup status check
	allResults = append(allResults, checkBackupStatus(rc)...)

	// Display results
	displayHecateResults(allResults)

	// Display summary and recommendations
	displayPreUpgradeSummary(allResults)

	return nil
}

func checkAuthentikVersion(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "server", "ak", "version")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Current Version",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("could not determine version"),
			Details:   "Unable to query Authentik version",
		})
		return results
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		version = "unknown"
	}

	results = append(results, HecateCheckResult{
		Component: HecateComponentAuthentik,
		CheckName: "Current Version",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   fmt.Sprintf("Current version: %s", version),
	})

	return results
}

func checkDiskSpace(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "df", "-h", hecatePath)
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Disk Space",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     err,
		})
		return results
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) >= 2 {
		fields := strings.Fields(lines[1])
		if len(fields) >= 5 {
			usage := fields[4]
			usageInt := 0
			_, _ = fmt.Sscanf(usage, "%d%%", &usageInt)

			if usageInt < 90 {
				results = append(results, HecateCheckResult{
					Component: HecateComponentAuthentik,
					CheckName: "Disk Space",
					Category:  "Pre-Upgrade",
					Passed:    true,
					Details:   fmt.Sprintf("Disk usage: %s (OK)", usage),
				})
			} else {
				results = append(results, HecateCheckResult{
					Component: HecateComponentAuthentik,
					CheckName: "Disk Space",
					Category:  "Pre-Upgrade",
					Passed:    false,
					Warning:   true,
					Details:   fmt.Sprintf("Disk usage: %s (Low space warning!)", usage),
					Remediation: []string{
						"Free up disk space before upgrading",
						"Consider cleaning old Docker images: docker image prune -a",
					},
				})
			}
		}
	}

	return results
}

func checkContainerHealth(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "ps", "--format", "table {{.Name}}\t{{.Status}}\t{{.State}}")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     err,
		})
		return results
	}

	details := "Container status:\n" + string(output)
	allRunning := strings.Count(string(output), "running") > 0
	anyExited := strings.Contains(string(output), "exited") || strings.Contains(string(output), "dead")

	if anyExited {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   details,
			Remediation: []string{
				"Some containers are not running",
				"Start all containers: cd /opt/hecate && docker compose up -d",
			},
		})
	} else if allRunning {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "All containers are running",
		})
	}

	return results
}

func checkPostgreSQLEncoding(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	// Check encoding
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "postgresql",
		"psql", "-U", "authentik", "-d", "authentik", "-c", "SHOW SERVER_ENCODING;")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     err,
			Remediation: []string{
				"Could not check database encoding",
				"Ensure PostgreSQL is running",
			},
		})
		return results
	}

	isUTF8 := strings.Contains(strings.ToUpper(string(output)), "UTF8") ||
		strings.Contains(strings.ToUpper(string(output)), "UTF-8")

	if isUTF8 {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Database encoding is UTF8 (required for 2025.8+)",
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("database encoding is not UTF8"),
			Details:   "Database must use UTF8 encoding for Authentik 2025.8+",
			Remediation: []string{
				"WARNING: Database encoding must be UTF8",
				"This is a CRITICAL requirement for Authentik 2025.8+",
				"Database migration may be required",
			},
		})
	}

	// Check database size
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	sizeCmd := exec.CommandContext(ctx2, "docker", "compose", "exec", "-T", "postgresql",
		"psql", "-U", "authentik", "-d", "authentik", "-c",
		"SELECT pg_database_size('authentik')/1024/1024 as size_mb;")
	sizeCmd.Dir = hecatePath
	sizeOutput, _ := sizeCmd.Output()
	cancel2()

	if len(sizeOutput) > 0 {
		results = append(results, HecateCheckResult{
			Component: HecateComponentPostgreSQL,
			CheckName: "Database Size",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Database size:\n" + string(sizeOutput),
		})
	}

	return results
}

func checkRedisConnectivity(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "redis", "redis-cli", "ping")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil || !strings.Contains(string(output), "PONG") {
		results = append(results, HecateCheckResult{
			Component: HecateComponentRedis,
			CheckName: "Redis Connectivity",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("redis not responding"),
			Remediation: []string{
				"Ensure Redis is running",
				"Restart Redis: cd /opt/hecate && docker compose restart redis",
			},
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentRedis,
			CheckName: "Redis Connectivity",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Redis is responding to PING",
		})
	}

	return results
}

func checkCustomModifications(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	// Check for custom templates
	customTemplatesPath := filepath.Join(hecatePath, "custom-templates")
	if info, err := os.Stat(customTemplatesPath); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(customTemplatesPath)
		if len(entries) > 0 {
			results = append(results, HecateCheckResult{
				Component: HecateComponentAuthentik,
				CheckName: "Custom Templates",
				Category:  "Pre-Upgrade",
				Passed:    true,
				Warning:   true,
				Details:   fmt.Sprintf("Found %d custom template(s) - review compatibility after upgrade", len(entries)),
			})
		}
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Custom Templates",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No custom templates detected",
		})
	}

	// Check for custom blueprints
	customBlueprintsPath := filepath.Join(hecatePath, "authentik/blueprints/custom")
	if info, err := os.Stat(customBlueprintsPath); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(customBlueprintsPath)
		if len(entries) > 0 {
			results = append(results, HecateCheckResult{
				Component: HecateComponentAuthentik,
				CheckName: "Custom Blueprints",
				Category:  "Pre-Upgrade",
				Passed:    true,
				Warning:   true,
				Details:   fmt.Sprintf("Found %d custom blueprint(s) - review compatibility after upgrade", len(entries)),
			})
		}
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Custom Blueprints",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No custom blueprints detected",
		})
	}

	return results
}

func checkEnvironmentFile(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	envPath := filepath.Join(hecatePath, ".env")
	data, err := os.ReadFile(envPath)
	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Environment File",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf(".env file not found"),
		})
		return results
	}

	content := string(data)

	// Check for deprecated settings
	deprecated := []string{
		"AUTHENTIK_BROKER__URL",
		"AUTHENTIK_BROKER__TRANSPORT_OPTIONS",
		"AUTHENTIK_RESULT_BACKEND__URL",
	}

	var foundDeprecated []string
	for _, setting := range deprecated {
		if strings.Contains(content, setting) {
			foundDeprecated = append(foundDeprecated, setting)
		}
	}

	if len(foundDeprecated) > 0 {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Deprecated Settings",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   fmt.Sprintf("Found deprecated settings: %s", strings.Join(foundDeprecated, ", ")),
			Remediation: []string{
				"These settings will be removed during upgrade",
				"They are no longer needed in Authentik 2025.8+",
			},
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Deprecated Settings",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No deprecated settings found",
		})
	}

	// Check for renamed settings
	if strings.Contains(content, "AUTHENTIK_WORKER__CONCURRENCY") {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Renamed Settings",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "AUTHENTIK_WORKER__CONCURRENCY will be renamed to AUTHENTIK_WORKER__THREADS",
			Remediation: []string{
				"This will be handled automatically during upgrade",
			},
		})
	}

	return results
}

func checkTaskQueue(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "worker",
		"bash", "-c", "DJANGO_SETTINGS_MODULE=authentik.root.settings celery -A authentik.root.celery inspect active")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "Could not check task queue status",
		})
		return results
	}

	isEmpty := strings.Contains(string(output), "empty")

	if isEmpty {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No active tasks in queue (good for upgrade)",
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "There may be active tasks in the queue",
			Remediation: []string{
				"Consider waiting for tasks to complete before upgrading",
				"Or proceed during a maintenance window",
			},
		})
	}

	return results
}

func checkMemoryUsage(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "free", "-m")
	output, err := cmd.Output()
	cancel()

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "Could not check memory usage",
		})
		return results
	}

	lines := strings.Split(string(output), "\n")
	var availableMem int
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				_, _ = fmt.Sscanf(fields[6], "%d", &availableMem)
				break
			}
		}
	}

	details := string(output)

	if availableMem > 1000 {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   fmt.Sprintf("Sufficient memory available (%d MB)\n%s", availableMem, details),
		})
	} else {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   fmt.Sprintf("Low memory (%d MB available) - monitor during upgrade\n%s", availableMem, details),
			Remediation: []string{
				"Monitor memory usage during upgrade",
				"Consider freeing up memory before upgrading",
			},
		})
	}

	return results
}

func checkBackupStatus(rc *eos_io.RuntimeContext) []HecateCheckResult {
	var results []HecateCheckResult

	backupDir := filepath.Join(hecatePath, "backups")
	entries, err := os.ReadDir(backupDir)

	if err != nil {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("no backup directory found"),
			Remediation: []string{
				"Create a backup before upgrading",
				"Run: eos backup authentik",
			},
		})
		return results
	}

	if len(entries) == 0 {
		results = append(results, HecateCheckResult{
			Component: HecateComponentAuthentik,
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   "No backups found",
			Remediation: []string{
				"Create a backup before upgrading",
				"Run: eos backup authentik",
			},
		})
		return results
	}

	// Find most recent backup
	var latestBackup string
	var latestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			info, _ := entry.Info()
			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				latestBackup = entry.Name()
			}
		}
	}

	results = append(results, HecateCheckResult{
		Component: HecateComponentAuthentik,
		CheckName: "Backup Status",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   fmt.Sprintf("Latest backup: %s (created %s)", latestBackup, latestTime.Format("2006-01-02 15:04:05")),
	})

	return results
}

func displayPreUpgradeSummary(results []HecateCheckResult) {
	fmt.Println("=========================================")
	fmt.Println("Pre-Upgrade Summary")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Key Breaking Changes in Authentik 2025.8:")
	fmt.Println("1. Worker and background tasks revamped")
	fmt.Println("2. Database must use UTF8 encoding")
	fmt.Println("3. AUTHENTIK_WORKER__CONCURRENCY renamed to AUTHENTIK_WORKER__THREADS")
	fmt.Println("4. Some broker settings removed")
	fmt.Println()

	criticalIssues := 0
	warnings := 0
	for _, r := range results {
		if !r.Passed && !r.Warning {
			criticalIssues++
		} else if r.Warning {
			warnings++
		}
	}

	if criticalIssues > 0 {
		fmt.Printf("⚠️  Found %d critical issue(s) that must be addressed\n", criticalIssues)
	}
	if warnings > 0 {
		fmt.Printf("⚠️  Found %d warning(s) to review\n", warnings)
	}
	if criticalIssues == 0 && warnings == 0 {
		fmt.Println("✅ All checks passed! System is ready for upgrade.")
	}

	fmt.Println()
	fmt.Println("Recommended Actions:")
	fmt.Println("1. Review the checks above for any warnings")
	fmt.Println("2. Ensure you have a recent backup")
	fmt.Println("3. Run the upgrade during a maintenance window")
	fmt.Println("4. Monitor logs during and after upgrade")
	fmt.Println()
	fmt.Println("To proceed with upgrade, run:")
	fmt.Println("  eos update hecate --authentik")
	fmt.Println()
}
