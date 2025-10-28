package hecate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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

// RunHecateDebug is the main entry point for Hecate diagnostics
func RunHecateDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
	component, _ := cmd.Flags().GetString("component")
	authentikCheck, _ := cmd.Flags().GetBool("authentik")
	bionicgptCheck, _ := cmd.Flags().GetBool("bionicgpt")
	hecatePath, _ := cmd.Flags().GetString("path")
	verbose, _ := cmd.Flags().GetBool("verbose")

	logger.Info("Starting Hecate diagnostics",
		zap.String("component_filter", component),
		zap.String("path", hecatePath),
		zap.Bool("authentik_check", authentikCheck),
		zap.Bool("bionicgpt_check", bionicgptCheck))

	// If --bionicgpt flag is set, run BionicGPT integration diagnostics
	if bionicgptCheck {
		config := &BionicGPTDebugConfig{
			HecatePath: hecatePath,
			Verbose:    verbose,
		}
		return RunBionicGPTIntegrationDebug(rc, config)
	}

	// If --authentik flag is set, run comprehensive Authentik check
	// Delegate to pkg/authentik for business logic
	if authentikCheck {
		config := &authentik.DebugConfig{
			HecatePath: hecatePath,
			Verbose:    verbose,
		}
		return authentik.RunAuthentikDebug(rc, config)
	}

	// Detect components
	components := detectHecateComponents(rc, hecatePath)

	if len(components) == 0 {
		fmt.Println("\n❌ No Hecate components detected on this system")
		fmt.Println("\nTo install Hecate:")
		fmt.Println("  • Full stack: eos create hecate")
		return nil
	}

	// Filter by component if specified
	if component != "" {
		filtered := make(map[HecateComponentType]*HecateComponentInfo)
		comp := HecateComponentType(component)
		if info, exists := components[comp]; exists {
			filtered[comp] = info
			components = filtered
		} else {
			return fmt.Errorf("component '%s' not found on this system", component)
		}
	}

	displayDetectedHecateComponents(components)

	// ASSESS: Perform standard component diagnostics
	var allResults []HecateCheckResult
	for _, info := range components {
		if !info.Detected {
			continue
		}

		results := diagnoseHecateComponent(rc, info, hecatePath, verbose)
		allResults = append(allResults, results...)
	}

	// INTERVENE: Display comprehensive file contents (new functionality)
	logger.Info("Displaying configuration file contents")
	fileResults := displayHecateConfigFiles(rc, hecatePath)
	allResults = append(allResults, fileResults...)

	// INTERVENE: Display Consul KV configuration
	logger.Info("Displaying Consul KV configuration")
	consulResults := displayConsulKVConfig(rc)
	allResults = append(allResults, consulResults...)

	// INTERVENE: Display container status and logs
	logger.Info("Displaying container status")
	containerResults := displayContainerStatus(rc, hecatePath)
	allResults = append(allResults, containerResults...)

	// EVALUATE: Display all diagnostic results
	displayHecateResults(allResults)

	return nil
}

func detectHecateComponents(rc *eos_io.RuntimeContext, hecatePath string) map[HecateComponentType]*HecateComponentInfo {
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

func diagnoseHecateComponent(rc *eos_io.RuntimeContext, info *HecateComponentInfo, hecatePath string, _ bool) []HecateCheckResult {
	var results []HecateCheckResult

	// Service status check
	results = append(results, checkHecateServiceStatus(rc, info, hecatePath))

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
		results = append(results, diagnoseAuthentikBasic(rc, hecatePath)...)
	case HecateComponentPostgreSQL:
		results = append(results, diagnosePostgreSQL(rc, hecatePath)...)
	case HecateComponentRedis:
		results = append(results, diagnoseRedis(rc, hecatePath)...)
	}

	return results
}

func checkHecateServiceStatus(_ *eos_io.RuntimeContext, info *HecateComponentInfo, hecatePath string) HecateCheckResult {
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

func diagnoseAuthentikBasic(_ *eos_io.RuntimeContext, hecatePath string) []HecateCheckResult {
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

func diagnosePostgreSQL(rc *eos_io.RuntimeContext, hecatePath string) []HecateCheckResult {
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

func diagnoseRedis(rc *eos_io.RuntimeContext, hecatePath string) []HecateCheckResult {
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

	fmt.Println("\n Diagnostic Results:")
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
				icon = " "
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

	fmt.Printf("\n Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
}

// displayHecateConfigFiles displays the content of key Hecate configuration files
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if configuration files exist
// - Intervene: Read and display file contents with proper formatting
// - Evaluate: Report which files were displayed successfully
func displayHecateConfigFiles(rc *eos_io.RuntimeContext, hecatePath string) []HecateCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []HecateCheckResult

	logger.Info("Displaying Hecate configuration files",
		zap.String("path", hecatePath))

	// ASSESS: Define files to display
	filesToDisplay := map[string]string{
		".env":               "Environment variables (contains secrets - handle with care)",
		"docker-compose.yml": "Docker Compose service definitions",
		"Caddyfile":          "Caddy reverse proxy configuration",
	}

	fmt.Println("\n📄 Configuration Files:")
	fmt.Println(strings.Repeat("=", 80))

	// INTERVENE: Display each file
	for filename, description := range filesToDisplay {
		filePath := filepath.Join(hecatePath, filename)

		fmt.Printf("\n▼ %s (%s)\n", filename, description)
		fmt.Println(strings.Repeat("-", 80))

		// ASSESS: Check if file exists
		content, err := os.ReadFile(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("     File not found: %s\n", filePath)
				results = append(results, HecateCheckResult{
					Component:   HecateComponentCaddy,
					CheckName:   fmt.Sprintf("Display %s", filename),
					Category:    "File Display",
					Passed:      false,
					Warning:     true,
					Details:     fmt.Sprintf("File not found: %s", filePath),
					Remediation: []string{"Run: eos create hecate --config hecate-config.yaml"},
				})
				continue
			}

			// Read error (permissions, etc.)
			fmt.Printf("   ❌ Error reading file: %v\n", err)
			results = append(results, HecateCheckResult{
				Component: HecateComponentCaddy,
				CheckName: fmt.Sprintf("Display %s", filename),
				Category:  "File Display",
				Passed:    false,
				Error:     err,
				Details:   fmt.Sprintf("Cannot read %s", filePath),
				Remediation: []string{
					fmt.Sprintf("Check permissions: ls -l %s", filePath),
					fmt.Sprintf("Fix permissions: sudo chmod 644 %s", filePath),
				},
			})
			continue
		}

		// INTERVENE: Display file content with line numbers
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			// Redact sensitive values in .env file
			if filename == ".env" {
				line = redactSensitiveValue(line)
			}
			fmt.Printf("   %4d │ %s\n", i+1, line)
		}

		// EVALUATE: File displayed successfully
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: fmt.Sprintf("Display %s", filename),
			Category:  "File Display",
			Passed:    true,
			Details:   fmt.Sprintf("Displayed %d lines from %s", len(lines), filePath),
		})

		logger.Debug("Displayed configuration file",
			zap.String("file", filename),
			zap.Int("lines", len(lines)))
	}

	fmt.Println()
	return results
}

// redactSensitiveValue redacts password/secret values in .env files for security
func redactSensitiveValue(line string) string {
	// Don't redact comments or empty lines
	if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
		return line
	}

	// Check if line contains sensitive keys
	sensitiveKeys := []string{
		"PASSWORD", "SECRET", "TOKEN", "KEY", "PASS",
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return line
	}

	key := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := parts[1]

	// Check if key contains sensitive keywords
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(key, sensitiveKey) {
			// Redact the value but show first/last 2 characters
			if len(value) > 8 {
				return fmt.Sprintf("%s=%s...%s (redacted)", parts[0], value[:2], value[len(value)-2:])
			}
			return fmt.Sprintf("%s=*** (redacted)", parts[0])
		}
	}

	return line
}

// displayConsulKVConfig displays Hecate configuration stored in Consul KV
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check Consul availability and look for config data
// - Intervene: Retrieve and display config from Consul KV
// - Evaluate: Report success or provide remediation steps
func displayConsulKVConfig(rc *eos_io.RuntimeContext) []HecateCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []HecateCheckResult

	logger.Info("Checking Consul KV for Hecate configuration")

	fmt.Println("\n🗄️  Consul KV Configuration:")
	fmt.Println(strings.Repeat("=", 80))

	// ASSESS: Try to connect to Consul
	configStorage, err := NewConfigStorage(rc)
	if err != nil {
		fmt.Printf("     Cannot connect to Consul: %v\n", err)
		fmt.Println("   Consul KV configuration not available")
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: "Consul KV Config",
			Category:  "Configuration Storage",
			Passed:    false,
			Warning:   true,
			Details:   "Consul not available",
			Remediation: []string{
				"Check Consul is running: systemctl status consul",
				"Start Consul: systemctl start consul",
			},
		})
		return results
	}

	// INTERVENE: Load configuration from Consul KV
	rawConfig, err := configStorage.LoadConfig(rc)
	if err != nil {
		fmt.Printf("     Cannot load config from Consul: %v\n", err)
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: "Consul KV Config",
			Category:  "Configuration Storage",
			Passed:    false,
			Warning:   true,
			Details:   "No configuration in Consul KV",
			Remediation: []string{
				"Generate config: eos create config --hecate",
				"Deploy Hecate: eos create hecate --config hecate-config.yaml",
			},
		})
		return results
	}

	if rawConfig == nil || len(rawConfig.Apps) == 0 {
		fmt.Println("   ℹ️  No Hecate configuration found in Consul KV")
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: "Consul KV Config",
			Category:  "Configuration Storage",
			Passed:    false,
			Warning:   true,
			Details:   "Consul KV is empty",
			Remediation: []string{
				"Generate and store config: eos create config --hecate",
			},
		})
		return results
	}

	// INTERVENE: Display configuration
	fmt.Printf("\n   Found configuration for %d app(s):\n\n", len(rawConfig.Apps))

	for appName, app := range rawConfig.Apps {
		fmt.Printf("   ▸ %s\n", appName)
		fmt.Printf("     Domain:  %s\n", app.Domain)
		if app.Backend != "" {
			fmt.Printf("     Backend: %s\n", app.Backend)
		}
		if app.Type != "" {
			fmt.Printf("     Type:    %s\n", app.Type)
		}
		if app.SSO {
			fmt.Printf("     SSO:     enabled\n")
		}
		if app.Talk {
			fmt.Printf("     Talk:    enabled\n")
		}
		fmt.Println()
	}

	// EVALUATE: Success
	results = append(results, HecateCheckResult{
		Component: HecateComponentCaddy,
		CheckName: "Consul KV Config",
		Category:  "Configuration Storage",
		Passed:    true,
		Details:   fmt.Sprintf("Found %d apps in Consul KV", len(rawConfig.Apps)),
	})

	logger.Info("Consul KV configuration displayed",
		zap.Int("app_count", len(rawConfig.Apps)))

	return results
}

// displayContainerStatus displays Docker container status and recent logs
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if Docker is available and containers exist
// - Intervene: Get container status and recent logs
// - Evaluate: Display results with remediation if needed
func displayContainerStatus(rc *eos_io.RuntimeContext, hecatePath string) []HecateCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []HecateCheckResult

	logger.Info("Checking Docker container status",
		zap.String("path", hecatePath))

	fmt.Println("\n🐳 Container Status:")
	fmt.Println(strings.Repeat("=", 80))

	// ASSESS: Check if docker-compose.yml exists
	composeFile := filepath.Join(hecatePath, "docker-compose.yml")
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		fmt.Printf("     No docker-compose.yml found at %s\n", composeFile)
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: "Container Status",
			Category:  "Docker",
			Passed:    false,
			Warning:   true,
			Details:   "No docker-compose.yml found",
			Remediation: []string{
				"Deploy Hecate: eos create hecate --config hecate-config.yaml",
			},
		})
		return results
	}

	// INTERVENE: Get container status using docker compose ps
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "--format", "table")
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("   ❌ Failed to get container status: %v\n", err)
		fmt.Printf("   Output: %s\n", string(output))
		results = append(results, HecateCheckResult{
			Component: HecateComponentCaddy,
			CheckName: "Container Status",
			Category:  "Docker",
			Passed:    false,
			Error:     err,
			Details:   "Cannot run docker compose ps",
			Remediation: []string{
				"Check Docker is running: systemctl status docker",
				"Start Docker: systemctl start docker",
				fmt.Sprintf("Check compose file: docker compose -f %s config", composeFile),
			},
		})
		return results
	}

	// INTERVENE: Display container status
	fmt.Printf("\n%s\n", string(output))

	// INTERVENE: Get recent logs (last 20 lines)
	fmt.Println("\n📋 Recent Logs (last 20 lines):")
	fmt.Println(strings.Repeat("-", 80))

	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel2()

	logCmd := exec.CommandContext(ctx2, "docker", "compose", "-f", composeFile, "logs", "--tail=20")
	logOutput, err := logCmd.CombinedOutput()

	if err != nil {
		fmt.Printf("     Could not retrieve logs: %v\n", err)
	} else {
		fmt.Printf("%s\n", string(logOutput))
	}

	// EVALUATE: Success
	results = append(results, HecateCheckResult{
		Component: HecateComponentCaddy,
		CheckName: "Container Status",
		Category:  "Docker",
		Passed:    true,
		Details:   "Container status retrieved successfully",
	})

	logger.Debug("Container status displayed")

	return results
}
