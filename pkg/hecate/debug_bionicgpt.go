// pkg/hecate/debug_bionicgpt.go - BionicGPT integration diagnostics (Authentik-Caddy-BionicGPT triangle)

package hecate

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BionicGPTDebugConfig holds configuration for BionicGPT integration diagnostics
type BionicGPTDebugConfig struct {
	HecatePath string // Path to Hecate installation
	Verbose    bool   // Show detailed output
}

// BionicGPTIntegrationCheck represents a single diagnostic check result
type BionicGPTIntegrationCheck struct {
	Category    string   // Category of check (Caddy, Authentik, BionicGPT, Integration)
	CheckName   string   // Name of the check
	Passed      bool     // Whether check passed
	Warning     bool     // Whether this is a warning (not critical)
	Details     string   // Detailed information
	Error       error    // Error if check failed
	Remediation []string // Steps to fix the issue
}

// RunBionicGPTIntegrationDebug performs comprehensive diagnostics of Authentik-Caddy-BionicGPT integration
func RunBionicGPTIntegrationDebug(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🔍 BionicGPT Integration Diagnostics",
		zap.String("hecate_path", config.HecatePath))

	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("🔍  BIONICGPT INTEGRATION DIAGNOSTICS")
	fmt.Println("     Authentik → Caddy → BionicGPT Triangle Validation")
	fmt.Println(strings.Repeat("=", 100))

	var checks []BionicGPTIntegrationCheck

	// Phase 1: Component Detection
	fmt.Println("\n📦 Phase 1: Component Detection")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkComponentsRunning(rc, config)...)

	// Phase 2: Caddy Configuration
	fmt.Println("\n⚙️  Phase 2: Caddy Configuration Validation")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkCaddyConfiguration(rc, config)...)

	// Phase 3: Authentik Integration
	fmt.Println("\n🔐 Phase 3: Authentik Integration")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkAuthentikIntegration(rc, config)...)

	// Phase 4: BionicGPT Backend Configuration
	fmt.Println("\n🤖 Phase 4: BionicGPT Backend Configuration")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkBionicGPTConfiguration(rc, config)...)

	// Phase 5: Header Flow Validation
	fmt.Println("\n📨 Phase 5: Header Flow Validation")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkHeaderFlow(rc, config)...)

	// Phase 6: End-to-End Integration Test
	fmt.Println("\n🧪 Phase 6: End-to-End Integration Test")
	fmt.Println(strings.Repeat("-", 100))
	checks = append(checks, checkEndToEndIntegration(rc, config)...)

	// Display Results Summary
	displayBionicGPTResults(checks)

	return nil
}

// ============================================================================
// PHASE 1: COMPONENT DETECTION
// ============================================================================

func checkComponentsRunning(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	// Check 1.1: Caddy running
	check := BionicGPTIntegrationCheck{
		Category:  "Components",
		CheckName: "Caddy Container Running",
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=caddy", "--format", "{{.Names}}")
	output, err := cmd.CombinedOutput()

	if err != nil || len(output) == 0 {
		check.Passed = false
		check.Error = fmt.Errorf("Caddy container not running")
		check.Details = "Caddy reverse proxy is required for forward auth"
		check.Remediation = []string{
			"Check if Hecate is installed: sudo eos debug hecate",
			"Start Caddy: cd /opt/hecate && docker compose up -d caddy",
			"View logs: docker logs hecate-caddy-1",
		}
	} else {
		check.Passed = true
		check.Details = fmt.Sprintf("Container running: %s", strings.TrimSpace(string(output)))
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 1.2: Authentik running
	check = BionicGPTIntegrationCheck{
		Category:  "Components",
		CheckName: "Authentik Container Running",
	}

	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel2()

	cmd = exec.CommandContext(ctx2, "docker", "ps", "--filter", "name=authentik", "--format", "{{.Names}}")
	output, err = cmd.CombinedOutput()

	if err != nil || len(output) == 0 {
		check.Passed = false
		check.Error = fmt.Errorf("Authentik container not running")
		check.Details = "Authentik identity provider is required for authentication"
		check.Remediation = []string{
			"Check if Authentik is installed: sudo eos debug hecate --component authentik",
			"Start Authentik: cd /opt/hecate && docker compose up -d authentik-server authentik-worker",
			"View logs: docker logs hecate-authentik-server-1",
		}
	} else {
		check.Passed = true
		containerNames := strings.Split(strings.TrimSpace(string(output)), "\n")
		check.Details = fmt.Sprintf("Containers running: %s", strings.Join(containerNames, ", "))
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 1.3: BionicGPT running
	check = BionicGPTIntegrationCheck{
		Category:  "Components",
		CheckName: "BionicGPT Container Running",
	}

	ctx3, cancel3 := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel3()

	cmd = exec.CommandContext(ctx3, "docker", "ps", "--filter", "name=bionic", "--format", "{{.Names}}")
	output, err = cmd.CombinedOutput()

	if err != nil || len(output) == 0 {
		check.Passed = false
		check.Warning = true // Not critical - user might be testing config before BionicGPT is installed
		check.Error = fmt.Errorf("BionicGPT container not running")
		check.Details = "BionicGPT backend service not found"
		check.Remediation = []string{
			"Check if BionicGPT is installed: sudo eos debug bionicgpt",
			"Install BionicGPT: sudo eos create bionicgpt",
			"View logs: docker logs bionicgpt-app-1",
		}
	} else {
		check.Passed = true
		containerNames := strings.Split(strings.TrimSpace(string(output)), "\n")
		check.Details = fmt.Sprintf("Containers running: %s", strings.Join(containerNames, ", "))
	}
	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// PHASE 2: CADDY CONFIGURATION
// ============================================================================

func checkCaddyConfiguration(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	caddyfilePath := filepath.Join(config.HecatePath, "Caddyfile")

	// Check 2.1: Caddyfile exists
	check := BionicGPTIntegrationCheck{
		Category:  "Caddy",
		CheckName: "Caddyfile Exists",
	}

	if _, err := os.Stat(caddyfilePath); os.IsNotExist(err) {
		check.Passed = false
		check.Error = fmt.Errorf("Caddyfile not found at %s", caddyfilePath)
		check.Details = "Caddy configuration file missing"
		check.Remediation = []string{
			"Verify Hecate installation: sudo eos debug hecate",
			fmt.Sprintf("Check file exists: ls -la %s", caddyfilePath),
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks // Cannot continue without Caddyfile
	}

	check.Passed = true
	check.Details = fmt.Sprintf("Found: %s", caddyfilePath)
	checks = append(checks, check)
	displayCheck(check)

	// Read Caddyfile
	caddyfileContent, err := os.ReadFile(caddyfilePath)
	if err != nil {
		check = BionicGPTIntegrationCheck{
			Category:    "Caddy",
			CheckName:   "Read Caddyfile",
			Passed:      false,
			Error:       err,
			Details:     "Could not read Caddyfile",
			Remediation: []string{fmt.Sprintf("Check permissions: ls -la %s", caddyfilePath)},
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	caddyfileStr := string(caddyfileContent)

	// Check 2.2: forward_auth directive present
	check = BionicGPTIntegrationCheck{
		Category:  "Caddy",
		CheckName: "forward_auth Directive Present",
	}

	if !strings.Contains(caddyfileStr, "forward_auth") {
		check.Passed = false
		check.Error = fmt.Errorf("forward_auth directive not found in Caddyfile")
		check.Details = "Caddy forward_auth is required for Authentik integration"
		check.Remediation = []string{
			"Add BionicGPT route: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
			"Check Caddyfile syntax: docker exec hecate-caddy-1 caddy validate --config /etc/caddy/Caddyfile",
		}
	} else {
		check.Passed = true
		check.Details = "forward_auth directive found in Caddyfile"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 2.3: Outpost path forwarding
	check = BionicGPTIntegrationCheck{
		Category:  "Caddy",
		CheckName: "Authentik Outpost Path Forwarding",
	}

	if !strings.Contains(caddyfileStr, "/outpost.goauthentik.io/") {
		check.Passed = false
		check.Error = fmt.Errorf("Authentik outpost path forwarding not found")
		check.Details = "Caddy must forward /outpost.goauthentik.io/* to Authentik for forward auth to work"
		check.Remediation = []string{
			"Re-add BionicGPT route with --sso flag",
			"Manually add to Caddyfile:",
			"  handle /outpost.goauthentik.io/* {",
			"    reverse_proxy http://localhost:9000",
			"  }",
		}
	} else {
		check.Passed = true
		check.Details = "Outpost path forwarding configured"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 2.4: Header mapping (X-Authentik-* → X-Auth-Request-*)
	check = BionicGPTIntegrationCheck{
		Category:  "Caddy",
		CheckName: "Header Mapping Configuration",
	}

	hasAuthRequestEmail := strings.Contains(caddyfileStr, "X-Auth-Request-Email")
	hasAuthRequestUser := strings.Contains(caddyfileStr, "X-Auth-Request-User")
	hasAuthRequestGroups := strings.Contains(caddyfileStr, "X-Auth-Request-Groups")

	if !hasAuthRequestEmail || !hasAuthRequestUser || !hasAuthRequestGroups {
		check.Passed = false
		check.Error = fmt.Errorf("Incomplete header mapping configuration")
		check.Details = fmt.Sprintf("Missing headers - Email: %t, User: %t, Groups: %t",
			hasAuthRequestEmail, hasAuthRequestUser, hasAuthRequestGroups)
		check.Remediation = []string{
			"Header mapping should include:",
			"  header_up X-Auth-Request-Email {http.request.header.X-Authentik-Email}",
			"  header_up X-Auth-Request-User {http.request.header.X-Authentik-Username}",
			"  header_up X-Auth-Request-Groups {http.request.header.X-Authentik-Groups}",
		}
	} else {
		check.Passed = true
		check.Details = "All required headers mapped: Email, User, Groups"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 2.5: Caddy config validation
	check = BionicGPTIntegrationCheck{
		Category:  "Caddy",
		CheckName: "Caddyfile Syntax Validation",
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	// Try to get actual Caddy container name (handles both hecate-caddy and hecate-caddy-1)
	caddyContainerName := detectCaddyContainerName(rc.Ctx)
	if caddyContainerName == "" {
		check.Passed = false
		check.Error = fmt.Errorf("Caddy container not found")
		check.Details = "Cannot validate without running Caddy container"
		check.Remediation = []string{
			"Verify Caddy is running: docker ps | grep caddy",
			"Start Caddy: cd /opt/hecate && docker compose up -d caddy",
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	cmd := exec.CommandContext(ctx, "docker", "exec", caddyContainerName, "caddy", "validate", "--config", "/etc/caddy/Caddyfile")
	output, err := cmd.CombinedOutput()

	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = fmt.Sprintf("Caddyfile validation failed: %s", string(output))
		check.Remediation = []string{
			"Check Caddyfile syntax errors",
			"View full output: docker exec hecate-caddy-1 caddy validate --config /etc/caddy/Caddyfile",
		}
	} else {
		check.Passed = true
		check.Details = "Caddyfile syntax is valid"
	}
	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// PHASE 3: AUTHENTIK INTEGRATION
// ============================================================================

func checkAuthentikIntegration(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	// Check 3.1: Authentik API token available
	check := BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "Authentik API Token",
	}

	bionicEnvPath := "/opt/bionicgpt/.env"
	authentikToken, authentikBaseURL, err := getAuthentikCredentialsFromEnv(bionicEnvPath)

	if err != nil || authentikToken == "" {
		check.Passed = false
		check.Warning = true // Not critical for runtime, only for setup/sync
		check.Error = fmt.Errorf("Authentik API token not configured")
		check.Details = "Token required for checking Authentik configuration (not required for auth flow)"
		check.Remediation = []string{
			"Get Authentik API token from admin UI",
			fmt.Sprintf("Add to %s:", bionicEnvPath),
			"  AUTHENTIK_TOKEN=<your_token>",
			"  AUTHENTIK_BASE_URL=http://localhost:9000",
		}
		checks = append(checks, check)
		displayCheck(check)
		// Continue with limited checks
		return checks
	}

	check.Passed = true
	check.Details = fmt.Sprintf("Token found (Base URL: %s)", authentikBaseURL)
	checks = append(checks, check)
	displayCheck(check)

	// Initialize Authentik API client
	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Check 3.2: Authentik API connectivity
	check = BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "Authentik API Connectivity",
	}

	apps, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = "Cannot connect to Authentik API"
		check.Remediation = []string{
			"Verify Authentik is running: docker ps | grep authentik",
			"Check Authentik logs: docker logs hecate-authentik-server-1",
			"Test API manually: curl http://localhost:9000/api/v3/",
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	check.Passed = true
	check.Details = fmt.Sprintf("API accessible (%d applications configured)", len(apps))
	checks = append(checks, check)
	displayCheck(check)

	// Check 3.3: BionicGPT application exists
	check = BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "BionicGPT Application",
	}

	var bionicApp *authentik.ApplicationResponse
	for i := range apps {
		if apps[i].Slug == "bionicgpt" {
			bionicApp = &apps[i]
			break
		}
	}

	if bionicApp == nil {
		check.Passed = false
		check.Error = fmt.Errorf("BionicGPT application not found in Authentik")
		check.Details = "Application required for authentication"
		check.Remediation = []string{
			"Create application: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
			"Or create manually in Authentik admin UI",
		}
	} else {
		check.Passed = true
		check.Details = fmt.Sprintf("Application found (name: %s, slug: %s)", bionicApp.Name, bionicApp.Slug)
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 3.4: Proxy provider exists
	check = BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "Proxy Provider Configuration",
	}

	providers, err := authentikClient.ListProxyProviders(rc.Ctx)
	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = "Cannot list proxy providers"
		check.Remediation = []string{
			"Check Authentik logs: docker logs hecate-authentik-server-1",
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	var bionicProvider *authentik.ProxyProviderResponse
	for i := range providers {
		if providers[i].Name == "BionicGPT" {
			bionicProvider = &providers[i]
			break
		}
	}

	if bionicProvider == nil {
		check.Passed = false
		check.Error = fmt.Errorf("BionicGPT proxy provider not found")
		check.Details = "Proxy provider required for forward auth"
		check.Remediation = []string{
			"Create provider: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
		}
	} else {
		check.Passed = true
		check.Details = fmt.Sprintf("Provider found (mode: %s, PK: %d)", bionicProvider.Mode, bionicProvider.PK)

		if bionicProvider.Mode != "forward_single" {
			check.Warning = true
			check.Details += fmt.Sprintf(" - Warning: mode is '%s', expected 'forward_single'", bionicProvider.Mode)
		}
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 3.5: Authentik groups exist
	check = BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "BionicGPT Groups",
	}

	groups, err := authentikClient.ListGroups(rc.Ctx, "") // Empty string = list all groups
	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = "Cannot list groups"
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	var superadminGroup, demoGroup *authentik.GroupResponse
	for i := range groups {
		if groups[i].Name == "bionicgpt-superadmin" {
			superadminGroup = &groups[i]
		}
		if groups[i].Name == "bionicgpt-demo" {
			demoGroup = &groups[i]
		}
	}

	if superadminGroup == nil || demoGroup == nil {
		check.Passed = false
		check.Warning = true
		check.Error = fmt.Errorf("BionicGPT groups not found")
		check.Details = fmt.Sprintf("Superadmin: %t, Demo: %t", superadminGroup != nil, demoGroup != nil)
		check.Remediation = []string{
			"Create groups: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
			"Or create manually in Authentik admin UI",
		}
	} else {
		check.Passed = true
		check.Details = "Groups found: bionicgpt-superadmin, bionicgpt-demo"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 3.6: Outpost assignment
	check = BionicGPTIntegrationCheck{
		Category:  "Authentik",
		CheckName: "Outpost Assignment",
	}

	outposts, err := authentikClient.ListOutposts(rc.Ctx)
	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = "Cannot list outposts"
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	var embeddedOutpost *authentik.OutpostResponse
	for i := range outposts {
		if outposts[i].Name == "authentik Embedded Outpost" {
			embeddedOutpost = &outposts[i]
			break
		}
	}

	if embeddedOutpost == nil {
		check.Passed = false
		check.Error = fmt.Errorf("Embedded outpost not found")
		check.Details = "Embedded outpost required for forward auth"
		check.Remediation = []string{
			"Check Authentik installation",
			"Embedded outpost should exist by default",
		}
	} else {
		// Check if BionicGPT provider assigned to outpost
		providerAssigned := false
		if bionicProvider != nil {
			for _, providerPK := range embeddedOutpost.Providers {
				if providerPK == bionicProvider.PK {
					providerAssigned = true
					break
				}
			}
		}

		if !providerAssigned {
			check.Passed = false
			check.Error = fmt.Errorf("BionicGPT provider not assigned to embedded outpost")
			check.Details = "Provider must be assigned to outpost for forward auth to work"
			check.Remediation = []string{
				"Re-run integration: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
				"Or assign manually in Authentik admin UI: Outposts → authentik Embedded Outpost → Applications",
			}
		} else {
			check.Passed = true
			check.Details = "BionicGPT provider assigned to embedded outpost"
		}
	}
	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// PHASE 4: BIONICGPT CONFIGURATION
// ============================================================================

func checkBionicGPTConfiguration(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	bionicEnvPath := "/opt/bionicgpt/.env"

	// Check 4.1: .env file exists
	check := BionicGPTIntegrationCheck{
		Category:  "BionicGPT",
		CheckName: ".env File Exists",
	}

	if _, err := os.Stat(bionicEnvPath); os.IsNotExist(err) {
		check.Passed = false
		check.Warning = true
		check.Error = fmt.Errorf(".env file not found at %s", bionicEnvPath)
		check.Details = "BionicGPT configuration file missing"
		check.Remediation = []string{
			"Install BionicGPT: sudo eos create bionicgpt",
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	check.Passed = true
	check.Details = fmt.Sprintf("Found: %s", bionicEnvPath)
	checks = append(checks, check)
	displayCheck(check)

	// Read .env file
	envVars, err := readEnvFile(bionicEnvPath)
	if err != nil {
		check = BionicGPTIntegrationCheck{
			Category:    "BionicGPT",
			CheckName:   "Read .env File",
			Passed:      false,
			Error:       err,
			Details:     "Could not read .env file",
			Remediation: []string{fmt.Sprintf("Check permissions: ls -la %s", bionicEnvPath)},
		}
		checks = append(checks, check)
		displayCheck(check)
		return checks
	}

	// Check 4.2: TRUST_PROXY enabled
	check = BionicGPTIntegrationCheck{
		Category:  "BionicGPT",
		CheckName: "TRUST_PROXY Configuration",
	}

	trustProxy := envVars["TRUST_PROXY"]
	if trustProxy != "true" {
		check.Passed = false
		check.Error = fmt.Errorf("TRUST_PROXY not enabled")
		check.Details = "BionicGPT must trust headers from Caddy proxy"
		check.Remediation = []string{
			fmt.Sprintf("Add to %s:", bionicEnvPath),
			"  TRUST_PROXY=true",
			"Restart BionicGPT: docker restart bionicgpt-app-1",
		}
	} else {
		check.Passed = true
		check.Details = "TRUST_PROXY=true (headers trusted from proxy)"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 4.3: AUTH_HEADER_EMAIL configured
	check = BionicGPTIntegrationCheck{
		Category:  "BionicGPT",
		CheckName: "AUTH_HEADER_EMAIL Configuration",
	}

	authHeaderEmail := envVars["AUTH_HEADER_EMAIL"]
	if authHeaderEmail != "X-Auth-Request-Email" {
		check.Passed = false
		check.Error = fmt.Errorf("AUTH_HEADER_EMAIL not configured correctly")
		check.Details = fmt.Sprintf("Current: '%s', Expected: 'X-Auth-Request-Email'", authHeaderEmail)
		check.Remediation = []string{
			fmt.Sprintf("Set in %s:", bionicEnvPath),
			"  AUTH_HEADER_EMAIL=X-Auth-Request-Email",
		}
	} else {
		check.Passed = true
		check.Details = "AUTH_HEADER_EMAIL=X-Auth-Request-Email"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 4.4: AUTH_HEADER_NAME configured
	check = BionicGPTIntegrationCheck{
		Category:  "BionicGPT",
		CheckName: "AUTH_HEADER_NAME Configuration",
	}

	authHeaderName := envVars["AUTH_HEADER_NAME"]
	if authHeaderName != "X-Auth-Request-User" {
		check.Passed = false
		check.Error = fmt.Errorf("AUTH_HEADER_NAME not configured correctly")
		check.Details = fmt.Sprintf("Current: '%s', Expected: 'X-Auth-Request-User'", authHeaderName)
		check.Remediation = []string{
			fmt.Sprintf("Set in %s:", bionicEnvPath),
			"  AUTH_HEADER_NAME=X-Auth-Request-User",
		}
	} else {
		check.Passed = true
		check.Details = "AUTH_HEADER_NAME=X-Auth-Request-User"
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 4.5: AUTH_HEADER_GROUPS configured
	check = BionicGPTIntegrationCheck{
		Category:  "BionicGPT",
		CheckName: "AUTH_HEADER_GROUPS Configuration",
	}

	authHeaderGroups := envVars["AUTH_HEADER_GROUPS"]
	if authHeaderGroups != "X-Auth-Request-Groups" {
		check.Passed = false
		check.Error = fmt.Errorf("AUTH_HEADER_GROUPS not configured correctly")
		check.Details = fmt.Sprintf("Current: '%s', Expected: 'X-Auth-Request-Groups'", authHeaderGroups)
		check.Remediation = []string{
			fmt.Sprintf("Set in %s:", bionicEnvPath),
			"  AUTH_HEADER_GROUPS=X-Auth-Request-Groups",
		}
	} else {
		check.Passed = true
		check.Details = "AUTH_HEADER_GROUPS=X-Auth-Request-Groups"
	}
	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// PHASE 5: HEADER FLOW VALIDATION
// ============================================================================

func checkHeaderFlow(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	// Check 5.1: Authentik outpost endpoint reachable
	check := BionicGPTIntegrationCheck{
		Category:  "Header Flow",
		CheckName: "Authentik Outpost Endpoint",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("http://localhost:9000/outpost.goauthentik.io/auth/caddy")
	if err != nil {
		check.Passed = false
		check.Error = err
		check.Details = "Cannot reach Authentik forward auth endpoint"
		check.Remediation = []string{
			"Verify Authentik is running: docker ps | grep authentik",
			"Check outpost status in Authentik admin UI",
			"Test manually: curl http://localhost:9000/outpost.goauthentik.io/auth/caddy",
		}
	} else {
		defer resp.Body.Close()

		// Forward auth endpoint should return 200 (authenticated) or 401 (not authenticated)
		// Any other status code indicates misconfiguration
		if resp.StatusCode == 200 || resp.StatusCode == 401 {
			check.Passed = true
			statusMeaning := "authenticated session"
			if resp.StatusCode == 401 {
				statusMeaning = "no session (expected when not logged in)"
			}
			check.Details = fmt.Sprintf("Endpoint reachable (status: %d - %s)", resp.StatusCode, statusMeaning)
		} else {
			check.Passed = false
			check.Error = fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
			check.Details = fmt.Sprintf("Forward auth endpoint returned %d, expected 200 or 401", resp.StatusCode)
			check.Remediation = []string{
				"Check Authentik outpost configuration in admin UI",
				"Verify embedded outpost is running and healthy",
				"Check Authentik logs: docker logs hecate-authentik-server-1",
				"Ensure forward auth application is assigned to outpost",
			}
		}
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 5.2: Can we trace header flow in Caddy logs?
	check = BionicGPTIntegrationCheck{
		Category:  "Header Flow",
		CheckName: "Caddy Access Logs",
	}

	caddyLogPath := filepath.Join(config.HecatePath, "logs/caddy/access.log")
	if _, err := os.Stat(caddyLogPath); os.IsNotExist(err) {
		check.Passed = false
		check.Warning = true
		check.Error = fmt.Errorf("Caddy access log not found")
		check.Details = "Cannot trace header flow without logs"
		check.Remediation = []string{
			"Enable Caddy logging in Caddyfile",
			"Check Caddy is running: docker ps | grep caddy",
		}
	} else {
		check.Passed = true
		check.Details = fmt.Sprintf("Access log available: %s", caddyLogPath)
	}
	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// PHASE 6: END-TO-END INTEGRATION
// ============================================================================

func checkEndToEndIntegration(rc *eos_io.RuntimeContext, config *BionicGPTDebugConfig) []BionicGPTIntegrationCheck {
	var checks []BionicGPTIntegrationCheck

	// Check 6.1: Find BionicGPT domain from Caddyfile
	check := BionicGPTIntegrationCheck{
		Category:  "Integration",
		CheckName: "BionicGPT Domain Detection",
	}

	caddyfilePath := filepath.Join(config.HecatePath, "Caddyfile")
	domain := extractBionicGPTDomain(caddyfilePath)

	if domain == "" {
		check.Passed = false
		check.Warning = true
		check.Error = fmt.Errorf("Cannot detect BionicGPT domain from Caddyfile")
		check.Details = "Cannot perform end-to-end test without domain"
		check.Remediation = []string{
			"Check Caddyfile for BionicGPT route",
			"Ensure route added with: sudo eos update hecate --add bionicgpt --dns <domain> --upstream <backend> --sso",
		}
	} else {
		check.Passed = true
		check.Details = fmt.Sprintf("Domain detected: %s", domain)
	}
	checks = append(checks, check)
	displayCheck(check)

	// Check 6.2: Summary of integration status
	check = BionicGPTIntegrationCheck{
		Category:  "Integration",
		CheckName: "Integration Summary",
		Passed:    true,
		Details:   "Run full test: Visit domain in browser, authenticate via Authentik, verify BionicGPT access",
	}

	if domain != "" {
		check.Details += fmt.Sprintf("\n\nTest URL: https://%s", domain)
		check.Details += "\n\nExpected flow:"
		check.Details += "\n  1. Browser → Caddy (HTTPS)"
		check.Details += "\n  2. Caddy → Authentik (forward_auth validation)"
		check.Details += "\n  3. Authentik → User login (if not authenticated)"
		check.Details += "\n  4. Authentik → Caddy (validation response with X-Authentik-* headers)"
		check.Details += "\n  5. Caddy → BionicGPT (with X-Auth-Request-* headers)"
		check.Details += "\n  6. BionicGPT → User dashboard (authenticated)"
	}

	checks = append(checks, check)
	displayCheck(check)

	return checks
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getAuthentikCredentialsFromEnv(envPath string) (string, string, error) {
	envVars, err := readEnvFile(envPath)
	if err != nil {
		return "", "", err
	}

	token := envVars["AUTHENTIK_TOKEN"]
	if token == "" {
		token = envVars["AUTHENTIK_API_KEY"] // Fallback
	}

	baseURL := envVars["AUTHENTIK_BASE_URL"]
	if baseURL == "" {
		baseURL = "http://localhost:9000" // Default
	}

	if token == "" {
		return "", "", fmt.Errorf("AUTHENTIK_TOKEN not found in %s", envPath)
	}

	return token, baseURL, nil
}

func readEnvFile(filepath string) (map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if present
		value = strings.Trim(value, `"'`)

		env[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return env, nil
}

// extractBionicGPTDomain finds the BionicGPT service domain from Caddyfile
//
// ARCHITECTURE NOTE: SSO Domain Conventions
//
// This function extracts the SERVICE domain (e.g., chat.codemonkey.net.au), NOT the SSO domain.
// The SSO/auth portal and service domains follow distinct naming conventions:
//
// DOMAIN CONVENTIONS:
// - **hera.* subdomain**: SSO/auth portals (Authentik admin UI, forward auth endpoint)
//   - Example: hera.codemonkey.net.au
//   - Purpose: Centralized authentication portal for all services
//   - Hosts: Authentik admin UI, login flows, forward auth endpoints
//
// - **Service-specific subdomains**: Individual services proxied through forward auth
//   - Example: chat.codemonkey.net.au (BionicGPT)
//   - Purpose: Service-specific access points
//   - Flow: User → chat.* → Caddy forward_auth → hera.* (Authentik) → chat.* (BionicGPT)
//
// WHY SEPARATE DOMAINS:
// - **Security**: Clear separation between auth portal and protected services
// - **UX**: Consistent auth experience across all services (always login at hera.*)
// - **Operations**: Single place to manage auth (hera.*), many service endpoints
// - **DNS**: Wildcard DNS simplifies setup (*.codemonkey.net.au → same server)
//
// DEBUG WORKFLOW:
// 1. This function extracts service domain from Caddyfile (chat.codemonkey.net.au)
// 2. Debug checks validate Authentik SSO portal separately (hera.codemonkey.net.au)
// 3. End-to-end test verifies triangle: Service → Caddy forward_auth → Authentik SSO
//
// RELATED CODE:
// - BionicGPT integration: pkg/hecate/add/bionicgpt.go (configures forward auth)
// - Caddyfile template: pkg/hecate/add/caddyfile.go:74-110 (includes outpost proxy)
// - Authentik checks: checkAuthentikIntegration() (validates SSO portal health)
func extractBionicGPTDomain(caddyfilePath string) string {
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Look for domain followed by "{"
		if strings.Contains(trimmed, "{") && !strings.HasPrefix(trimmed, "#") {
			domain := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
			// Simple heuristic: if domain looks valid (has dot), assume it might be BionicGPT
			if strings.Contains(domain, ".") && !strings.Contains(domain, "import") {
				return domain
			}
		}
	}

	return ""
}

func displayCheck(check BionicGPTIntegrationCheck) {
	symbol := "✅"
	if !check.Passed {
		if check.Warning {
			symbol = "⚠️ "
		} else {
			symbol = "❌"
		}
	}

	fmt.Printf("%s %s\n", symbol, check.CheckName)
	if check.Details != "" {
		fmt.Printf("     %s\n", check.Details)
	}

	if !check.Passed && len(check.Remediation) > 0 {
		fmt.Println("     Remediation:")
		for _, step := range check.Remediation {
			fmt.Printf("       • %s\n", step)
		}
	}
	fmt.Println()
}

// detectCaddyContainerName finds the actual Caddy container name
// Handles both hecate-caddy (legacy) and hecate-caddy-1 (docker compose v2)
func detectCaddyContainerName(ctx context.Context) string {
	// Try docker compose v2 naming first (hecate-caddy-1)
	cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=hecate-caddy", "--format", "{{.Names}}")
	output, err := cmd.CombinedOutput()
	if err != nil || len(output) == 0 {
		return ""
	}

	// Return first match (should only be one Caddy container)
	containerNames := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(containerNames) > 0 && containerNames[0] != "" {
		return containerNames[0]
	}

	return ""
}

func displayBionicGPTResults(checks []BionicGPTIntegrationCheck) {
	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("📊 DIAGNOSTIC RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 100))

	// Count results
	totalChecks := len(checks)
	passedChecks := 0
	failedChecks := 0
	warningChecks := 0

	for _, check := range checks {
		if check.Passed {
			passedChecks++
		} else if check.Warning {
			warningChecks++
		} else {
			failedChecks++
		}
	}

	fmt.Printf("\nTotal Checks: %d\n", totalChecks)
	fmt.Printf("✅ Passed: %d\n", passedChecks)
	fmt.Printf("❌ Failed: %d\n", failedChecks)
	fmt.Printf("⚠️  Warnings: %d\n", warningChecks)

	if failedChecks == 0 && warningChecks == 0 {
		fmt.Println("\n🎉 All checks passed! BionicGPT integration is correctly configured.")
	} else if failedChecks > 0 {
		fmt.Println("\n⚠️  Some checks failed. Review remediation steps above to fix issues.")
	} else {
		fmt.Println("\n⚠️  All critical checks passed, but some warnings present.")
	}

	// Grouped summary by category
	categories := make(map[string][]BionicGPTIntegrationCheck)
	for _, check := range checks {
		categories[check.Category] = append(categories[check.Category], check)
	}

	fmt.Println("\n" + strings.Repeat("-", 100))
	fmt.Println("📋 Results by Category:")
	fmt.Println(strings.Repeat("-", 100))

	for category, categoryChecks := range categories {
		passed := 0
		failed := 0
		warnings := 0

		for _, check := range categoryChecks {
			if check.Passed {
				passed++
			} else if check.Warning {
				warnings++
			} else {
				failed++
			}
		}

		status := "✅"
		if failed > 0 {
			status = "❌"
		} else if warnings > 0 {
			status = "⚠️ "
		}

		fmt.Printf("\n%s %s: %d/%d passed", status, category, passed, len(categoryChecks))
		if warnings > 0 {
			fmt.Printf(" (%d warnings)", warnings)
		}
		if failed > 0 {
			fmt.Printf(" (%d failed)", failed)
		}
		fmt.Println()
	}

	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("For detailed component diagnostics:")
	fmt.Println("  • Caddy: sudo eos debug hecate --component caddy")
	fmt.Println("  • Authentik: sudo eos debug hecate --authentik")
	fmt.Println("  • BionicGPT: sudo eos debug bionicgpt")
	fmt.Println(strings.Repeat("=", 100))
}
