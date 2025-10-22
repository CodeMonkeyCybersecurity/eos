// pkg/debug/bionicgpt/auth_diagnostic.go
// BionicGPT authentication issue diagnostic
// Diagnoses why BionicGPT shows "Didn't find an authentication header" instead of login page

package bionicgpt

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthenticationIssueDiagnostic diagnoses why BionicGPT shows "Didn't find an authentication header" instead of login page
// This comprehensive check covers: app logs, user database state, auth config, routes, registration settings,
// OIDC/OAuth config, initial setup requirements, and HTTP request details
func AuthenticationIssueDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Authentication Issue Diagnosis",
		Category:    "Authentication",
		Description: "Diagnose why BionicGPT shows authentication error instead of login page",
		Condition: func(ctx context.Context) bool {
			// Only run if installation directory and app container exist
			_, dirErr := os.Stat(DefaultInstallDir)
			cmd := exec.CommandContext(ctx, "docker", "ps", "-q", "--filter", fmt.Sprintf("name=%s", bionicgpt.ContainerApp))
			output, cmdErr := cmd.Output()
			return dirErr == nil && cmdErr == nil && len(output) > 0
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("═══════════════════════════════════════════════════════════════\n")
			output.WriteString("BionicGPT Authentication Issue Diagnosis\n")
			output.WriteString("Why showing 'authentication header' error instead of login page?\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

			errorCount := 0

			// 1. CHECK APP LOGS FOR ERRORS
			errorCount += checkAppLogs(ctx, &output)

			// 2. CHECK IF THIS IS FIRST RUN
			errorCount += checkFirstRun(ctx, &output, result)

			// 3. CHECK AUTHENTICATION CONFIGURATION
			errorCount += checkAuthConfig(ctx, &output)

			// 4. CHECK APP ROUTES/ENDPOINTS
			errorCount += checkAppRoutes(ctx, &output)

			// 5. CHECK IF REGISTRATION IS ENABLED
			checkRegistration(ctx, &output)

			// 6. CHECK HEALTH ENDPOINT DETAIL
			checkHealthEndpoint(ctx, &output)

			// 7. CHECK IF INITIAL SETUP REQUIRED
			errorCount += checkInitialSetup(ctx, &output)

			// 8. TEST WITH FULL HTTP REQUEST DETAILS
			checkHTTPDetails(ctx, &output)

			// 9. CHECK IF OIDC/OAUTH REQUIRED
			checkOAuthConfig(ctx, &output)

			// 10. CHECK FOR ADDRESS IN USE ERRORS
			errorCount += checkAddressInUseErrors(ctx, &output)

			// 11. CHECK USERS TABLE STRUCTURE
			checkUsersTableStructure(ctx, &output)

			// ANALYSIS SECTION
			output.WriteString("\n═══════════════════════════════════════════════════════════════\n")
			output.WriteString("Analysis\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")
			output.WriteString("Common causes for this issue:\n")
			output.WriteString("1. App expects OAuth/OIDC but it's not configured\n")
			output.WriteString("2. First-time setup not completed (need to create initial user)\n")
			output.WriteString("3. Authentication middleware blocking all routes\n")
			output.WriteString("4. Missing JWT secret or authentication configuration\n")
			output.WriteString("5. Database migrations didn't create required tables\n\n")
			output.WriteString("Check the app logs above for specific errors or clues\n")

			result.Output = output.String()
			result.Metadata["error_count"] = errorCount

			// Set status based on findings
			if errorCount > 3 {
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("Multiple authentication issues found (%d errors)", errorCount)
				result.Remediation = "Review diagnostic output. Key checks:\n" +
					"1. Ensure JWT_SECRET is set in .env\n" +
					"2. Check database initialization (users table)\n" +
					"3. Verify app logs for auth errors\n" +
					"4. If first run, check /setup endpoint\n" +
					"5. Consider: sudo eos create bionicgpt --force"
			} else if errorCount > 0 {
				result.Status = debug.StatusWarning
				result.Message = "Authentication configuration has some issues"
				result.Remediation = "Review specific errors in output and address individually"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Authentication configuration appears valid"
			}

			logger.Info("Authentication diagnosis completed",
				zap.Int("error_count", errorCount))

			return result, nil
		},
	}
}

// checkAppLogs retrieves and analyzes app container logs
func checkAppLogs(ctx context.Context, output *strings.Builder) int {
	output.WriteString("1. CHECK APP LOGS FOR ERRORS\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Last 50 lines of app logs:\n")

	cmd := exec.CommandContext(ctx, "docker", "logs", bionicgpt.ContainerApp, "--tail", "50")
	logs, err := cmd.CombinedOutput()
	if err != nil {
		output.WriteString(fmt.Sprintf("ERROR: Could not retrieve app logs: %v\n", err))
		return 1
	}

	output.WriteString(string(logs))
	output.WriteString("\n")

	// Check for auth-related errors
	logsLower := strings.ToLower(string(logs))
	if strings.Contains(logsLower, "auth") || strings.Contains(logsLower, "jwt") || strings.Contains(logsLower, "token") {
		output.WriteString("⚠ Found authentication-related messages in logs\n")
		return 1
	}

	return 0
}

// checkFirstRun checks if any users exist in the database
func checkFirstRun(ctx context.Context, output *strings.Builder, result *debug.Result) int {
	output.WriteString("\n2. CHECK IF THIS IS FIRST RUN (No users created yet)\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Checking if any users exist in database:\n")

	cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", "bionic_application", "-d", "bionic-gpt",
		"-c", "SELECT COUNT(*) as user_count FROM users;")
	userCheckOutput, err := cmd.CombinedOutput()
	if err != nil {
		output.WriteString(fmt.Sprintf("Could not query users table: %v\n", err))
		output.WriteString(string(userCheckOutput))
		output.WriteString("⚠ Database might not be initialized or users table doesn't exist\n")
		return 1
	}

	output.WriteString(string(userCheckOutput))
	if strings.Contains(string(userCheckOutput), " 0") {
		output.WriteString("⚠ No users found - FIRST RUN, setup wizard should appear\n")
		result.Metadata["first_run"] = true
	} else {
		result.Metadata["first_run"] = false
	}

	return 0
}

// checkAuthConfig checks authentication configuration in .env file
func checkAuthConfig(ctx context.Context, output *strings.Builder) int {
	output.WriteString("\n3. CHECK AUTHENTICATION CONFIGURATION\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")

	envData, err := os.ReadFile(DefaultEnvFile)
	if err != nil {
		output.WriteString(fmt.Sprintf("ERROR: Could not read .env file: %v\n", err))
		return 1
	}

	errorCount := 0

	// Check JWT_SECRET
	if strings.Contains(string(envData), "JWT_SECRET") {
		output.WriteString("✓ JWT_SECRET is set\n")
	} else {
		output.WriteString("✗ JWT_SECRET not found in .env\n")
		errorCount++
	}

	// Check for AUTH-related config
	output.WriteString("\nAuthentication mode configuration:\n")
	scanner := bufio.NewScanner(strings.NewReader(string(envData)))
	foundAuthConfig := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToUpper(line), "AUTH") && !strings.Contains(line, "PASSWORD") {
			output.WriteString(line + "\n")
			foundAuthConfig = true
		}
	}
	if !foundAuthConfig {
		output.WriteString("(No AUTH configuration found)\n")
	}

	return errorCount
}

// checkAppRoutes tests various application endpoints
func checkAppRoutes(ctx context.Context, output *strings.Builder) int {
	output.WriteString("\n4. CHECK APP ROUTES/ENDPOINTS\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Testing various endpoints:\n\n")

	endpoints := map[string]string{
		"/ (root)":      "/",
		"/auth/sign_in": "/auth/sign_in",
		"/auth/sign_up": "/auth/sign_up",
		"/setup":        "/setup",
	}

	errorCount := 0
	for name, path := range endpoints {
		cmd := exec.CommandContext(ctx, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			fmt.Sprintf("http://localhost:%d%s", DefaultPort, path))
		statusOutput, err := cmd.CombinedOutput()
		status := strings.TrimSpace(string(statusOutput))
		if err != nil {
			output.WriteString(fmt.Sprintf("%s: ERROR (could not connect)\n", name))
			errorCount++
		} else {
			output.WriteString(fmt.Sprintf("%s: HTTP %s\n", name, status))
			if status == "404" || status == "500" {
				errorCount++
			}
		}
	}
	output.WriteString("\n")

	return errorCount
}

// checkRegistration checks registration settings
func checkRegistration(ctx context.Context, output *strings.Builder) {
	output.WriteString("5. CHECK IF REGISTRATION IS ENABLED\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Looking for registration settings in env:\n")

	envData, err := os.ReadFile(DefaultEnvFile)
	if err != nil {
		output.WriteString("Could not read .env file\n")
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(envData)))
	foundRegConfig := false
	for scanner.Scan() {
		line := scanner.Text()
		upperLine := strings.ToUpper(line)
		if strings.Contains(upperLine, "ENABLE") && (strings.Contains(upperLine, "REG") || strings.Contains(upperLine, "SIGN")) {
			output.WriteString(line + "\n")
			foundRegConfig = true
		}
	}
	if !foundRegConfig {
		output.WriteString("(No registration settings found in .env)\n")
	}
	output.WriteString("\n")
}

// checkHealthEndpoint checks Docker health status
func checkHealthEndpoint(ctx context.Context, output *strings.Builder) {
	output.WriteString("6. CHECK HEALTH ENDPOINT DETAIL\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")

	cmd := exec.CommandContext(ctx, "docker", "inspect", bionicgpt.ContainerApp, "--format", "{{json .State.Health}}")
	healthOutput, err := cmd.CombinedOutput()
	if err != nil {
		output.WriteString("Health check info not available\n")
	} else {
		output.WriteString(string(healthOutput) + "\n")
	}
	output.WriteString("\n")
}

// checkInitialSetup checks database tables
func checkInitialSetup(ctx context.Context, output *strings.Builder) int {
	output.WriteString("7. CHECK IF INITIAL SETUP REQUIRED\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Checking for setup/initialization tables:\n")

	cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", "bionic_application", "-d", "bionic-gpt", "-c", "\\dt")
	tablesOutput, err := cmd.CombinedOutput()
	if err != nil {
		output.WriteString(fmt.Sprintf("Could not list tables: %v\n", err))
		return 1
	}

	lines := strings.Split(string(tablesOutput), "\n")
	if len(lines) > 20 {
		lines = lines[:20]
	}
	output.WriteString(strings.Join(lines, "\n") + "\n\n")

	return 0
}

// checkHTTPDetails performs verbose HTTP request
func checkHTTPDetails(ctx context.Context, output *strings.Builder) {
	output.WriteString("8. TEST WITH FULL HTTP REQUEST DETAILS\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Full verbose request to root:\n")

	cmd := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("curl -v http://localhost:%d/ 2>&1 | grep -E 'HTTP|Location|Set-Cookie|Content-Type'", DefaultPort))
	verboseOutput, err := cmd.CombinedOutput()
	if err == nil {
		output.WriteString(string(verboseOutput))
	} else {
		output.WriteString("Could not perform verbose HTTP request\n")
	}
	output.WriteString("\n")
}

// checkOAuthConfig checks OAuth/OIDC configuration
func checkOAuthConfig(ctx context.Context, output *strings.Builder) {
	output.WriteString("9. CHECK IF OIDC/OAUTH REQUIRED\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Looking for OAuth/OIDC configuration:\n")

	envData, err := os.ReadFile(DefaultEnvFile)
	if err != nil {
		output.WriteString("Could not read .env file\n")
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(envData)))
	foundOAuthConfig := false
	for scanner.Scan() {
		line := scanner.Text()
		upperLine := strings.ToUpper(line)
		if strings.Contains(upperLine, "OAUTH") || strings.Contains(upperLine, "OIDC") || strings.Contains(upperLine, "IDP") {
			output.WriteString(line + "\n")
			foundOAuthConfig = true
		}
	}
	if !foundOAuthConfig {
		output.WriteString("(No OAuth/OIDC configuration found)\n")
	}

	output.WriteString("\nRecent auth-related logs:\n")
	cmd := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("docker logs %s 2>&1 | grep -i 'oauth\\|oidc\\|auth' | tail -10", bionicgpt.ContainerApp))
	authLogsOutput, err := cmd.CombinedOutput()
	if err == nil && len(authLogsOutput) > 0 {
		output.WriteString(string(authLogsOutput))
	} else {
		output.WriteString("(No recent auth-related log entries)\n")
	}
	output.WriteString("\n")
}

// checkAddressInUseErrors checks for "Address in use" errors in app container logs
// This error indicates the app is failing to start because port is already bound
func checkAddressInUseErrors(ctx context.Context, output *strings.Builder) int {
	output.WriteString("10. CHECK FOR ADDRESS IN USE ERRORS\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Checking app logs for 'Address in use' errors:\n")

	// Get last 100 lines to check for the error
	cmd := exec.CommandContext(ctx, "docker", "logs", bionicgpt.ContainerApp, "--tail", "100")
	logs, err := cmd.CombinedOutput()
	if err != nil {
		output.WriteString(fmt.Sprintf("Could not retrieve app logs: %v\n", err))
		return 0
	}

	logsStr := string(logs)

	// Check for "Address in use" error (code 98)
	if strings.Contains(logsStr, "Address in use") || strings.Contains(logsStr, "code: 98") {
		output.WriteString("✗ CRITICAL: Found 'Address in use' error in app logs\n")
		output.WriteString("The app container is failing to start because the port is already bound.\n\n")

		// Extract relevant error lines
		scanner := bufio.NewScanner(strings.NewReader(logsStr))
		errorLines := []string{}
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Address in use") || strings.Contains(line, "PANIC") || strings.Contains(line, "ERROR") {
				errorLines = append(errorLines, line)
			}
		}

		if len(errorLines) > 0 {
			output.WriteString("Error details:\n")
			// Show last 10 error lines
			start := 0
			if len(errorLines) > 10 {
				start = len(errorLines) - 10
			}
			for i := start; i < len(errorLines); i++ {
				output.WriteString(fmt.Sprintf("  %s\n", errorLines[i]))
			}
		}

		output.WriteString("\nREMEDIATION:\n")
		output.WriteString("1. Check what's using the port: sudo ss -tlnp | grep 8513\n")
		output.WriteString("2. Stop conflicting containers: docker compose -f /opt/bionicgpt/docker-compose.yml down\n")
		output.WriteString("3. Restart: docker compose -f /opt/bionicgpt/docker-compose.yml up -d\n")
		output.WriteString("\n")
		return 1
	}

	output.WriteString("✓ No 'Address in use' errors found\n\n")
	return 0
}

// checkUsersTableStructure checks the database users table structure
// This verifies that migrations ran correctly and the table has expected columns
func checkUsersTableStructure(ctx context.Context, output *strings.Builder) {
	output.WriteString("11. CHECK USERS TABLE STRUCTURE\n")
	output.WriteString("───────────────────────────────────────────────────────────\n")
	output.WriteString("Checking users table structure to verify migrations:\n")

	cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", "bionic_application", "-d", "bionic-gpt", "-c", "\\d users")
	tableOutput, err := cmd.CombinedOutput()

	if err != nil {
		output.WriteString(fmt.Sprintf("✗ Could not describe users table: %v\n", err))
		output.WriteString(string(tableOutput))
		output.WriteString("\nThis likely means migrations haven't run or failed.\n")
		output.WriteString("Check migrations container logs: docker logs bionicgpt-db-migrations\n\n")
		return
	}

	tableStr := string(tableOutput)
	output.WriteString(tableStr)
	output.WriteString("\n")

	// Verify key columns exist
	requiredColumns := []string{"id", "email", "openid_sub", "system_admin", "first_name", "last_name"}
	missingColumns := []string{}

	for _, col := range requiredColumns {
		if !strings.Contains(tableStr, col) {
			missingColumns = append(missingColumns, col)
		}
	}

	if len(missingColumns) > 0 {
		output.WriteString(fmt.Sprintf("⚠ Missing expected columns: %v\n", missingColumns))
		output.WriteString("Database schema may be incomplete or migrations failed.\n")
	} else {
		output.WriteString("✓ All expected columns present in users table\n")
	}

	// Check for the important trigger
	if strings.Contains(tableStr, "set_first_user_as_admin") {
		output.WriteString("✓ First user admin trigger is configured\n")
	} else {
		output.WriteString("⚠ Missing 'set_first_user_as_admin' trigger\n")
	}

	output.WriteString("\n")
}
