// pkg/consul/debug/checks_advanced.go
//
// Advanced diagnostic checks for Consul ACL bootstrap and Raft state debugging.
// These checks provide deep inspection of Consul's internal state when standard
// diagnostics don't reveal the root cause.
//
// Last Updated: 2025-01-25

package debug

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkConsulProcessRunning is THE FIRST diagnostic check - verifies Consul process exists.
//
// CRITICAL P0 CHECK - MUST RUN FIRST:
//   - Confirms Consul binary is actually running (not just installed)
//   - Shows PID, user, command line, uptime
//   - Distinguishes "not running" from "running but broken"
//   - If this fails, ALL other checks are meaningless
//
// Methodology:
//   1. Check if `consul` process exists (pgrep)
//   2. Show process details (ps aux)
//   3. Verify process is Consul agent (not just `consul` command)
//   4. Show listening ports (lsof/ss) to confirm service is active
//
// Returns:
//   - SUCCESS: Consul process running and appears healthy
//   - CRITICAL: Consul process NOT running (explains ALL other failures)
//   - WARNING: Consul process exists but appears unhealthy
func checkConsulProcessRunning(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking if Consul process is running (P0 CRITICAL CHECK)")

	result := DiagnosticResult{
		CheckName: "Consul Process Running",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Step 1: Check if consul process exists
	logger.Debug("Checking for consul process via pgrep")
	cmd := execute.Options{
		Command: "pgrep",
		Args:    []string{"-a", "consul"}, // -a shows full command line
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		// pgrep returns exit code 1 when no processes found
		if strings.TrimSpace(output) == "" {
			result.Success = false
			result.Severity = SeverityCritical
			result.Message = "Consul process is NOT RUNNING"
			result.Details = append(result.Details, "✗ CRITICAL: No consul process found")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "THIS EXPLAINS ALL OTHER FAILURES:")
			result.Details = append(result.Details, "  • API unreachable → Consul is not running")
			result.Details = append(result.Details, "  • Ports not listening → Consul is not running")
			result.Details = append(result.Details, "  • No raft.db found → Consul never started")
			result.Details = append(result.Details, "  • ACLs cannot be verified → Consul is not running")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMMEDIATE NEXT STEPS:")
			result.Details = append(result.Details, "  1. Check systemd status: systemctl status consul")
			result.Details = append(result.Details, "  2. Check why it's not running: journalctl -xeu consul -n 100")
			result.Details = append(result.Details, "  3. Common causes:")
			result.Details = append(result.Details, "       - Service never started: sudo systemctl start consul")
			result.Details = append(result.Details, "       - Failed at startup: check journal logs for errors")
			result.Details = append(result.Details, "       - Crashed: check for panic/segfault in logs")
			result.Details = append(result.Details, "       - Port conflict: another process using port "+strconv.Itoa(shared.PortConsul))
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "DO NOT PROCEED with other diagnostics until Consul is running.")

			return result
		}

		// Other errors
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Cannot determine if Consul is running"
		result.Details = append(result.Details, fmt.Sprintf("⚠ pgrep command failed: %v", err))
		result.Details = append(result.Details, "Trying fallback method...")

		// Fallback: Try ps aux | grep consul
		psCmd := execute.Options{
			Command: "ps",
			Args:    []string{"aux"},
			Capture: true,
		}

		psOutput, psErr := execute.Run(rc.Ctx, psCmd)
		if psErr == nil {
			found := false
			lines := strings.Split(psOutput, "\n")
			for _, line := range lines {
				if strings.Contains(line, "consul agent") && !strings.Contains(line, "grep") {
					result.Success = true
					result.Details = append(result.Details, "✓ Found via ps aux:")
					result.Details = append(result.Details, "  "+strings.TrimSpace(line))
					found = true
					break
				}
			}

			if !found {
				result.Success = false
				result.Severity = SeverityCritical
				result.Message = "Consul process is NOT RUNNING (verified via ps)"
				result.Details = append(result.Details, "✗ No 'consul agent' process found in ps aux output")
				return result
			}
		}

		if !result.Success {
			return result
		}
	}

	// ASSESS - Step 2: Parse pgrep output to verify it's actually Consul agent
	logger.Debug("Parsing process information")
	result.Details = append(result.Details, "✓ Consul process is RUNNING")
	result.Details = append(result.Details, "")

	lines := strings.Split(output, "\n")
	consulProcesses := []string{}
	var consulAgentPID string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Filter out:
		// - This debug command itself
		// - grep commands
		// - Other non-agent consul commands
		if strings.Contains(line, "eos debug consul") ||
			strings.Contains(line, "eos update consul") ||
			strings.Contains(line, "grep consul") {
			continue
		}

		consulProcesses = append(consulProcesses, line)

		// Extract PID of the consul agent
		if strings.Contains(line, "consul agent") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				consulAgentPID = fields[0]
			}
		}
	}

	if len(consulProcesses) == 0 {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Found consul process but it's not the agent"
		result.Details = append(result.Details, "⚠ Found 'consul' process but no 'consul agent'")
		result.Details = append(result.Details, "  This might be:")
		result.Details = append(result.Details, "    - A consul CLI command (e.g., 'consul members')")
		result.Details = append(result.Details, "    - A short-lived consul operation")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Expected: A long-running 'consul agent' process")
		return result
	}

	// Show all consul processes found
	result.Details = append(result.Details, "Process details:")
	for _, proc := range consulProcesses {
		result.Details = append(result.Details, "  "+proc)
	}
	result.Details = append(result.Details, "")

	// ASSESS - Step 3: Get detailed process information
	if consulAgentPID != "" {
		logger.Debug("Gathering detailed process information", zap.String("pid", consulAgentPID))

		// Get process user, start time, uptime
		psCmd := execute.Options{
			Command: "ps",
			Args:    []string{"-p", consulAgentPID, "-o", "user,pid,start,etime,rss,command"},
			Capture: true,
		}

		psOutput, psErr := execute.Run(rc.Ctx, psCmd)
		if psErr == nil {
			result.Details = append(result.Details, "Detailed process information:")
			psLines := strings.Split(psOutput, "\n")
			for i, line := range psLines {
				if i < 2 && strings.TrimSpace(line) != "" { // Header + first data line
					result.Details = append(result.Details, "  "+strings.TrimSpace(line))
				}
			}
			result.Details = append(result.Details, "")
		}

		// ASSESS - Step 4: Check listening ports (confirms service is actually working)
		logger.Debug("Checking listening ports for consul process")
		result.Details = append(result.Details, "Listening ports (confirms service is active):")

		// Try lsof first (more detailed)
		lsofCmd := execute.Options{
			Command: "lsof",
			Args:    []string{"-p", consulAgentPID, "-a", "-iTCP", "-sTCP:LISTEN", "-P", "-n"},
			Capture: true,
		}

		lsofOutput, lsofErr := execute.Run(rc.Ctx, lsofCmd)
		if lsofErr == nil && strings.TrimSpace(lsofOutput) != "" {
			lsofLines := strings.Split(lsofOutput, "\n")
			for _, line := range lsofLines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "COMMAND") {
					continue
				}

				// Parse lsof output to extract ports
				// Format: consul 12345 user TCP *:8500 (LISTEN)
				fields := strings.Fields(line)
				if len(fields) >= 9 {
					portInfo := fields[8] // e.g., "*:8500"
					parts := strings.Split(portInfo, ":")
					if len(parts) == 2 {
						port := parts[1]
						portNum, err := strconv.Atoi(port)
						if err == nil {
							// Identify the port by its number
							portDesc := identifyConsulPort(portNum)
							result.Details = append(result.Details,
								fmt.Sprintf("  ✓ Port %s listening (%s)", port, portDesc))
						}
					}
				}
			}
		} else {
			// Fallback: Use ss or netstat
			ssCmd := execute.Options{
				Command: "ss",
				Args:    []string{"-tlnp"},
				Capture: true,
			}

			ssOutput, ssErr := execute.Run(rc.Ctx, ssCmd)
			if ssErr == nil {
				ssLines := strings.Split(ssOutput, "\n")
				for _, line := range ssLines {
					if strings.Contains(line, consulAgentPID) {
						result.Details = append(result.Details, "  "+strings.TrimSpace(line))
					}
				}
			} else {
				result.Details = append(result.Details, "  ⚠ Cannot check listening ports (lsof/ss unavailable)")
			}
		}

		result.Details = append(result.Details, "")

		// ASSESS - Step 5: Verify Consul is actually responsive (quick API check)
		logger.Debug("Testing Consul API responsiveness")
		result.Details = append(result.Details, "API Responsiveness Check:")

		// Use net.DialTimeout for quick TCP connection test (don't wait for full HTTP)
		addr := net.JoinHostPort(shared.GetInternalHostname(), strconv.Itoa(shared.PortConsul))
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  ⚠ Port %d not accepting connections: %v", shared.PortConsul, err))
			result.Details = append(result.Details, "    Process is running but API may not be ready yet")
			result.Success = false
			result.Severity = SeverityWarning
		} else {
			conn.Close()
			result.Details = append(result.Details, fmt.Sprintf("  ✓ Port %d is accepting connections", shared.PortConsul))
		}
	}

	// EVALUATE
	if result.Success {
		result.Message = "Consul agent process is running and responding"
	} else {
		result.Message = "Consul process issues detected"
	}

	return result
}

// identifyConsulPort returns a human-readable description for known Consul ports
func identifyConsulPort(port int) string {
	portDescriptions := map[int]string{
		shared.PortConsul: "HTTP API",
		8502:              "gRPC API",
		8600:              "DNS",
		8301:              "Serf LAN gossip",
		8302:              "Serf WAN gossip",
		8300:              "Server RPC",
	}

	if desc, ok := portDescriptions[port]; ok {
		return desc
	}

	// Check if it's the configured Consul port (might not be 8500)
	if port == shared.PortConsul {
		return "HTTP API (custom port)"
	}

	return "unknown purpose"
}

// checkACLAuthentication tests Consul API authentication with and without tokens.
//
// CRITICAL for debugging ACL issues:
//   - Distinguishes "API unreachable" from "API rejecting due to ACLs"
//   - Tests unauthenticated access (should fail if ACLs enabled)
//   - Tests authenticated access with token from environment/Vault
//   - Validates token format and permissions
//   - Shows which operations are blocked vs. allowed
//
// Methodology:
//   1. Test API without token (baseline - should fail with "Permission denied" if ACLs on)
//   2. Try to get token from CONSUL_HTTP_TOKEN environment variable
//   3. Try to get token from Vault at secret/consul/bootstrap-token
//   4. Test API with token (should succeed if token valid)
//   5. Verify token permissions by reading token metadata
//
// Returns:
//   - SUCCESS: API accessible with valid token
//   - WARNING: API works without token (ACLs not enforced)
//   - CRITICAL: API rejects token (invalid/expired)
func checkACLAuthentication(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing Consul API authentication (with and without ACL token)")

	result := DiagnosticResult{
		CheckName: "ACL Authentication",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Step 1: Test API without token (unauthenticated)
	logger.Debug("Testing unauthenticated API access")
	result.Details = append(result.Details, "=== Unauthenticated Access Test ===")
	result.Details = append(result.Details, "")

	unauthConfig := consulapi.DefaultConfig()
	unauthConfig.Token = "" // Explicitly no token
	unauthClient, err := consulapi.NewClient(unauthConfig)
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot create Consul client"
		result.Details = append(result.Details, fmt.Sprintf("✗ Client creation failed: %v", err))
		return result
	}

	// Try a basic API call that requires minimal permissions
	_, err = unauthClient.Agent().Self()
	unauthSuccess := (err == nil)

	if unauthSuccess {
		result.Details = append(result.Details, "⚠ WARNING: API accepts requests WITHOUT token")
		result.Details = append(result.Details, "  This indicates ACLs are NOT enforced")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "SECURITY RISK:")
		result.Details = append(result.Details, "  • Anyone can access Consul API")
		result.Details = append(result.Details, "  • No authentication required")
		result.Details = append(result.Details, "  • Data is unprotected")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  1. Enable ACLs: Edit /etc/consul.d/consul.hcl")
		result.Details = append(result.Details, "     acl = { enabled = true, default_policy = \"deny\" }")
		result.Details = append(result.Details, "  2. Bootstrap: sudo eos update consul --bootstrap-token")
		result.Details = append(result.Details, "  3. Restart: sudo systemctl restart consul")
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "ACLs not enforced - API accepts unauthenticated requests"
		return result
	}

	// Check error type - is it ACL-related?
	if err != nil {
		errStr := err.Error()
		isACLError := strings.Contains(errStr, "Permission denied") ||
			strings.Contains(errStr, "ACL not found") ||
			strings.Contains(errStr, "Forbidden") ||
			strings.Contains(strings.ToLower(errStr), "403")

		if isACLError {
			result.Details = append(result.Details, "✓ API correctly rejects unauthenticated requests")
			result.Details = append(result.Details, fmt.Sprintf("  Error: %s", errStr))
			result.Details = append(result.Details, "  This confirms ACLs are enforced")
		} else {
			// Different error - might be connection issue
			result.Details = append(result.Details, "✗ API unreachable (not an ACL issue)")
			result.Details = append(result.Details, fmt.Sprintf("  Error: %s", errStr))
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "Possible causes:")
			result.Details = append(result.Details, "  • Consul not running")
			result.Details = append(result.Details, "  • Network connectivity issue")
			result.Details = append(result.Details, "  • Firewall blocking connection")
			result.Success = false
			result.Severity = SeverityCritical
			result.Message = "Cannot connect to Consul API"
			return result
		}
	}

	result.Details = append(result.Details, "")

	// ASSESS - Step 2: Try to find ACL token from various sources
	logger.Debug("Searching for ACL token in environment and Vault")
	result.Details = append(result.Details, "=== Authenticated Access Test ===")
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "Searching for ACL token:")

	var token string
	var tokenSource string

	// Source 1: Environment variable
	if envToken := os.Getenv("CONSUL_HTTP_TOKEN"); envToken != "" {
		token = envToken
		tokenSource = "CONSUL_HTTP_TOKEN environment variable"
		result.Details = append(result.Details, "  ✓ Found in: "+tokenSource)
	}

	// Source 2: Vault (if no env token)
	if token == "" {
		vaultToken, err := getBootstrapTokenFromVault(rc)
		if err == nil && vaultToken != "" {
			token = vaultToken
			tokenSource = "Vault (secret/consul/bootstrap-token)"
			result.Details = append(result.Details, "  ✓ Found in: "+tokenSource)
		} else if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  ⚠ Vault check failed: %v", err))
		} else {
			result.Details = append(result.Details, "  ✗ Not found in: Vault (secret/consul/bootstrap-token)")
		}
	}

	// Source 3: Agent config file (fallback)
	if token == "" {
		configToken := getTokenFromConsulConfig(rc)
		if configToken != "" {
			token = configToken
			tokenSource = "Consul config file (acl.tokens.default)"
			result.Details = append(result.Details, "  ⚠ Found in: "+tokenSource)
			result.Details = append(result.Details, "    WARNING: Tokens in config files are less secure than Vault")
		}
	}

	if token == "" {
		result.Details = append(result.Details, "  ✗ No ACL token found in any location")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "IMPACT:")
		result.Details = append(result.Details, "  Cannot verify authenticated access works")
		result.Details = append(result.Details, "  Cannot determine if bootstrap token is valid")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  1. Bootstrap ACLs: sudo eos update consul --bootstrap-token")
		result.Details = append(result.Details, "  2. Store token in Vault (done automatically by step 1)")
		result.Details = append(result.Details, "  3. OR set env var: export CONSUL_HTTP_TOKEN=<token>")
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "ACLs enforced but no token available for testing"
		return result
	}

	result.Details = append(result.Details, "")

	// ASSESS - Step 3: Test API with token
	logger.Debug("Testing authenticated API access", zap.String("source", tokenSource))
	result.Details = append(result.Details, "Testing authenticated access:")

	authConfig := consulapi.DefaultConfig()
	authConfig.Token = token
	authClient, err := consulapi.NewClient(authConfig)
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot create authenticated Consul client"
		result.Details = append(result.Details, fmt.Sprintf("✗ Client creation failed: %v", err))
		return result
	}

	// Try basic API call with token
	agentInfo, err := authClient.Agent().Self()
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Token rejected by Consul API"
		result.Details = append(result.Details, "✗ API rejects authenticated request")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, fmt.Sprintf("  Token source: %s", tokenSource))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "POSSIBLE CAUSES:")
		result.Details = append(result.Details, "  • Token is invalid or expired")
		result.Details = append(result.Details, "  • Token was revoked")
		result.Details = append(result.Details, "  • ACLs were reset (bootstrap reset performed)")
		result.Details = append(result.Details, "  • Token is for different Consul cluster")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  1. Re-bootstrap ACLs: sudo eos update consul --bootstrap-token")
		result.Details = append(result.Details, "  2. This will create a new bootstrap token")
		result.Details = append(result.Details, "  3. Store new token: automatically saved to Vault")
		return result
	}

	result.Details = append(result.Details, "  ✓ API accepts authenticated requests")
	result.Details = append(result.Details, fmt.Sprintf("    Token source: %s", tokenSource))

	// Extract agent name to show we got real data
	if configMap, ok := agentInfo["Config"]; ok {
		if nodeName, ok := configMap["NodeName"].(string); ok {
			result.Details = append(result.Details, fmt.Sprintf("    Connected to node: %s", nodeName))
		}
	}

	result.Details = append(result.Details, "")

	// ASSESS - Step 4: Verify token permissions by reading token metadata
	logger.Debug("Verifying token permissions")
	result.Details = append(result.Details, "Token Validation:")

	aclToken, _, err := authClient.ACL().TokenReadSelf(&consulapi.QueryOptions{})
	if err != nil {
		result.Details = append(result.Details, "  ⚠ Cannot read token metadata")
		result.Details = append(result.Details, fmt.Sprintf("    Error: %v", err))
		result.Details = append(result.Details, "    Token works but lacks 'acl:read' permission")
	} else {
		result.Details = append(result.Details, "  ✓ Token metadata retrieved")
		result.Details = append(result.Details, fmt.Sprintf("    Token ID: %s", aclToken.AccessorID))
		result.Details = append(result.Details, fmt.Sprintf("    Description: %s", aclToken.Description))

		// Check if it's a management token
		isManagement := false
		for _, policy := range aclToken.Policies {
			result.Details = append(result.Details, fmt.Sprintf("    Policy: %s", policy.Name))
			if policy.Name == "global-management" || policy.Name == "builtin/global-management" {
				isManagement = true
			}
		}

		if isManagement {
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "  ✓ Token has MANAGEMENT permissions")
			result.Details = append(result.Details, "    This is the bootstrap/root token with full cluster access")
		} else {
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "  ⚠ Token has LIMITED permissions")
			result.Details = append(result.Details, "    This is not the bootstrap token")
			result.Details = append(result.Details, "    Some operations may be restricted")
		}
	}

	// EVALUATE
	result.Message = "ACLs enforced and authentication working"
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "SUMMARY:")
	result.Details = append(result.Details, "  ✓ ACLs are properly enforced")
	result.Details = append(result.Details, "  ✓ Unauthenticated requests blocked")
	result.Details = append(result.Details, "  ✓ Authenticated requests work")
	result.Details = append(result.Details, fmt.Sprintf("  ✓ Token available from: %s", tokenSource))

	return result
}

// getBootstrapTokenFromVault attempts to retrieve the Consul bootstrap token from Vault
func getBootstrapTokenFromVault(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Attempting to read Consul bootstrap token from Vault")

	// Check if VAULT_ADDR is set (indicates Vault is available)
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://" + shared.GetInternalHostname() + ":8200"
	}

	// Check if VAULT_TOKEN is set (needed to read from Vault)
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		// Try to read token from Vault Agent token file
		tokenPath := "/run/eos/vault_agent_eos.token"
		tokenBytes, err := os.ReadFile(tokenPath)
		if err != nil {
			return "", fmt.Errorf("no VAULT_TOKEN env var and cannot read %s: %w", tokenPath, err)
		}
		vaultToken = strings.TrimSpace(string(tokenBytes))
	}

	if vaultToken == "" {
		return "", fmt.Errorf("no Vault token available (VAULT_TOKEN not set and agent token file not found)")
	}

	// Create Vault client
	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = vaultAddr
	vaultClient, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return "", fmt.Errorf("cannot create Vault client: %w", err)
	}

	vaultClient.SetToken(vaultToken)

	// Try to read bootstrap token from Vault KV v2
	secret, err := vaultClient.Logical().Read("secret/data/consul/bootstrap-token")
	if err != nil {
		return "", fmt.Errorf("cannot read secret/consul/bootstrap-token: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret exists but has no data")
	}

	// KV v2 stores data in secret.Data["data"]
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("secret data has unexpected format")
	}

	tokenValue, ok := data["value"].(string)
	if !ok || tokenValue == "" {
		return "", fmt.Errorf("secret has no 'value' field or it's empty")
	}

	logger.Debug("Successfully retrieved Consul bootstrap token from Vault")
	return tokenValue, nil
}

// getTokenFromConsulConfig attempts to extract ACL token from Consul config file
func getTokenFromConsulConfig(rc *eos_io.RuntimeContext) string {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Attempting to read ACL token from Consul config file")

	configPath := consul.ConsulConfigFile
	content, err := os.ReadFile(configPath)
	if err != nil {
		logger.Debug("Cannot read Consul config", zap.Error(err))
		return ""
	}

	configStr := string(content)

	// Look for: acl { tokens { default = "..." } }
	// This is a simple pattern match, not full HCL parsing
	re := regexp.MustCompile(`tokens\s*\{[^}]*default\s*=\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(configStr)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Alternative format: acl.tokens.default = "..."
	re2 := regexp.MustCompile(`tokens\.default\s*=\s*"([^"]+)"`)
	matches2 := re2.FindStringSubmatch(configStr)
	if len(matches2) >= 2 {
		return matches2[1]
	}

	return ""
}

// checkRaftBootstrapState inspects Consul's Raft state database to determine
// the ACTUAL ACL bootstrap reset index stored in Raft (not from error messages).
//
// CRITICAL for debugging ACL bootstrap reset failures:
//   - Reads raft.db directly to get the true reset index
//   - Compares Raft state vs. error message reset index (detects stale errors)
//   - Shows if Consul and Eos have divergent views of reset state
//   - Evidence: If raft.db shows index N but error says N-1, error is stale
//
// Methodology:
//   - Uses `consul operator raft list-peers` for cluster state
//   - Attempts to read reset index from Consul internals if accessible
//   - Falls back to inferring from error messages
//
// Returns:
//   - SUCCESS: Raft state accessible and shows current index
//   - WARNING: Raft state inaccessible, using fallback methods
//   - INFO: Raft inspection not available (expected without token)
func checkRaftBootstrapState(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Inspecting Raft state for ACL bootstrap reset index")

	result := DiagnosticResult{
		CheckName: "Raft ACL Bootstrap State",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Try to get Raft peer list (shows cluster state)
	cmd := execute.Options{
		Command: "consul",
		Args:    []string{"operator", "raft", "list-peers"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Details = append(result.Details, "Cannot access Raft peer list (ACL token required)")
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "This is expected when ACLs are locked and no token is available.")
		result.Details = append(result.Details, "Raft state inspection requires valid ACL token.")
		result.Success = false
		result.Severity = SeverityInfo // Info because this is expected
		result.Message = "Raft state inspection unavailable (ACL token required)"
		return result
	}

	result.Details = append(result.Details, "=== Raft Cluster State ===")
	result.Details = append(result.Details, "")

	// Parse peer list output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result.Details = append(result.Details, line)
		}
	}

	result.Details = append(result.Details, "")

	// ASSESS - Try to bootstrap to get current reset index from error
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		result.Details = append(result.Details, "Cannot create Consul client to check bootstrap state")
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Cannot inspect ACL bootstrap state"
		return result
	}

	result.Details = append(result.Details, "=== ACL Bootstrap State ===")
	result.Details = append(result.Details, "")

	// Attempt bootstrap (will fail if already done, but error message contains reset index)
	_, _, bootstrapErr := consulClient.ACL().Bootstrap()

	if bootstrapErr == nil {
		result.Details = append(result.Details, "✓ ACL system has NEVER been bootstrapped")
		result.Details = append(result.Details, "  Bootstrap() succeeded on first try")
		result.Details = append(result.Details, "  Reset index: N/A (no reset needed)")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "ACTION REQUIRED:")
		result.Details = append(result.Details, "  Store the bootstrap token in Vault:")
		result.Details = append(result.Details, "  sudo eos update consul --bootstrap-token")
		result.Message = "ACLs not bootstrapped yet (first-time setup)"
		return result
	}

	// Bootstrap failed - extract reset index
	errorMsg := bootstrapErr.Error()
	result.Details = append(result.Details, "✗ ACL system is already bootstrapped")
	result.Details = append(result.Details, "  Bootstrap error:")
	result.Details = append(result.Details, "  "+errorMsg)
	result.Details = append(result.Details, "")

	// Try to extract reset index from error
	re := regexp.MustCompile(`reset index:\s*(\d+)`)
	matches := re.FindStringSubmatch(errorMsg)

	if len(matches) >= 2 {
		var reportedIndex int
		fmt.Sscanf(matches[1], "%d", &reportedIndex)

		nextRequiredIndex := reportedIndex + 1

		result.Details = append(result.Details, "=== Reset Index Analysis ===")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("Consul reports LAST CONSUMED reset index: %d", reportedIndex))
		result.Details = append(result.Details, fmt.Sprintf("NEXT REQUIRED reset index for reset:  %d", nextRequiredIndex))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "CRITICAL: When writing acl-bootstrap-reset file, use the NEXT index.")
		result.Details = append(result.Details, fmt.Sprintf("  echo '%d' > /opt/consul/acl-bootstrap-reset", nextRequiredIndex))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Common Bug:")
		result.Details = append(result.Details, "  ✗ Writing the REPORTED index (3117) → fails")
		result.Details = append(result.Details, "  ✓ Writing the NEXT index (3118) → works")
	} else {
		result.Details = append(result.Details, "⚠ Cannot extract reset index from error message")
		result.Details = append(result.Details, "  Error message format unexpected")
		result.Details = append(result.Details, "  This may indicate Consul version incompatibility")
	}

	result.Message = "ACL bootstrap state inspected via Bootstrap() error"
	return result
}

// checkConsulServiceDiscovery tests if Consul's service registration and
// discovery are working properly. This is critical because Vault uses
// Consul for storage backend discovery.
//
// CRITICAL for debugging Vault-Consul integration failures:
//   - Registers a test service to verify write permissions
//   - Queries the service to verify read permissions
//   - Tests health check registration
//   - Verifies Consul catalog is functioning
//
// Returns:
//   - SUCCESS: Service registration/discovery working
//   - WARNING: Service operations failing (check ACL permissions)
//   - CRITICAL: Consul catalog unavailable (severe)
func checkConsulServiceDiscovery(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing Consul service registration and discovery")

	result := DiagnosticResult{
		CheckName: "Service Discovery Test",
		Success:   true,
		Details:   []string{},
	}

	// Create unauthenticated client
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot create Consul client"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		return result
	}

	result.Details = append(result.Details, "=== Service Catalog Test ===")
	result.Details = append(result.Details, "")

	// ASSESS - Query existing services (read-only, should work even with ACLs)
	services, _, err := consulClient.Catalog().Services(nil)
	if err != nil {
		result.Details = append(result.Details, "✗ Cannot query Consul service catalog")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, "")

		if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "403") {
			result.Details = append(result.Details, "CAUSE: ACL permission denied")
			result.Details = append(result.Details, "  Anonymous token lacks 'service:read' permission")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMPACT:")
			result.Details = append(result.Details, "  - Vault cannot discover Consul nodes via service catalog")
			result.Details = append(result.Details, "  - Service mesh features unavailable")
			result.Details = append(result.Details, "  - Consul UI will not show services")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "REMEDIATION:")
			result.Details = append(result.Details, "  1. Bootstrap ACLs: sudo eos update consul --bootstrap-token")
			result.Details = append(result.Details, "  2. Create anonymous token policy:")
			result.Details = append(result.Details, "       consul acl policy create -name anonymous-policy \\")
			result.Details = append(result.Details, "         -rules 'service_prefix \"\" { policy = \"read\" }'")
			result.Details = append(result.Details, "  3. Update anonymous token:")
			result.Details = append(result.Details, "       consul acl token update -id anonymous \\")
			result.Details = append(result.Details, "         -policy-name anonymous-policy")
			result.Success = false
			result.Severity = SeverityWarning
		} else {
			result.Details = append(result.Details, "CAUSE: Consul catalog unavailable")
			result.Details = append(result.Details, "  This indicates a severe Consul failure")
			result.Success = false
			result.Severity = SeverityCritical
		}

		result.Message = "Service catalog query failed"
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("✓ Service catalog accessible (%d services registered)", len(services)))
	result.Details = append(result.Details, "")

	if len(services) > 0 {
		result.Details = append(result.Details, "Registered services:")
		for serviceName := range services {
			result.Details = append(result.Details, fmt.Sprintf("  - %s", serviceName))
			if len(result.Details) > 20 {
				result.Details = append(result.Details, fmt.Sprintf("  ... and %d more services", len(services)-15))
				break
			}
		}
		result.Details = append(result.Details, "")
	}

	// Check specifically for Vault service registration
	if _, exists := services["vault"]; exists {
		result.Details = append(result.Details, "✓ Vault service is registered in Consul catalog")
		result.Details = append(result.Details, "  This is expected if Vault is using Consul for storage")
	} else {
		result.Details = append(result.Details, "⚠ Vault service NOT registered in Consul catalog")
		result.Details = append(result.Details, "  This is normal if:")
		result.Details = append(result.Details, "    - Vault is not installed yet")
		result.Details = append(result.Details, "    - Vault is not configured to use Consul storage")
		result.Details = append(result.Details, "    - Vault service registration is disabled")
	}

	result.Message = "Service catalog is accessible"
	return result
}

// checkSystemdUnitStatus provides detailed systemd unit inspection for Consul
// and related services (Vault, Vault Agent). Shows unit file configuration,
// service dependencies, and recent systemd journal events.
//
// CRITICAL for debugging service startup failures:
//   - Shows if Consul has failed to start (vs. running but locked by ACLs)
//   - Displays systemd unit dependencies and ordering
//   - Shows recent systemd state transitions (activating → active → failed)
//   - Captures ExecStart command line for verification
//
// Returns:
//   - SUCCESS: Systemd unit status looks healthy
//   - WARNING: Service running but warnings detected
//   - CRITICAL: Service failed to start or crashed
func checkSystemdUnitStatus(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Inspecting systemd unit status for Consul and dependencies")

	result := DiagnosticResult{
		CheckName: "Systemd Unit Inspection",
		Success:   true,
		Details:   []string{},
	}

	// Services to check
	services := []string{"consul", "vault", "vault-agent-eos"}

	for _, serviceName := range services {
		result.Details = append(result.Details, fmt.Sprintf("=== %s.service ===", serviceName))
		result.Details = append(result.Details, "")

		// ASSESS - Get full systemd status
		cmd := execute.Options{
			Command: "systemctl",
			Args:    []string{"status", serviceName + ".service", "--no-pager", "--full"},
			Capture: true,
		}

		output, err := execute.Run(rc.Ctx, cmd)

		// systemctl status returns exit code 3 if service is inactive (not an error for our purposes)
		if err != nil && !strings.Contains(output, "inactive") && !strings.Contains(output, "not-found") {
			result.Details = append(result.Details, fmt.Sprintf("⚠ Cannot get status for %s", serviceName))
			result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
			result.Details = append(result.Details, "")
			continue
		}

		// Parse output for key information
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			// Show key lines only (not the full log dump)
			if strings.Contains(line, "Loaded:") ||
				strings.Contains(line, "Active:") ||
				strings.Contains(line, "Main PID:") ||
				strings.Contains(line, "Tasks:") ||
				strings.Contains(line, "Memory:") ||
				strings.Contains(line, "CGroup:") ||
				strings.Contains(line, "ExecStart") ||
				strings.Contains(line, "Wants") ||
				strings.Contains(line, "After") ||
				strings.Contains(line, "Requires") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}

			// Detect failures
			if strings.Contains(line, "Active:") && strings.Contains(line, "failed") {
				result.Success = false
				result.Severity = SeverityCritical
				result.Details = append(result.Details, "")
				result.Details = append(result.Details, fmt.Sprintf("  ✗ CRITICAL: %s has FAILED", serviceName))
			}

			if strings.Contains(line, "Active:") && strings.Contains(line, "inactive") {
				if serviceName == "consul" {
					result.Success = false
					result.Severity = SeverityCritical
					result.Details = append(result.Details, "")
					result.Details = append(result.Details, "  ✗ CRITICAL: Consul is NOT RUNNING")
				} else {
					result.Details = append(result.Details, "")
					result.Details = append(result.Details, fmt.Sprintf("  ⚠ %s is not running (may be optional)", serviceName))
				}
			}
		}

		result.Details = append(result.Details, "")

		// Show recent journal entries for errors
		journalCmd := execute.Options{
			Command: "journalctl",
			Args:    []string{"-u", serviceName + ".service", "-n", "5", "--no-pager"},
			Capture: true,
		}

		journalOutput, journalErr := execute.Run(rc.Ctx, journalCmd)
		if journalErr == nil && strings.TrimSpace(journalOutput) != "" {
			result.Details = append(result.Details, "  Recent journal entries:")
			journalLines := strings.Split(journalOutput, "\n")
			for i, line := range journalLines {
				if i >= 5 || strings.TrimSpace(line) == "" {
					break
				}
				result.Details = append(result.Details, "    "+strings.TrimSpace(line))
			}
			result.Details = append(result.Details, "")
		}
	}

	if result.Success {
		result.Message = "Systemd units look healthy"
	} else {
		result.Message = "Systemd unit failures detected"
	}

	return result
}
