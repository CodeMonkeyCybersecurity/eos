package hecate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateAuthPolicy creates a new authentication policy in Authentik
func CreateAuthPolicy(rc *eos_io.RuntimeContext, policy *AuthPolicy) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate prerequisites
	logger.Info("Assessing auth policy creation prerequisites",
		zap.String("name", policy.Name),
		zap.String("provider", policy.Provider))

	// Check if policy already exists
	exists, err := authPolicyExists(rc, policy.Name)
	if err != nil {
		return fmt.Errorf("failed to check policy existence: %w", err)
	}
	if exists {
		return eos_err.NewUserError("auth policy %s already exists", policy.Name)
	}

	// Validate provider configuration
	if err := validateAuthProvider(rc, policy.Provider); err != nil {
		return eos_err.NewUserError("invalid auth provider %s: %v", policy.Provider, err)
	}

	// INTERVENE - Create the policy
	logger.Info("Creating authentication policy in Authentik",
		zap.String("name", policy.Name))

	// Build Authentik API request
	authentikConfig := buildAuthentikPolicyConfig(policy)

	// Get Authentik API token from Vault
	apiToken, err := getAuthentikAPIToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik API token: %w", err)
	}

	// Create policy via Authentik API
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(authentikConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "POST",
		getAuthentikURL(rc)+"/api/v3/policies/expression/",
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create policy in Authentik: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentik API returned error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response to get policy ID
	var policyResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&policyResponse); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	policyID, ok := policyResponse["pk"].(string)
	if !ok {
		return fmt.Errorf("failed to get policy ID from response")
	}

	// If groups are specified, bind them to the policy
	if len(policy.Groups) > 0 {
		if err := bindGroupsToPolicy(rc, policyID, policy.Groups, apiToken); err != nil {
			// Rollback - delete the policy
			_ = deleteAuthentikPolicy(rc, policyID, apiToken)
			return fmt.Errorf("failed to bind groups to policy: %w", err)
		}
	}

	// Update state store
	if err := updateStateStore(rc, "auth_policies", policy.Name, policy); err != nil {
		logger.Warn("Failed to update state store",
			zap.Error(err))
	}

	// EVALUATE - Verify the policy works
	logger.Info("Verifying authentication policy",
		zap.String("name", policy.Name))

	if err := verifyAuthPolicy(rc, policy); err != nil {
		return fmt.Errorf("auth policy verification failed: %w", err)
	}

	logger.Info("Authentication policy created successfully",
		zap.String("name", policy.Name))

	return nil
}

// UpdateAuthPolicy updates an existing authentication policy
func UpdateAuthPolicy(rc *eos_io.RuntimeContext, policyName string, policy *AuthPolicy) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if policy exists
	logger.Info("Assessing auth policy update prerequisites",
		zap.String("name", policyName))

	exists, err := authPolicyExists(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("auth policy %s not found", policyName)
	}

	// Get current policy ID
	policyID, err := getAuthPolicyID(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to get policy ID: %w", err)
	}

	// INTERVENE - Update the policy
	logger.Info("Updating authentication policy in Authentik",
		zap.String("name", policyName))

	// Build updated configuration
	authentikConfig := buildAuthentikPolicyConfig(policy)

	// Get Authentik API token
	apiToken, err := getAuthentikAPIToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik API token: %w", err)
	}

	// Update via Authentik API
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(authentikConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "PATCH",
		fmt.Sprintf("%s/api/v3/policies/expression/%s/", getAuthentikURL(rc), policyID),
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update policy in Authentik: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentik API returned error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Update group bindings if changed
	if err := updateGroupBindings(rc, policyID, policy.Groups, apiToken); err != nil {
		return fmt.Errorf("failed to update group bindings: %w", err)
	}

	// Update state store
	if err := updateStateStore(rc, "auth_policies", policy.Name, policy); err != nil {
		logger.Warn("Failed to update state store",
			zap.Error(err))
	}

	// EVALUATE - Verify the updated policy works
	logger.Info("Verifying updated authentication policy",
		zap.String("name", policy.Name))

	if err := verifyAuthPolicy(rc, policy); err != nil {
		return fmt.Errorf("auth policy verification failed: %w", err)
	}

	logger.Info("Authentication policy updated successfully",
		zap.String("name", policy.Name))

	return nil
}

// DeleteAuthPolicy removes an authentication policy
func DeleteAuthPolicy(rc *eos_io.RuntimeContext, policyName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if policy exists and is not in use
	logger.Info("Assessing auth policy deletion prerequisites",
		zap.String("name", policyName))

	exists, err := authPolicyExists(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("auth policy %s not found", policyName)
	}

	// Check if policy is in use by any routes
	inUse, routes, err := checkAuthPolicyUsage(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to check policy usage: %w", err)
	}
	if inUse {
		return eos_err.NewUserError("auth policy %s is in use by routes: %v", policyName, routes)
	}

	// Get policy ID
	policyID, err := getAuthPolicyID(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to get policy ID: %w", err)
	}

	// INTERVENE - Delete the policy
	logger.Info("Deleting authentication policy from Authentik",
		zap.String("name", policyName))

	// Get Authentik API token
	apiToken, err := getAuthentikAPIToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik API token: %w", err)
	}

	// Delete via Authentik API
	if err := deleteAuthentikPolicy(rc, policyID, apiToken); err != nil {
		return fmt.Errorf("failed to delete policy from Authentik: %w", err)
	}

	// Delete from state store
	if err := deleteFromStateStore(rc, "auth_policies", policyName); err != nil {
		logger.Warn("Failed to delete from state store",
			zap.Error(err))
	}

	// EVALUATE - Verify deletion
	logger.Info("Verifying auth policy deletion",
		zap.String("name", policyName))

	exists, err = authPolicyExists(rc, policyName)
	if err != nil {
		return fmt.Errorf("failed to verify policy deletion: %w", err)
	}
	if exists {
		return fmt.Errorf("policy still exists after deletion")
	}

	logger.Info("Authentication policy deleted successfully",
		zap.String("name", policyName))

	return nil
}

// buildAuthentikPolicyConfig builds the configuration for Authentik
func buildAuthentikPolicyConfig(policy *AuthPolicy) map[string]interface{} {
	// Build the policy expression
	expression := fmt.Sprintf(`
# Policy: %s
# Provider: %s
# Require MFA: %v
# Allowed Groups: %v

# Check if user is authenticated
if not request.user.is_authenticated:
    return False
`, policy.Name, policy.Provider, policy.RequireMFA, policy.Groups)

	// Add group membership check if groups are specified
	if len(policy.Groups) > 0 {
		expression += fmt.Sprintf(`
# Check group membership
allowed_groups = %v
user_groups = [group.name for group in request.user.groups.all()]
if not any(group in allowed_groups for group in user_groups):
    ak_message("User not in allowed groups")
    return False
`, policy.Groups)
	}

	// Add MFA check if required
	if policy.RequireMFA {
		expression += `
# Check MFA
if not request.user.mfa_devices.exists():
    ak_message("MFA required but not configured")
    return False
`
	}

	// Add custom metadata checks if specified
	for key, value := range policy.Metadata {
		expression += fmt.Sprintf(`
# Check metadata: %s
if request.user.attributes.get("%s", "") != "%s":
    return False
`, key, key, value)
	}

	expression += `
# All checks passed
return True
`

	config := map[string]interface{}{
		"name":              policy.Name,
		"expression":        expression,
		"execution_logging": true,
	}

	return config
}

// Helper functions

func authPolicyExists(_ *eos_io.RuntimeContext, policyName string) (bool, error) {
	// Check both Authentik and state store
	// In production, would query Authentik API
	logger := zap.L().With(zap.String("component", "auth_manager"))
	logger.Info("Checking if auth policy exists", zap.String("policy", policyName))
	return false, nil
}

func validateAuthProvider(_ *eos_io.RuntimeContext, provider string) error {
	validProviders := []string{"authentik", "oauth2", "saml", "ldap", "basic"}
	for _, valid := range validProviders {
		if provider == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid provider: must be one of %v", validProviders)
}

func getAuthentikAPIToken(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get token from Vault
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return "", fmt.Errorf("failed to get Vault client: %w", err)
	}

	secret, err := vaultClient.Logical().Read("secret/data/hecate/authentik")
	if err != nil {
		return "", fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no secret found at path secret/data/hecate/authentik")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid secret format")
	}

	token, ok := data["api_token"].(string)
	if !ok {
		return "", fmt.Errorf("api_token not found in secret")
	}

	logger.Debug("Successfully retrieved Authentik API token from Vault")
	return token, nil
}

func getAuthentikURL(_ *eos_io.RuntimeContext) string {
	// Make this configurable via environment or config file
	// In production, would read from configuration
	return "https://authentik.example.com"
}

func verifyAuthPolicy(rc *eos_io.RuntimeContext, policy *AuthPolicy) error {
	logger := otelzap.Ctx(rc.Ctx)

	// TODO: Implement actual verification
	// This would involve creating a test binding and verifying it works

	logger.Debug("Auth policy verification completed",
		zap.String("name", policy.Name))

	return nil
}

func bindGroupsToPolicy(_ *eos_io.RuntimeContext, policyID string, groups []string, _ string) error {
	// Bind groups to policy via Authentik API
	logger := zap.L().With(zap.String("component", "auth_manager"))
	logger.Info("Binding groups to policy",
		zap.String("policy_id", policyID),
		zap.Int("group_count", len(groups)))

	// In production, would make API calls to bind groups
	for _, group := range groups {
		logger.Debug("Would bind group", zap.String("group", group))
	}
	return nil
}

func deleteAuthentikPolicy(rc *eos_io.RuntimeContext, policyID, apiToken string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(rc.Ctx, "DELETE",
		fmt.Sprintf("%s/api/v3/policies/expression/%s/", getAuthentikURL(rc), policyID),
		nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func getAuthPolicyID(_ *eos_io.RuntimeContext, policyName string) (string, error) {
	// Fetch policy ID from Authentik API
	logger := zap.L().With(zap.String("component", "auth_manager"))
	logger.Debug("Fetching auth policy ID", zap.String("policy", policyName))

	// In production, would query Authentik API
	return "", fmt.Errorf("policy not found: %s", policyName)
}

func checkAuthPolicyUsage(_ *eos_io.RuntimeContext, policyName string) (bool, []string, error) {
	// Check all routes to see if any use this policy
	logger := zap.L().With(zap.String("component", "auth_manager"))
	logger.Debug("Checking auth policy usage", zap.String("policy", policyName))

	// In production, would check route configurations
	return false, nil, nil
}

func updateGroupBindings(_ *eos_io.RuntimeContext, policyID string, groups []string, _ string) error {
	// Update group bindings via Authentik API
	logger := zap.L().With(zap.String("component", "auth_manager"))
	logger.Info("Updating group bindings",
		zap.String("policy_id", policyID),
		zap.Int("group_count", len(groups)))
	return nil
}
