// pkg/wazuh/provision.go

package wazuh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// wazuhAPIURL builds a Wazuh API URL using the dynamically-resolved internal hostname.
// SECURITY: Uses shared.GetInternalHostname() function call, NOT a string literal.
func wazuhAPIURL(path string) string {
	return fmt.Sprintf("https://%s:%d%s", shared.GetInternalHostname(), shared.PortWazuh55000, path)
}

// opensearchURL builds an OpenSearch URL using the dynamically-resolved internal hostname.
func opensearchURL(path string) string {
	return fmt.Sprintf("https://%s:9200%s", shared.GetInternalHostname(), path)
}

// getWazuhAdminPassword retrieves the Wazuh/OpenSearch admin password
// SECURITY: Tries Vault first, falls back to environment variable
func getWazuhAdminPassword(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to read from Vault first (preferred)
	var vaultData map[string]interface{}
	err := vault.ReadFromVault(rc, "secret/wazuh/admin", &vaultData)
	if err == nil {
		if password, ok := vaultData["password"].(string); ok && password != "" {
			logger.Debug("Retrieved Wazuh admin password from Vault")
			return password, nil
		}
	}

	// Fallback to environment variable (for initial bootstrap)
	password := os.Getenv("WAZUH_ADMIN_PASSWORD")
	if password != "" {
		logger.Warn("Using Wazuh admin password from environment variable (should migrate to Vault)")
		return password, nil
	}

	return "", fmt.Errorf("Wazuh admin password not found in Vault or WAZUH_ADMIN_PASSWORD environment variable")
}

// doOpenSearchRequest performs an authenticated OpenSearch API request.
// Handles JSON marshaling, BasicAuth, Content-Type header, response cleanup, and status check.
//
// DRY RATIONALE: Previously, 5 functions (EnsureOpensearchRoleMapping, EnsureOpensearchTenant,
// EnsureOpensearchRole, EnsureGlobalReadonlyRole, plus role mapping) duplicated identical
// request setup, auth, and response handling (~25 lines each = ~125 lines total).
func doOpenSearchRequest(rc *eos_io.RuntimeContext, method, url string, payload interface{}) (*http.Response, error) {
	var body *bytes.Buffer
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request payload: %w", err)
		}
		body = bytes.NewBuffer(data)
	}

	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	adminPassword, err := getWazuhAdminPassword(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin password: %w", err)
	}
	req.SetBasicAuth("admin", adminPassword)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// doWazuhAPIRequest performs an authenticated Wazuh API request using Bearer token.
// Handles request creation, auth header, and response cleanup.
//
// DRY RATIONALE: Previously, 7 functions duplicated identical token setup, request
// creation, and response handling (~15 lines each = ~105 lines total).
func doWazuhAPIRequest(method, url string, payload interface{}) (*http.Response, error) {
	var body *bytes.Buffer
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request payload: %w", err)
		}
		body = bytes.NewBuffer(data)
	}

	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// TODO: retrieve Wazuh API token from Vault
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>"
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// resolveWazuhEntityID resolves a Wazuh API entity (role, user, policy) by name.
// Returns the entity's ID or an error if not found.
//
// DRY RATIONALE: ResolveWazuhRoleID, ResolveWazuhUserID, ResolveWazuhPolicyID
// were 99% identical (~40 lines each = ~120 lines). Only the API path and
// the JSON field name for matching differed.
func resolveWazuhEntityID(rc *eos_io.RuntimeContext, apiPath, entityName, nameField, entityType string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	resp, err := doWazuhAPIRequest("GET", wazuhAPIURL(apiPath), nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", entityType, err)
	}
	defer resp.Body.Close()

	var result struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode %s response: %w", entityType, err)
	}

	for _, item := range result.Data {
		if name, ok := item[nameField].(string); ok && name == entityName {
			if id, ok := item["id"].(string); ok {
				log.Info("Resolved "+entityType+" ID",
					zap.String("name", entityName),
					zap.String("id", id))
				return id, nil
			}
			// ID might be a number
			if id, ok := item["id"].(float64); ok {
				idStr := fmt.Sprintf("%.0f", id)
				log.Info("Resolved "+entityType+" ID",
					zap.String("name", entityName),
					zap.String("id", idStr))
				return idStr, nil
			}
		}
	}
	return "", fmt.Errorf("%s not found: %s", entityType, entityName)
}

func CreateWazuhTenant(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	if err := EnsureOpensearchTenant(rc, spec); err != nil {
		return err
	}
	if err := EnsureOpensearchRole(rc, spec); err != nil {
		return err
	}
	if err := EnsureOpensearchRoleMapping(rc, spec); err != nil {
		return err
	}
	if err := EnsureWazuhGroup(rc, spec); err != nil {
		return err
	}
	if err := EnsureWazuhEnrollmentKey(rc, spec); err != nil {
		return err
	}
	if err := EnsureWazuhPolicy(rc, spec); err != nil {
		return err
	}
	if err := AttachPolicyToRole(rc, spec); err != nil {
		return err
	}
	if err := AssignRoleToUser(rc, spec); err != nil {
		return err
	}
	return nil
}

type RoleMapping struct {
	BackendRoles    []string `json:"backend_roles"`
	Hosts           []string `json:"hosts"`
	Users           []string `json:"users"`
	AndBackendRoles []string `json:"and_backend_roles,omitempty"`
}

func EnsureOpensearchRoleMapping(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	mapping := RoleMapping{
		BackendRoles: []string{"wazuh-readonly"},
		Hosts:        []string{},
		Users:        []string{spec.User},
	}

	url := opensearchURL(fmt.Sprintf("/_plugins/_security/api/rolesmapping/wazuh-%s-role", spec.Name))
	resp, err := doOpenSearchRequest(rc, "PUT", url, mapping)
	if err != nil {
		return fmt.Errorf("role mapping request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from OpenSearch: %s", resp.Status)
	}

	log.Info("OpenSearch role mapping applied", zap.String("role", fmt.Sprintf("wazuh-%s-role", spec.Name)))
	return nil
}

func EnsureOpensearchTenant(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	payload := map[string]any{
		"description": fmt.Sprintf("Private tenant for %s", spec.Name),
		"hidden":      false,
		"reserved":    false,
		"static":      false,
	}

	url := opensearchURL(fmt.Sprintf("/_plugins/_security/api/tenants/%s", spec.Name))
	resp, err := doOpenSearchRequest(rc, "PUT", url, payload)
	if err != nil {
		return fmt.Errorf("tenant creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status creating tenant: %s", resp.Status)
	}

	log.Info("OpenSearch tenant created", zap.String("tenant", spec.Name))
	return nil
}

func EnsureWazuhGroup(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	groupID := spec.GroupID
	if groupID == "" {
		groupID = fmt.Sprintf("group_%s", spec.Name)
	}

	payload := map[string]any{"group_id": groupID}

	resp, err := doWazuhAPIRequest("POST", wazuhAPIURL("/groups?pretty=true"), payload)
	if err != nil {
		return fmt.Errorf("wazuh group creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status from Wazuh API: %s", resp.Status)
	}

	log.Info("Wazuh group created", zap.String("group", groupID))
	return nil
}

func EnsureWazuhEnrollmentKey(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	groupID := spec.GroupID
	if groupID == "" {
		groupID = fmt.Sprintf("group_%s", spec.Name)
	}

	payload := map[string]any{
		"name":         fmt.Sprintf("%s-enrollment", spec.Name),
		"group":        groupID,
		"agents_limit": 10,     // TODO: make configurable
		"ttl":          "365d", // TODO: make configurable
		"one_time":     false,  // TODO: optionally support
	}

	resp, err := doWazuhAPIRequest("POST", wazuhAPIURL("/agents?pretty=true"), payload)
	if err != nil {
		return fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status creating enrollment key: %s", resp.Status)
	}

	log.Info("Enrollment key created", zap.String("group", groupID))
	return nil
}

func EnsureWazuhPolicy(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	policyName := fmt.Sprintf("policy_%s", spec.Name)
	groupID := spec.GroupID
	if groupID == "" {
		groupID = fmt.Sprintf("group_%s", spec.Name)
	}

	payload := map[string]any{
		"name": policyName,
		"policy": map[string]any{
			"actions":   []string{"agent:read"},
			"resources": []string{fmt.Sprintf("agent:group:%s", groupID)},
			"effect":    "allow",
		},
	}

	resp, err := doWazuhAPIRequest("POST", wazuhAPIURL("/security/policies?pretty=true"), payload)
	if err != nil {
		return fmt.Errorf("wazuh policy creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status from Wazuh policy API: %s", resp.Status)
	}

	log.Info("Wazuh policy created", zap.String("policy", policyName))
	return nil
}

type TenantPermissions struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

type IndexPermissions struct {
	IndexPatterns  []string `json:"index_patterns"`
	AllowedActions []string `json:"allowed_actions"`
	DLS            string   `json:"dls,omitempty"`
}

type OpenSearchRole struct {
	ClusterPermissions []string            `json:"cluster_permissions"`
	IndexPermissions   []IndexPermissions  `json:"index_permissions"`
	TenantPermissions  []TenantPermissions `json:"tenant_permissions"`
}

func EnsureOpensearchRole(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	role := OpenSearchRole{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []IndexPermissions{
			{
				IndexPatterns:  []string{"wazuh-*"},
				AllowedActions: []string{"read", "search"},
				DLS:            fmt.Sprintf(`{"term": {"agent.group.name": "%s"}}`, spec.GroupID),
			},
		},
		TenantPermissions: []TenantPermissions{
			{
				TenantPatterns: []string{"__user__"},
				AllowedActions: []string{"kibana_all_read"},
			},
			{
				TenantPatterns: []string{spec.Name},
				AllowedActions: []string{"kibana_all_read"},
			},
		},
	}

	url := opensearchURL(fmt.Sprintf("/_plugins/_security/api/roles/wazuh-%s-role", spec.Name))
	resp, err := doOpenSearchRequest(rc, "PUT", url, role)
	if err != nil {
		return fmt.Errorf("role creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response: %s", resp.Status)
	}

	log.Info("OpenSearch role created", zap.String("tenant", spec.Name))
	return nil
}

func EnsureGlobalReadonlyRole(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	role := OpenSearchRole{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []IndexPermissions{
			{
				IndexPatterns:  []string{"wazuh-*"},
				AllowedActions: []string{"read", "search"},
			},
		},
		TenantPermissions: []TenantPermissions{
			{
				TenantPatterns: []string{"__user__"},
				AllowedActions: []string{"kibana_all_read"},
			},
		},
	}

	url := opensearchURL("/_plugins/_security/api/roles/wazuh-readonly-role")
	resp, err := doOpenSearchRequest(rc, "PUT", url, role)
	if err != nil {
		return fmt.Errorf("global role creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response from OpenSearch: %s", resp.Status)
	}

	log.Info("Global readonly role ensured")
	return nil
}

// ResolveWazuhRoleID resolves a Wazuh role name to its ID.
func ResolveWazuhRoleID(rc *eos_io.RuntimeContext, name string) (string, error) {
	return resolveWazuhEntityID(rc, "/security/roles?pretty=true", name, "name", "role")
}

// ResolveWazuhUserID resolves a Wazuh username to its ID.
func ResolveWazuhUserID(rc *eos_io.RuntimeContext, name string) (string, error) {
	return resolveWazuhEntityID(rc, "/security/users?pretty=true", name, "username", "user")
}

// ResolveWazuhPolicyID resolves a Wazuh policy name to its ID.
func ResolveWazuhPolicyID(rc *eos_io.RuntimeContext, name string) (string, error) {
	return resolveWazuhEntityID(rc, "/security/policies?pretty=true", name, "name", "policy")
}

func AttachPolicyToRole(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	roleID := spec.RoleID
	if roleID == "" {
		resolved, err := ResolveWazuhRoleID(rc, fmt.Sprintf("role_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve role ID: %w", err)
		}
		roleID = resolved
	}

	policyID := spec.PolicyID
	if policyID == "" {
		resolved, err := ResolveWazuhPolicyID(rc, fmt.Sprintf("policy_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve policy ID: %w", err)
		}
		policyID = resolved
	}

	url := wazuhAPIURL(fmt.Sprintf("/security/roles/%s/policies?policy_ids=%s&pretty=true", roleID, policyID))
	resp, err := doWazuhAPIRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("attach policy request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status attaching policy: %s", resp.Status)
	}

	log.Info("Policy attached to role",
		zap.String("role_id", roleID),
		zap.String("policy_id", policyID))
	return nil
}

func AssignRoleToUser(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	roleID := spec.RoleID
	if roleID == "" {
		resolved, err := ResolveWazuhRoleID(rc, fmt.Sprintf("role_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve role ID: %w", err)
		}
		roleID = resolved
	}

	userID, err := ResolveWazuhUserID(rc, spec.User)
	if err != nil {
		return fmt.Errorf("cannot resolve user ID: %w", err)
	}

	url := wazuhAPIURL(fmt.Sprintf("/security/users/%s/roles?role_ids=%s&pretty=true", userID, roleID))
	resp, err := doWazuhAPIRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("assign role to user request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status assigning role to user: %s", resp.Status)
	}

	log.Info("Role assigned to user",
		zap.String("user_id", userID),
		zap.String("role_id", roleID))
	return nil
}
