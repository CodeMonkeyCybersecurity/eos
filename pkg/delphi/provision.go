// pkg/delphi/provision.go

package delphi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func CreateDelphiTenant(rc *eos_io.RuntimeContext, spec TenantSpec) error {
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
		BackendRoles: []string{"delphi-readonly"}, // TODO: support dynamic role naming if needed
		Hosts:        []string{},
		Users:        []string{spec.User},
	}

	payload, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("failed to marshal role mapping: %w", err)
	}

	url := fmt.Sprintf("https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/delphi-%s-role", spec.Name)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth("admin", "<vaulted-secret>") // TODO: Replace with secure Vault retrieval
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("role mapping request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from OpenSearch: %s", resp.Status)
	}

	log.Info(" OpenSearch role mapping applied", zap.String("role", fmt.Sprintf("delphi-%s-role", spec.Name)))
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

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant definition: %w", err)
	}

	url := fmt.Sprintf("https://127.0.0.1:9200/_plugins/_security/api/tenants/%s", spec.Name)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create tenant request: %w", err)
	}

	req.SetBasicAuth("admin", "<vaulted-secret>") // TODO: Replace with Vault-backed secret
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to make tenant creation request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status creating tenant: %s", resp.Status)
	}

	log.Info(" OpenSearch tenant created", zap.String("tenant", spec.Name))
	return nil
}

func EnsureWazuhGroup(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	// The group ID to be created for Wazuh agent grouping
	groupID := spec.GroupID
	if groupID == "" {
		groupID = fmt.Sprintf("group_%s", spec.Name)
	}

	// JSON body for the group creation API
	payload := map[string]any{
		"group_id": groupID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal group creation payload: %w", err)
	}

	// TODO: retrieve Wazuh API token from Vault
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // Replace with secure lookup

	req, err := http.NewRequest("POST", "https://127.0.0.1:55000/groups?pretty=true", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("wazuh group creation request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status from Wazuh API: %s", resp.Status)
	}

	log.Info(" Wazuh group created", zap.String("group", groupID))
	return nil
}

func EnsureWazuhEnrollmentKey(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	groupID := spec.GroupID
	if groupID == "" {
		groupID = fmt.Sprintf("group_%s", spec.Name)
	}

	// Payload for the enrollment key creation
	payload := map[string]any{
		"name":         fmt.Sprintf("%s-enrollment", spec.Name),
		"group":        groupID,
		"agents_limit": 10,     // TODO: make configurable
		"ttl":          "365d", // TODO: make configurable
		"one_time":     false,  // TODO: optionally support
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment payload: %w", err)
	}

	// TODO: replace with Vault-protected Wazuh API token
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>"

	req, err := http.NewRequest("POST", "https://127.0.0.1:55000/agents?pretty=true", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create enrollment request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("enrollment request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status creating enrollment key: %s", resp.Status)
	}

	log.Info(" Enrollment key created", zap.String("group", groupID))
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
			"actions": []string{"agent:read"},
			"resources": []string{
				fmt.Sprintf("agent:group:%s", groupID),
			},
			"effect": "allow",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal policy definition: %w", err)
	}

	// TODO: Replace with Vault-managed token
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>"

	req, err := http.NewRequest("POST", "https://127.0.0.1:55000/security/policies?pretty=true", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("wazuh policy creation request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status from Wazuh policy API: %s", resp.Status)
	}

	log.Info(" Wazuh policy created", zap.String("policy", policyName))
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

	payload, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal role definition: %w", err)
	}

	url := fmt.Sprintf("https://127.0.0.1:9200/_plugins/_security/api/roles/delphi-%s-role", spec.Name)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth("admin", "<vaulted-secret>") // Replace with secure lookup
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to send role creation request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response: %s", resp.Status)
	}

	log.Info(" OpenSearch role created", zap.String("tenant", spec.Name))
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

	payload, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal global readonly role: %w", err)
	}

	url := "https://127.0.0.1:9200/_plugins/_security/api/roles/delphi-readonly-role"
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth("admin", "<vaulted-secret>") // TODO: Secure from Vault
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to create global role: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response from OpenSearch: %s", resp.Status)
	}

	log.Info(" Global readonly role ensured")
	return nil
}

func ResolveWazuhRoleID(rc *eos_io.RuntimeContext, name string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // TODO: secure lookup
	req, err := http.NewRequest("GET", "https://127.0.0.1:55000/security/roles?pretty=true", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch roles: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	for _, r := range result.Data {
		if r.Name == name {
			log.Info(" Resolved role ID",
				zap.String("name", name),
				zap.String("id", r.ID),
			)
			return r.ID, nil
		}
	}
	return "", fmt.Errorf("role not found: %s", name)
}

func ResolveWazuhUserID(rc *eos_io.RuntimeContext, name string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // TODO: Retrieve from Vault
	req, err := http.NewRequest("GET", "https://127.0.0.1:55000/security/users?pretty=true", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Wazuh users: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"username"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode users: %w", err)
	}

	for _, user := range result.Data {
		if user.Name == name {
			log.Info(" Resolved role ID",
				zap.String("name", name),
				zap.String("id", user.ID),
			)
			return user.ID, nil
		}
	}
	return "", fmt.Errorf("user not found: %s", name)
}

func ResolveWazuhPolicyID(rc *eos_io.RuntimeContext, name string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // TODO: Retrieve from Vault
	req, err := http.NewRequest("GET", "https://127.0.0.1:55000/security/policies?pretty=true", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Wazuh policies: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode policies: %w", err)
	}

	for _, p := range result.Data {
		if p.Name == name {
			log.Info(" Resolved policy ID", zap.String("name", name), zap.String("id", p.ID))
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("policy not found: %s", name)
}

func AttachPolicyToRole(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)
	roleID := spec.RoleID
	policyID := spec.PolicyID

	//  Fallback to lookup if missing
	if roleID == "" {
		resolved, err := ResolveWazuhRoleID(rc, fmt.Sprintf("role_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve role ID: %w", err)
		}
		roleID = resolved
	}

	if policyID == "" {
		resolved, err := ResolveWazuhPolicyID(rc, fmt.Sprintf("policy_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve policy ID: %w", err)
		}
		policyID = resolved
	}

	url := fmt.Sprintf("https://127.0.0.1:55000/security/roles/%s/policies?policy_ids=%s&pretty=true", roleID, policyID)
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // TODO: Vault integration

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build attach policy request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("attach policy request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status attaching policy: %s", resp.Status)
	}

	log.Info(" Policy attached to role",
		zap.String("role_id", roleID),
		zap.String("policy_id", policyID),
	)
	return nil
}

func AssignRoleToUser(rc *eos_io.RuntimeContext, spec TenantSpec) error {
	log := otelzap.Ctx(rc.Ctx)

	roleID := spec.RoleID
	userID := ""

	//  Fallback to lookup if missing
	if roleID == "" {
		resolved, err := ResolveWazuhRoleID(rc, fmt.Sprintf("role_%s", spec.Name))
		if err != nil {
			return fmt.Errorf("cannot resolve role ID: %w", err)
		}
		roleID = resolved
	}

	if userID == "" {
		resolved, err := ResolveWazuhUserID(rc, spec.User)
		if err != nil {
			return fmt.Errorf("cannot resolve user ID: %w", err)
		}
		userID = resolved
	}

	url := fmt.Sprintf("https://127.0.0.1:55000/security/users/%s/roles?role_ids=%s&pretty=true", userID, roleID)
	// #nosec G101 - This is a placeholder template, not a hardcoded credential
	token := "<vaulted-wazuh-token>" // TODO: Vault integration

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build assign request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpclient.DefaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("assign role to user request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status assigning role to user: %s", resp.Status)
	}

	log.Info(" Role assigned to user", zap.String("user_id", userID), zap.String("role_id", roleID))
	return nil
}
