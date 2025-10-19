// Package wazuh provides SSO integration helpers for the sync connector
package wazuh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GenerateExchangeKey generates a secure exchange key for SAML
func GenerateExchangeKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	return hex.EncodeToString(key), nil
}

// UpdateSecurityConfig updates the OpenSearch Security config.yml with SAML configuration
func UpdateSecurityConfig(rc *eos_io.RuntimeContext, entityID, exchangeKey, wazuhURL string) error {
	logger := otelzap.Ctx(rc.Ctx)
	configPath := "/etc/wazuh-indexer/opensearch-security/config.yml"

	logger.Debug("Reading current config.yml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.yml: %w", err)
	}

	// Parse YAML
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config.yml: %w", err)
	}

	logger.Debug("Updating SAML configuration in config.yml")

	// Update or create the SAML auth domain
	if err := updateSAMLAuthDomain(config, entityID, exchangeKey, wazuhURL); err != nil {
		return fmt.Errorf("failed to update SAML auth domain: %w", err)
	}

	// Marshal back to YAML
	newData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(configPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write updated config: %w", err)
	}

	logger.Info("Updated OpenSearch security config",
		zap.String("path", configPath))

	return nil
}

// UpdateRolesMapping updates the roles_mapping.yml with SAML role mappings
func UpdateRolesMapping(rc *eos_io.RuntimeContext, roleMappings map[string]string) error {
	logger := otelzap.Ctx(rc.Ctx)
	rolesMappingPath := "/etc/wazuh-indexer/opensearch-security/roles_mapping.yml"

	logger.Debug("Reading current roles_mapping.yml")

	data, err := os.ReadFile(rolesMappingPath)
	if err != nil {
		return fmt.Errorf("failed to read roles_mapping.yml: %w", err)
	}

	// Parse YAML
	var mapping map[string]interface{}
	if err := yaml.Unmarshal(data, &mapping); err != nil {
		return fmt.Errorf("failed to parse roles_mapping.yml: %w", err)
	}

	logger.Debug("Updating role mappings")

	// Update role mappings
	for authentikRole, opensearchRole := range roleMappings {
		addBackendRole(mapping, opensearchRole, authentikRole)
		logger.Debug("Mapped role",
			zap.String("authentik_role", authentikRole),
			zap.String("opensearch_role", opensearchRole))
	}

	// Marshal back to YAML
	newData, err := yaml.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("failed to marshal updated mapping: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(rolesMappingPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write updated mapping: %w", err)
	}

	logger.Info("Updated roles mapping",
		zap.String("path", rolesMappingPath),
		zap.Int("mappings_count", len(roleMappings)))

	return nil
}

// UpdateDashboardConfig updates the opensearch_dashboards.yml for SAML auth
func UpdateDashboardConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	dashboardConfigPath := "/etc/wazuh-dashboard/opensearch_dashboards.yml"

	logger.Debug("Reading current opensearch_dashboards.yml")

	data, err := os.ReadFile(dashboardConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read opensearch_dashboards.yml: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	// Settings to add/update
	settings := map[string]string{
		"opensearch_security.auth.type":         "saml",
		"opensearch_security.session.keepalive": "true",
	}

	// Check if settings already exist
	existingSettings := make(map[string]bool)
	for i, line := range lines {
		for key, value := range settings {
			if strings.HasPrefix(strings.TrimSpace(line), key+":") {
				lines[i] = fmt.Sprintf("%s: %s", key, value)
				existingSettings[key] = true
			}
		}
	}

	// Add missing settings
	for key, value := range settings {
		if !existingSettings[key] {
			lines = append(lines, fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Handle xsrf allowlist
	xsrfLine := `server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]`
	hasXSRF := false
	for i, line := range lines {
		if strings.Contains(line, "server.xsrf.allowlist") {
			lines[i] = xsrfLine
			hasXSRF = true
			break
		}
	}
	if !hasXSRF {
		lines = append(lines, xsrfLine)
	}

	newData := []byte(strings.Join(lines, "\n"))

	if err := os.WriteFile(dashboardConfigPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write updated dashboard config: %w", err)
	}

	logger.Info("Updated Wazuh dashboard config",
		zap.String("path", dashboardConfigPath))

	return nil
}

// ApplySecurityConfig applies the security configuration using securityadmin.sh
func ApplySecurityConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying OpenSearch security configuration")

	// Run securityadmin.sh to apply changes
	cmd := "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
	args := []string{
		"-cd", "/etc/wazuh-indexer/opensearch-security",
		"-icl", "-nhnv",
		"-cacert", "/etc/wazuh-indexer/certs/root-ca.pem",
		"-cert", "/etc/wazuh-indexer/certs/admin.pem",
		"-key", "/etc/wazuh-indexer/certs/admin-key.pem",
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: cmd,
		Args:    args,
		Capture: true,
		Env: []string{
			"JAVA_HOME=/usr/share/wazuh-indexer/jdk",
		},
	})

	if err != nil {
		logger.Error("securityadmin.sh failed",
			zap.String("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to apply security config: %s\nError: %w", output, err)
	}

	logger.Debug("securityadmin.sh output",
		zap.String("output", output))
	logger.Info("Security configuration applied successfully")

	return nil
}

// RestartSSOServices restarts Wazuh indexer and dashboard services for SSO
func RestartSSOServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting Wazuh services")

	// Restart indexer first
	logger.Debug("Restarting wazuh-indexer")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "wazuh-indexer"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart wazuh-indexer: %w", err)
	}

	// Wait for indexer to be ready
	logger.Debug("Waiting for wazuh-indexer to be ready")
	time.Sleep(10 * time.Second)

	// Check if indexer is responsive
	for i := 0; i < 30; i++ {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-sk", "https://localhost:9200"},
			Capture: true,
		})
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Restart dashboard
	logger.Debug("Restarting wazuh-dashboard")
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "wazuh-dashboard"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart wazuh-dashboard: %w", err)
	}

	time.Sleep(5 * time.Second)

	logger.Info("Services restarted successfully")
	return nil
}

// CheckServiceStatus checks if Wazuh services are running
func CheckServiceStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	services := []string{"wazuh-indexer", "wazuh-dashboard"}

	for _, service := range services {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		})

		if err != nil || strings.TrimSpace(output) != "active" {
			logger.Error("Service is not active",
				zap.String("service", service),
				zap.String("status", strings.TrimSpace(output)))
			return fmt.Errorf("service %s is not active: %s", service, strings.TrimSpace(output))
		}

		logger.Debug("Service is active",
			zap.String("service", service))
	}

	logger.Info("All Wazuh services are active")
	return nil
}

// Private helper functions

func updateSAMLAuthDomain(config map[string]interface{}, entityID, exchangeKey, wazuhURL string) error {
	// Navigate to config.dynamic.authc
	configMap, ok := config["config"].(map[string]interface{})
	if !ok {
		configMap = make(map[string]interface{})
		config["config"] = configMap
	}

	dynamicMap, ok := configMap["dynamic"].(map[string]interface{})
	if !ok {
		dynamicMap = make(map[string]interface{})
		configMap["dynamic"] = dynamicMap
	}

	authcMap, ok := dynamicMap["authc"].(map[string]interface{})
	if !ok {
		authcMap = make(map[string]interface{})
		dynamicMap["authc"] = authcMap
	}

	// Create SAML auth domain
	metadataPath := "/etc/wazuh-indexer/opensearch-security/authentik-metadata.xml"

	samlDomain := map[string]interface{}{
		"http_enabled":      true,
		"transport_enabled": false,
		"order":             1,
		"http_authenticator": map[string]interface{}{
			"type":      "saml",
			"challenge": true,
			"config": map[string]interface{}{
				"idp": map[string]interface{}{
					"metadata_file": metadataPath,
					"entity_id":     entityID,
				},
				"sp": map[string]interface{}{
					"entity_id":  entityID,
					"forceAuthn": false,
				},
				"kibana_url":   wazuhURL,
				"roles_key":    "Roles", // CRITICAL: Capital R for Wazuh role mapping
				"exchange_key": exchangeKey,
			},
		},
		"authentication_backend": map[string]interface{}{
			"type": "noop",
		},
	}

	authcMap["saml_auth_domain"] = samlDomain

	// Ensure basic auth domain exists as fallback
	if _, exists := authcMap["basic_internal_auth_domain"]; !exists {
		basicDomain := map[string]interface{}{
			"http_enabled":      true,
			"transport_enabled": true,
			"order":             0,
			"http_authenticator": map[string]interface{}{
				"type":      "basic",
				"challenge": true,
			},
			"authentication_backend": map[string]interface{}{
				"type": "intern",
			},
		}
		authcMap["basic_internal_auth_domain"] = basicDomain
	}

	return nil
}

func addBackendRole(mapping map[string]interface{}, opensearchRole, backendRole string) {
	roleConfig, ok := mapping[opensearchRole].(map[string]interface{})
	if !ok {
		// Role doesn't exist, create it
		roleConfig = map[string]interface{}{
			"reserved":      false,
			"backend_roles": []string{backendRole},
		}
		mapping[opensearchRole] = roleConfig
		return
	}

	// Check if backend_roles exists
	backendRoles, ok := roleConfig["backend_roles"].([]interface{})
	if !ok {
		roleConfig["backend_roles"] = []string{backendRole}
		return
	}

	// Check if role already exists
	for _, role := range backendRoles {
		if role == backendRole {
			return // Already exists
		}
	}

	// Add the role
	roleConfig["backend_roles"] = append(backendRoles, backendRole)
}
