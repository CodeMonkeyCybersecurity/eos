// pkg/consul/acl/templates.go
//
// Policy template definitions and rendering
//
// Last Updated: 2025-10-23

package acl

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// RenderPolicyTemplate renders a policy from a template with variable substitution
func (pm *ConsulPolicyManager) RenderPolicyTemplate(ctx context.Context, template PolicyTemplate, vars map[string]string) (*Policy, error) {
	pm.logger.Info("Rendering policy template",
		zap.String("template", string(template)))

	rules, description := getPolicyTemplate(template)
	if rules == "" {
		return nil, fmt.Errorf("unknown policy template: %s", template)
	}

	// Substitute variables
	for key, value := range vars {
		placeholder := fmt.Sprintf("{{%s}}", key)
		rules = strings.ReplaceAll(rules, placeholder, value)
		description = strings.ReplaceAll(description, placeholder, value)
	}

	// Validate no unsubstituted variables remain
	if strings.Contains(rules, "{{") {
		return nil, fmt.Errorf("template has unsubstituted variables in rules: %s", rules)
	}

	// Generate policy name from template and vars
	policyName := generatePolicyName(template, vars)

	policy := &Policy{
		Name:        policyName,
		Description: description,
		Rules:       rules,
	}

	return policy, nil
}

// getPolicyTemplate returns the HCL rules and description for a template
func getPolicyTemplate(template PolicyTemplate) (rules string, description string) {
	switch template {

	case PolicyTemplateServiceRead:
		description = "Read-only access to service {{service_name}}"
		rules = `
service "{{service_name}}" {
  policy = "read"
}
`

	case PolicyTemplateServiceWrite:
		description = "Read-write access to service {{service_name}}"
		rules = `
service "{{service_name}}" {
  policy = "write"
}
service_prefix "" {
  policy = "read"
}
`

	case PolicyTemplateKVRead:
		description = "Read-only access to KV path {{kv_path}}"
		rules = `
key_prefix "{{kv_path}}" {
  policy = "read"
}
`

	case PolicyTemplateKVWrite:
		description = "Read-write access to KV path {{kv_path}}"
		rules = `
key_prefix "{{kv_path}}" {
  policy = "write"
}
`

	case PolicyTemplateNodeRead:
		description = "Read-only access to node {{node_name}}"
		rules = `
node "{{node_name}}" {
  policy = "read"
}
`

	case PolicyTemplateNodeWrite:
		description = "Read-write access to node {{node_name}}"
		rules = `
node "{{node_name}}" {
  policy = "write"
}
node_prefix "" {
  policy = "read"
}
`

	case PolicyTemplateOperator:
		description = "Operator access for administrative tasks"
		rules = `
operator = "write"
acl = "write"
agent_prefix "" {
  policy = "write"
}
service_prefix "" {
  policy = "write"
}
node_prefix "" {
  policy = "write"
}
key_prefix "" {
  policy = "write"
}
`

	case PolicyTemplateVaultAccess:
		description = "Vault server access to Consul for storage and service registration"
		rules = `
# Vault storage backend
key_prefix "vault/" {
  policy = "write"
}

# Service registration
service "vault" {
  policy = "write"
}

# Health checks
agent_prefix "" {
  policy = "read"
}

# Node catalog for HA coordination
node_prefix "" {
  policy = "read"
}

# Session management for HA locking
session_prefix "" {
  policy = "write"
}
`

	case PolicyTemplateMonitoringAgent:
		description = "Monitoring agent access for metrics and health checks"
		rules = `
# Service discovery
service_prefix "" {
  policy = "read"
}

# Node information
node_prefix "" {
  policy = "read"
}

# Agent metrics
agent_prefix "" {
  policy = "read"
}

# Health check status
key_prefix "health/" {
  policy = "read"
}

# Catalog access
operator = "read"
`

	default:
		return "", ""
	}

	return strings.TrimSpace(rules), description
}

// generatePolicyName creates a policy name from template and variables
func generatePolicyName(template PolicyTemplate, vars map[string]string) string {
	switch template {
	case PolicyTemplateServiceRead:
		if name, ok := vars["service_name"]; ok {
			return fmt.Sprintf("service-read-%s", name)
		}
		return "service-read"

	case PolicyTemplateServiceWrite:
		if name, ok := vars["service_name"]; ok {
			return fmt.Sprintf("service-write-%s", name)
		}
		return "service-write"

	case PolicyTemplateKVRead:
		if path, ok := vars["kv_path"]; ok {
			// Clean path for use in name
			cleanPath := strings.ReplaceAll(path, "/", "-")
			cleanPath = strings.Trim(cleanPath, "-")
			return fmt.Sprintf("kv-read-%s", cleanPath)
		}
		return "kv-read"

	case PolicyTemplateKVWrite:
		if path, ok := vars["kv_path"]; ok {
			cleanPath := strings.ReplaceAll(path, "/", "-")
			cleanPath = strings.Trim(cleanPath, "-")
			return fmt.Sprintf("kv-write-%s", cleanPath)
		}
		return "kv-write"

	case PolicyTemplateNodeRead:
		if name, ok := vars["node_name"]; ok {
			return fmt.Sprintf("node-read-%s", name)
		}
		return "node-read"

	case PolicyTemplateNodeWrite:
		if name, ok := vars["node_name"]; ok {
			return fmt.Sprintf("node-write-%s", name)
		}
		return "node-write"

	case PolicyTemplateOperator:
		return "operator"

	case PolicyTemplateVaultAccess:
		return "vault-access"

	case PolicyTemplateMonitoringAgent:
		return "monitoring-agent"

	default:
		return string(template)
	}
}

// Common policy builders

// BuildServicePolicy creates a service access policy
func BuildServicePolicy(serviceName string, write bool) *Policy {
	template := PolicyTemplateServiceRead
	if write {
		template = PolicyTemplateServiceWrite
	}

	rules, description := getPolicyTemplate(template)
	rules = strings.ReplaceAll(rules, "{{service_name}}", serviceName)
	description = strings.ReplaceAll(description, "{{service_name}}", serviceName)

	name := fmt.Sprintf("service-%s-%s", map[bool]string{true: "write", false: "read"}[write], serviceName)

	return &Policy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}
}

// BuildKVPolicy creates a KV store access policy
func BuildKVPolicy(kvPath string, write bool) *Policy {
	template := PolicyTemplateKVRead
	if write {
		template = PolicyTemplateKVWrite
	}

	rules, description := getPolicyTemplate(template)
	rules = strings.ReplaceAll(rules, "{{kv_path}}", kvPath)
	description = strings.ReplaceAll(description, "{{kv_path}}", kvPath)

	cleanPath := strings.ReplaceAll(kvPath, "/", "-")
	cleanPath = strings.Trim(cleanPath, "-")
	name := fmt.Sprintf("kv-%s-%s", map[bool]string{true: "write", false: "read"}[write], cleanPath)

	return &Policy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}
}

// BuildNodePolicy creates a node access policy
func BuildNodePolicy(nodeName string, write bool) *Policy {
	template := PolicyTemplateNodeRead
	if write {
		template = PolicyTemplateNodeWrite
	}

	rules, description := getPolicyTemplate(template)
	rules = strings.ReplaceAll(rules, "{{node_name}}", nodeName)
	description = strings.ReplaceAll(description, "{{node_name}}", nodeName)

	name := fmt.Sprintf("node-%s-%s", map[bool]string{true: "write", false: "read"}[write], nodeName)

	return &Policy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}
}

// BuildOperatorPolicy creates an operator access policy
func BuildOperatorPolicy() *Policy {
	rules, description := getPolicyTemplate(PolicyTemplateOperator)

	return &Policy{
		Name:        "operator",
		Description: description,
		Rules:       rules,
	}
}

// BuildVaultAccessPolicy creates a Vault integration policy
func BuildVaultAccessPolicy() *Policy {
	rules, description := getPolicyTemplate(PolicyTemplateVaultAccess)

	return &Policy{
		Name:        "vault-access",
		Description: description,
		Rules:       rules,
	}
}

// BuildMonitoringAgentPolicy creates a monitoring agent policy
func BuildMonitoringAgentPolicy() *Policy {
	rules, description := getPolicyTemplate(PolicyTemplateMonitoringAgent)

	return &Policy{
		Name:        "monitoring-agent",
		Description: description,
		Rules:       rules,
	}
}

// BuildCustomPolicy creates a custom policy with raw HCL rules
func BuildCustomPolicy(name, description, rules string) *Policy {
	return &Policy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}
}
