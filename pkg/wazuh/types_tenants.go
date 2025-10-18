// pkg/wazuh/types_tenants.go

package wazuh

import (
	"bytes"
	"fmt"
	"text/template"
)

const roleMappingTemplate = `
{{ .Name }}:
  reserved: false
  hidden: false
  backend_roles:
    - "{{ .Name }}"
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps {{ .Name }} role to Wazuh {{ .Name }}"
`

type RoleMappingInput struct {
	Name            string
	Users           []string // TODO: inject Keycloak usernames
	Hosts           []string // TODO: inject IPs or hostnames
	AndBackendRoles []string // TODO: for composite roles
	Reserved        bool     // TODO: enable read-only control
	Hidden          bool     // TODO: hide from UI
}

func GenerateRoleMappingYAML(input RoleMappingInput) (string, error) {
	tmpl, err := template.New("rolemap").Parse(roleMappingTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, input)
	if err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}
	return buf.String(), nil
}

type TenantSpec struct {
	Name     string `json:"name"`                // Logical tenant name (e.g. "alice")
	User     string `json:"user"`                // Keycloak username (e.g. "alice")
	GroupID  string `json:"group_id"`            // Wazuh agent group (e.g. "group_alice")
	RoleID   string `json:"role_id,omitempty"`   // Optional explicit Wazuh role ID
	PolicyID string `json:"policy_id,omitempty"` // Optional explicit Wazuh policy ID
	UserID   string `json:"user_id,omitempty"`
}
