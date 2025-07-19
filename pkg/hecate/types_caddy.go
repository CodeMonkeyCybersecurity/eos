// pkg/hecate/types_caddy.go

package hecate

import (
	"bytes"
	"fmt"
	"text/template"
)

var caddyFragments []CaddyFragment

// CaddyFragment is the rendered result for one service.
type CaddyFragment struct {
	ServiceName string
	CaddyBlock  string
}

type CaddyAppProxy struct {
	AppName         string
	Domain          string
	BackendIP       string
	BackendPort     string
	ExtraDirectives string //  Optional: timeouts, headers
	ServiceType     string // NEW: e.g., "web", "api", "db-proxy"
}

func NewCaddyAppProxy(appName, domain, backendIP, backendPort string, extra string) CaddyAppProxy {
	return CaddyAppProxy{
		AppName:         appName,
		Domain:          domain,
		BackendIP:       backendIP,
		BackendPort:     backendPort,
		ExtraDirectives: extra,
	}
}

type CaddySpec struct {
	AuthentikDomain string          // Only 1 expected (special case)
	Proxies         []CaddyAppProxy // All proxies (Wazuh, Jenkins, Nextcloud, etc.)
	// Deprecated: Use AuthentikDomain instead
	KeycloakDomain string
}

// Template for reverse proxy block.
const GenericCaddyBlockTemplate = `
{{ .Domain }} {
    reverse_proxy {{ .BackendIP }}:{{ .BackendPort }}
    {{- if .ExtraDirectives }}
    {{ .ExtraDirectives }}
    {{- end }}
}
`

func RenderCaddyfileContent(spec CaddySpec) (string, error) {
	tmplStr := `
{{- if .KeycloakDomain }}
{{ .KeycloakDomain }} {
    reverse_proxy keycloak:8080
}
{{ end }}

{{- range .Proxies }}
{{ .Domain }} {
    reverse_proxy {{ .BackendIP }}:{{ .BackendPort }}
}
{{- end }}
`
	tmpl, err := template.New("caddyfile").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, spec); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ToFragment renders the CaddySpec into a usable CaddyFragment.
func (c *CaddySpec) ToFragment(backendIP string) (CaddyFragment, error) {
	if len(c.Proxies) == 0 && c.KeycloakDomain == "" {
		return CaddyFragment{}, fmt.Errorf("no proxies or Keycloak domain to render for %s", c.KeycloakDomain)
	}

	// Template logic
	tmpl, err := template.New("caddyblock").Parse(GenericCaddyBlockTemplate)
	if err != nil {
		return CaddyFragment{}, err
	}

	var buf bytes.Buffer

	for _, proxy := range c.Proxies {
		// Fill in runtime backend IP (like Nginx does)
		proxy.BackendIP = backendIP

		if err := tmpl.Execute(&buf, proxy); err != nil {
			return CaddyFragment{}, err
		}
		buf.WriteString("\n\n")
	}

	// Special case: handle Keycloak separately
	if c.KeycloakDomain != "" {
		keycloakBlock := fmt.Sprintf(`
%s {
    reverse_proxy hecate-kc:8080
}
`, c.KeycloakDomain)
		buf.WriteString(keycloakBlock)
		buf.WriteString("\n\n")
	}

	return CaddyFragment{
		ServiceName: c.KeycloakDomain, // or use something meaningful
		CaddyBlock:  buf.String(),
	}, nil
}
