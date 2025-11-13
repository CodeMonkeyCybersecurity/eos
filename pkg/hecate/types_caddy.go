// pkg/hecate/types_caddy.go

package hecate

import (
	"bytes"
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
