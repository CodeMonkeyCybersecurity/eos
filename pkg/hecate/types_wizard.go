// pkg/hecate/types_wizard.go

package hecate

import "bufio"

// ServiceBundle is returned by each wizard setup and holds the full config for Compose, Nginx, and Caddy.
type ServiceBundle struct {
	Domain      string // e.g., "hera-int.cybermonkey.dev"
	BackendPort string // e.g., "8080"
	Compose     *ComposeSpec
	Nginx       *NginxSpec
	Caddy       *CaddySpec
}

// PromptField describes a field to prompt the user for.
type PromptField struct {
	Prompt  string
	Default string
	EnvVar  string
	Reader  *bufio.Reader
}
