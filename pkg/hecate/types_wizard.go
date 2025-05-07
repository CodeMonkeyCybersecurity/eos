// pkg/hecate/types_wizard.go

package hecate

// ServiceBundle is returned by each wizard setup and holds the full config for Compose, Nginx, and Caddy.
type ServiceBundle struct {
	Compose *ComposeSpec
	Nginx   *NginxSpec
	Caddy   *CaddySpec
}

