// pkg/hecate/types_wizard.go

package hecate

// ServiceBundle is returned by each wizard setup and holds the full config for Compose, Nginx, and Caddy.
type ServiceBundle struct {
	Compose *ComposeSpec
	Nginx   *NginxSpec
	Caddy   *CaddySpec
}

const (
	// Centralized Hecate file paths
	BaseDir               = "/opt/hecate"
	HecateDockerCompose   = BaseDir + "/docker-compose.yml"
	HecateCaddyfile       = BaseDir + "/Caddyfile"
	HecateNginxConfig     = BaseDir + "/nginx.conf"
	HecateStreamFragments = BaseDir + "/assets/conf.d/stream"
	HecateCertsDir        = BaseDir + "/certs"
	HecateLogsDir         = BaseDir + "/logs"
	HecateAssetsDir       = BaseDir + "/assets"
	HecateErrorsDir       = BaseDir + "/error_pages"
)
