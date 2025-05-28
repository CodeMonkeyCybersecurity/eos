// pkg/hecate/types_wizard.go

package hecate

const (
	// Centralized Hecate file paths
	BaseDir = "/opt/hecate/"

	// Files
	HecateDockerCompose     = BaseDir + "docker-compose.yml"
	HecateCaddyfile         = BaseDir + "Caddyfile"
	HecateNginxConfig       = BaseDir + "nginx.conf"
	HecateStreamIncludePath = HecateConfDDir + "stream_include.conf"

	// Dirs
	HecateStreamFragments = BaseDir + "assets/conf.d/stream/"
	HecateCertsDir        = BaseDir + "certs/"
	HecateLogsDir         = BaseDir + "logs/"
	HecateAssetsDir       = BaseDir + "assets/"
	HecateErrorsDir       = BaseDir + "error_pages/"
	HecateConfDDir        = HecateAssetsDir + "conf.d/"
	HecateStreamDir       = HecateConfDDir + "stream/"
)

const StreamIncludeTemplate = `
stream {
    include /etc/nginx/conf.d/stream/*.conf;
}
`
