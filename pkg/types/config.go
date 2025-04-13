// pkg/types/config.go

package types

//
// ---------------------------- CONSTANTS ---------------------------- //
//

const (
	// Delphi Paths
	VenvPath       = "/opt/delphi_venv"
	DockerListener = "/var/ossec/wodles/docker/DockerListener"

	// Install Paths
	UmamiDir   = "/opt/umami"
	JenkinsDir = "/opt/jenkins"
	ZabbixDir  = "/opt/zabbix"
	HeraDir    = "/opt/hera"

	JenkinsComposeYML = JenkinsDir + "/jenkins-docker-compose.yml"
	UmamiComposeYML   = UmamiDir + "/umami-docker-compose.yml"
	ZabbixComposeYML  = ZabbixDir + "/zabbix-docker-compose.yml"
	HeraComposeYML    = HeraDir + "/hera-docker-compose.yml"

	// Treecat preview
	MaxPreviewSize  = 5 * 1024
	MaxPreviewLines = 100

	// Hecate defaults
	HecateLastValuesFile = ".hecate.conf"
	DefaultComposeYML    = "docker-compose.yml"
	DefaultCertsDir      = "certs"
	DefaultConfDir       = "conf.d"
	AssetsPath           = "assets"
	NginxConfPath        = "/etc/nginx/conf.d/"
	NginxStreamPath      = "/etc/nginx/stream.d/"
	DockerNetworkName    = "arachne-net"
	DockerIPv4Subnet     = "10.1.0.0/16"
	DockerIPv6Subnet     = "fd42:1a2b:3c4d:5e6f::/64"
	DefaultConfigPath    = "./config/default.yaml"
	AssetServerPath      = "assets/servers"
	AssetStreamPath      = "assets/stream"
)

var DefaultMarkers = []string{"80", "443"}

func CombineMarkers(additional ...string) []string {
	return append(DefaultMarkers, additional...)
}
