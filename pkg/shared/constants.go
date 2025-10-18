// pkg/shared/constants.go

package shared

const (
	EosSudoersPath      = "/etc/sudoers.d/eos"
	SystemctlVaultStart = "/usr/bin/systemctl start vault*"
	// #nosec G101 - This is a command to read a token file, not a hardcoded credential
	CatVaultAgentToken = "/bin/cat /run/eos/vault_agent_eos.token"
	SudoersLine        = "eos ALL=(ALL) NOPASSWD: /bin/systemctl"
	EosLogDir          = "/var/log/eos/"
	EosLogs            = EosLogDir + "eos.log"
	// #nosec G101 - This is a log file path, not a hardcoded credential
	EosLogsPWD      = "./eos.log"
	EosShellNoLogin = "/usr/sbin/nologin"
	EosShellBash    = "/bin/bash"
)

const SudoersEosEntry = `eos ALL=(ALL) NOPASSWD: ` + SystemctlVaultStart + `, ` + CatVaultAgentToken

const (
	// Permission modes (in octal)
	DirPermStandard        = 0755
	RuntimeDirPerms        = 0750
	FilePermOwnerRWX       = 0700
	RuntimeFilePerms       = 0640
	FilePermStandard       = 0644
	FilePermOwnerReadWrite = 0600
	FilePermReadOnly       = 0444
	OwnerReadOnly          = 0400
)

const (
	LDAPVaultPath        = "eos/ldap"             // For use with WriteToVault, ReadFromVaultAt
	LDAPVaultPathFull    = "secret/data/eos/ldap" // For UI or external calls
	LDAPVaultMount       = "secret"
	LDAPFallbackFileName = "ldap_config.json"
)

const (
	DefaultConfigFilename = "config.json"
)

const (
	EosID = "eos"
)

const (
	// Wazuh Paths
	VenvPath       = "/opt/wazuh_venv"
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
