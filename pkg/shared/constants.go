// pkg/shared/consts.go

package shared

const (
	SudoersEosPath      = "/etc/sudoers.d/eos"
	SystemctlVaultStart = "/usr/bin/systemctl start vault*"
	CatVaultAgentToken  = "/bin/cat /run/eos/vault_agent_eos.token"
)

const SudoersEosEntry = `eos ALL=(ALL) NOPASSWD: ` + SystemctlVaultStart + `, ` + CatVaultAgentToken

const (
	// Permission modes (in octal)
	DirPermStandard        = 0755
	VaultRuntimePerms      = 0750
	FilePermOwnerRWX       = 0700
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
	EosID      = "eos"
	EosUser          = EosID
	EosGroup         = EosID
	VaultAgentUser   = EosID
	VaultAgentGroup  = EosID
	DefaultConfigDir = EosID
	EosVaultUsername = EosID
	DefaultNamespace = EosID
)

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
