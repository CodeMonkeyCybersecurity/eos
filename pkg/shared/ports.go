// pkg/shared/ports.go
// Centralized port management for Eos services
// Convention: Prime numbers starting from 8000 for internal service ports

package shared

import "fmt"

// Port constants following prime number convention starting from 8000
const (
	PortHelen      = 8009
	PortWazuh      = 8011
	PortMattermost = 8017
	PortMailcow    = 8053
	PortGrafana    = 8069
	// Deprecated: Use PortAuthentik instead
	PortElk          = 8081
	PortStack        = 8087
	PortArachne      = 8089
	PortSoc          = 8093
	PortRestic       = 8101
	PortUmami        = 8117
	PortMinio        = 8123
	PortN8n          = 8147 // Planned
	PortConsul       = 8500 // HashiCorp Consul HTTP API (standard)
	PortGitea        = 8167 // Planned
	PortGophish      = 8171 // Planned, migrating from 8080
	PortVault        = 8200 // HashiCorp Vault API (standard)
	PortVaultCluster = 8201 // Vault Raft cluster communication (standard)
	PortConsulWeb    = 8191
	PortConsulAPI    = 8209
	PortGophishAPI   = 8209 // Legacy Gophish port 3333→8209
	PortZabbix       = 8233
	PortZabbixAPI    = 8237
	PortPenpot       = 8239 // Design platform
	PortNomad        = 4646 // HashiCorp Nomad HTTP API (standard)

	// New port definitions using next available primes
	PortPostgreSQL     = 8263 // PostgreSQL database (not 5432)
	PortRedis          = 8269 // Redis cache (not 6379)
	PortPrometheus     = 8273 // Prometheus metrics (not 9090)
	PortGuacamole      = 8287 // Apache Guacamole (not 8080)
	PortJenkins        = 8291 // Jenkins UI (not 8080)
	PortJenkinsAgent   = 8293 // Jenkins agent (not 50000)
	PortOllama         = 8297 // Ollama web UI (not 3000)
	PortKubernetesAPI  = 8311 // Kubernetes API server (not 6443)
	PortKubelet        = 8317 // Kubelet API (not 10250)
	PortFlannel        = 8329 // Flannel VXLAN (not 8472)
	PortZabbixServer   = 8353 // Zabbix server (not 10051)
	PortZabbixAgent    = 8363 // Zabbix agent (not 10050)
	PortHecateAPI      = 8369 // Hecate API server (not 8080)
	PortNomadSerf      = 4648 // HashiCorp Nomad Serf gossip (standard)
	PortNomadRPC       = 4647 // HashiCorp Nomad RPC (standard)
	PortHeadscaleGRPC  = 8387 // Headscale GRPC (not 50443)
	PortBoundary       = 8419 // HashiCorp Boundary (not 9200)
	PortTerraform      = 8423 // Terraform Enterprise (if needed)
	PortPacker         = 8429 // Packer (if server mode added)
	PortConsulDNS      = 8600 // Consul DNS (HashiCorp standard)
	PortConsulRPC      = 8300 // Consul server RPC (HashiCorp standard)
	PortConsulSerfLAN  = 8301 // Consul Serf LAN (HashiCorp standard)
	PortConsulSerfWAN  = 8302 // Consul Serf WAN (HashiCorp standard)
	PortBuildService   = 8431 // Build orchestrator service (not 8080)
	PortCaddyAdmin     = 8443 // Caddy admin API (not 2019)
	PortAuthentik      = 9000 // Authentik identity provider (HTTP)
	PortPenpotBackend  = 8461 // Penpot backend API (not 6060)
	PortPenpotExporter = 8467 // Penpot exporter (not 6061)
	PortOpenWebUI      = 8501 // Open WebUI (not 3000)
	PortBionicGPT      = 8513 // BionicGPT multi-tenant LLM platform (not 3000)

	// Temporal/Iris ports
	PortTemporalGRPC    = 7233 // Temporal gRPC frontend (standard)
	PortTemporalUI      = 8233 // Temporal Web UI
	PortTemporalMetrics = 9090 // Temporal Prometheus metrics

	// Well-known ports that should remain standard
	PortHTTP       = 80  // Standard HTTP
	PortHTTPS      = 443 // Standard HTTPS
	PortSSH        = 22  // Standard SSH
	PortSMTP       = 25  // Standard SMTP
	PortPOP3       = 110 // Standard POP3
	PortIMAP       = 143 // Standard IMAP
	PortSMTPS      = 465 // Standard SMTPS
	PortSubmission = 587 // Standard mail submission
	PortIMAPSSL    = 993 // Standard IMAPS
	PortPOP3SSL    = 995 // Standard POP3S

	// Next available primes: 8521, 8527, 8537, 8539, 8543, 8563...

	// Legacy ports to be migrated
	PortJenkinsLegacy   = 55000 // Should move to 8291
	PortNextcloudLegacy = 11000 // Should move to 8xxx range
	PortResticAPI       = 9101  // Should move to 8xxx range
	PortMinioAPI        = 9123  // Should move to 8xxx range

	// HashiCorp standard ports (now using defaults)
	// Note: PortConsul and PortVault now use HashiCorp defaults
	// Consul: 8500 (HTTP), 8501 (HTTPS), 8502 (gRPC), 8600 (DNS)
	// Consul Serf: 8301 (LAN), 8302 (WAN)
	// Consul RPC: 8300
	// Vault: 8200 (HTTP), 8201 (cluster)

	// Additional port constants for legacy services
	PortWazuh1514  = 1514  // Wazuh manager port
	PortWazuh1515  = 1515  // Wazuh manager port
	PortWazuh55000 = 55000 // Wazuh web port (legacy)
)

// Port string conversion helpers
func PortToString(port int) string {
	return fmt.Sprintf("%d", port)
}

// Common port string constants for convenience
var (
	PortVaultStr      = PortToString(PortVault)
	PortConsulStr     = PortToString(PortConsul)
	PortNomadStr      = PortToString(PortNomad)
	PortPostgreSQLStr = PortToString(PortPostgreSQL)
	PortRedisStr      = PortToString(PortRedis)
	PortGrafanaStr    = PortToString(PortGrafana)
)

type AppProxy struct {
	AppName     string
	Subdomain   string
	BackendPort int
}

var AppProxies = []AppProxy{
	{AppName: "helen", Subdomain: "", BackendPort: PortHelen},
	{AppName: "wazuh", Subdomain: "wazuh", BackendPort: PortWazuh},
	{AppName: "mattermost", Subdomain: "m", BackendPort: PortMattermost},
	{AppName: "mailcow", Subdomain: "mail", BackendPort: PortMailcow},
	{AppName: "grafana", Subdomain: "g", BackendPort: PortGrafana},
	{AppName: "authentik", Subdomain: "hera", BackendPort: PortAuthentik},
	// Deprecated: Use authentik instead
	{AppName: "elk", Subdomain: "e", BackendPort: PortElk},
	{AppName: "stack", Subdomain: "e", BackendPort: PortStack},
	{AppName: "arachne", Subdomain: "arachne", BackendPort: PortArachne},
	{AppName: "soc", Subdomain: "e", BackendPort: PortSoc},
	{AppName: "restic", Subdomain: "persephone", BackendPort: PortRestic},
	{AppName: "resticapi", Subdomain: "persephoneapi", BackendPort: PortResticAPI},
	{AppName: "zabbix", Subdomain: "z", BackendPort: PortZabbix},
	{AppName: "zabbixapi", Subdomain: "z-api", BackendPort: PortZabbixAPI},
	{AppName: "consul", Subdomain: "c", BackendPort: PortConsulWeb},
	{AppName: "consulapi", Subdomain: "c-api", BackendPort: PortConsulAPI},
	{AppName: "umami", Subdomain: "u", BackendPort: PortUmami},
	{AppName: "minio", Subdomain: "s3", BackendPort: PortMinio},
	{AppName: "minio-api", Subdomain: "s3api", BackendPort: PortMinioAPI},
	{AppName: "jenkins", Subdomain: "j-api", BackendPort: PortJenkinsLegacy},
	{AppName: "nextcloud", Subdomain: "cloud", BackendPort: PortNextcloudLegacy},
	{AppName: "n8n", Subdomain: "n8n", BackendPort: PortN8n},
}

// n8n 8147
// 8167 gitea
// 8171:80 , 8209:3333  gophish
//    8219, 8221, 8231

// Centralized service stream blocks.
var (
	MailcowStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "mailcow_smtp", BackendPort: PortToString(PortSMTP), ListenPort: PortToString(PortSMTP)},
		{UpstreamName: "mailcow_submission", BackendPort: PortToString(PortSubmission), ListenPort: PortToString(PortSubmission)},
		{UpstreamName: "mailcow_smtps", BackendPort: PortToString(PortSMTPS), ListenPort: PortToString(PortSMTPS)},
		{UpstreamName: "mailcow_pop3", BackendPort: PortToString(PortPOP3), ListenPort: PortToString(PortPOP3)},
		{UpstreamName: "mailcow_pop3s", BackendPort: PortToString(PortPOP3SSL), ListenPort: PortToString(PortPOP3SSL)},
		{UpstreamName: "mailcow_imap", BackendPort: PortToString(PortIMAP), ListenPort: PortToString(PortIMAP)},
		{UpstreamName: "mailcow_imaps", BackendPort: PortToString(PortIMAPSSL), ListenPort: PortToString(PortIMAPSSL)},
	}

	JenkinsStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "jenkins_agent", BackendPort: PortToString(PortJenkinsAgent), ListenPort: PortToString(PortJenkinsAgent)},
	}

	WazuhStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "wazuh_manager_1515", BackendPort: PortToString(PortWazuh1515), ListenPort: PortToString(PortWazuh1515)},
		{UpstreamName: "wazuh_manager_1514", BackendPort: PortToString(PortWazuh1514), ListenPort: PortToString(PortWazuh1514)},
		{UpstreamName: "wazuh_manager_55000", BackendPort: PortToString(PortWazuh55000), ListenPort: PortToString(PortWazuh55000)},
	}
)

// Centralized port maps
var (
	MailcowPorts = ServicePorts{
		TCP: []string{
			PortToString(PortSMTP),
			PortToString(PortSubmission),
			PortToString(PortSMTPS),
			PortToString(PortPOP3),
			PortToString(PortPOP3SSL),
			PortToString(PortIMAP),
			PortToString(PortIMAPSSL),
		},
		UDP: []string{},
	}

	JenkinsPorts = ServicePorts{
		TCP: []string{PortToString(PortJenkinsAgent)},
		UDP: []string{},
	}

	WazuhPorts = ServicePorts{
		TCP: []string{
			PortToString(PortWazuh1515),
			PortToString(PortWazuh1514),
			PortToString(PortWazuh55000),
		},
		UDP: []string{
			PortToString(PortWazuh1515),
			PortToString(PortWazuh1514),
		},
	}
)

// Centralized port configs (TCP/UDP) for quick reference.
type ServicePorts struct {
	TCP []string
	UDP []string
}

// NginxStreamBlock defines the config for one upstream + server block.
type NginxStreamBlock struct {
	BackendIP    string
	UpstreamName string
	BackendPort  string
	ListenPort   string
}
