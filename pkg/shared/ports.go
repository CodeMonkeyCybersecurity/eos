// pkg/shared/ports.go
// Centralized port management for Eos services
// Convention: Prime numbers starting from 8000 for internal service ports

package shared

// Port constants following prime number convention starting from 8000
const (
	PortHelen       = 8009
	PortWazuh       = 8011
	PortMattermost  = 8017
	PortMailcow     = 8053
	PortGrafana     = 8069
	PortKeycloak    = 8080
	PortElk         = 8081
	PortStack       = 8087
	PortArachne     = 8089
	PortSoc         = 8093
	PortRestic      = 8101
	PortUmami       = 8117
	PortMinio       = 8123
	PortN8n         = 8147 // Planned
	PortConsul      = 8161 // Not 8500
	PortGitea       = 8167 // Planned
	PortGophish     = 8171 // Planned, migrating from 8080
	PortVault       = 8179 // Not 8200
	PortConsulWeb   = 8191
	PortConsulAPI   = 8209
	PortGophishAPI  = 8209 // Legacy Gophish port 3333→8209
	PortZabbix      = 8233
	PortZabbixAPI   = 8237
	
	// Next available primes: 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269...
	
	// Legacy ports to be migrated
	PortJenkinsLegacy   = 55000  // Should move to 8xxx range
	PortNextcloudLegacy = 11000  // Should move to 8xxx range
	PortResticAPI       = 9101   // Should move to 8xxx range
	PortMinioAPI        = 9123   // Should move to 8xxx range
)

type AppProxy struct {
	AppName     string
	Subdomain   string
	BackendPort int
}

var AppProxies = []AppProxy{
	{AppName: "helen", Subdomain: "", BackendPort: PortHelen},
	{AppName: "wazuh", Subdomain: "delphi", BackendPort: PortWazuh},
	{AppName: "mattermost", Subdomain: "m", BackendPort: PortMattermost},
	{AppName: "mailcow", Subdomain: "mail", BackendPort: PortMailcow},
	{AppName: "grafana", Subdomain: "g", BackendPort: PortGrafana},
	{AppName: "keycloak", Subdomain: "hera", BackendPort: PortKeycloak},
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
}

// n8n 8147 
// 8167 gitea
// 8171:80 , 8209:3333  gophish
//    8219, 8221, 8231

// Centralized service stream blocks.
var (
	MailcowStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "mailcow_smtp", BackendPort: "25", ListenPort: "25"},
		{UpstreamName: "mailcow_submission", BackendPort: "587", ListenPort: "587"},
		{UpstreamName: "mailcow_smtps", BackendPort: "465", ListenPort: "465"},
		{UpstreamName: "mailcow_pop3", BackendPort: "110", ListenPort: "110"},
		{UpstreamName: "mailcow_pop3s", BackendPort: "995", ListenPort: "995"},
		{UpstreamName: "mailcow_imap", BackendPort: "143", ListenPort: "143"},
		{UpstreamName: "mailcow_imaps", BackendPort: "993", ListenPort: "993"},
	}

	JenkinsStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "jenkins_agent", BackendPort: "8059", ListenPort: "50000"},
	}

	WazuhStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "wazuh_manager_1515", BackendPort: "1515", ListenPort: "1515"},
		{UpstreamName: "wazuh_manager_1514", BackendPort: "1514", ListenPort: "1514"},
		{UpstreamName: "wazuh_manager_55000", BackendPort: "55000", ListenPort: "55000"},
	}
)

// Centralized port maps (unchanged).
var (
	MailcowPorts = ServicePorts{
		TCP: []string{"25", "587", "465", "110", "995", "143", "993"},
		UDP: []string{},
	}

	JenkinsPorts = ServicePorts{
		TCP: []string{"50000"},
		UDP: []string{},
	}

	WazuhPorts = ServicePorts{
		TCP: []string{"1515", "1514", "55000"},
		UDP: []string{"1515", "1514"},
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
