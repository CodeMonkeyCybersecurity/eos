// pkg/shared/ports.go

package shared

type AppProxy struct {
	AppName     string
	Subdomain   string
	BackendPort int
}

var AppProxies = []AppProxy{
	{AppName: "helen", Subdomain: "", BackendPort: 8009},
	{AppName: "wazuh", Subdomain: "delphi", BackendPort: 8011},
	{AppName: "mattermost", Subdomain: "m", BackendPort: 8017},
	{AppName: "mailcow", Subdomain: "mail", BackendPort: 8053},
	{AppName: "grafana", Subdomain: "g", BackendPort: 8069},
	{AppName: "keycloak", Subdomain: "hera", BackendPort: 8080},
	{AppName: "elk", Subdomain: "e", BackendPort: 8081},
	{AppName: "stack", Subdomain: "e", BackendPort: 8087},
	{AppName: "arachne", Subdomain: "arachne", BackendPort: 8089},
	{AppName: "soc", Subdomain: "e", BackendPort: 8093},
	{AppName: "restic", Subdomain: "persephone", BackendPort: 8101},
	{AppName: "resticapi", Subdomain: "persephoneapi", BackendPort: 9101},
	{AppName: "zabbix", Subdomain: "z", BackendPort: 8233},
	{AppName: "zabbixapi", Subdomain: "z-api", BackendPort: 8237},
	{AppName: "consul", Subdomain: "c", BackendPort: 8191},
	{AppName: "consulapi", Subdomain: "c-api", BackendPort: 8209},
	{AppName: "umami", Subdomain: "u", BackendPort: 8117},
	{AppName: "minio", Subdomain: "s3", BackendPort: 8123},
	{AppName: "minio-api", Subdomain: "s3api", BackendPort: 9123},
	{AppName: "jenkins", Subdomain: "j-api", BackendPort: 55000},
	{AppName: "nextcloud", Subdomain: "cloud", BackendPort: 11000},
}

// n8n 8147 
// 8161 consul
// 8167 gitea
// 8171 
// 8179 8191 8209 8219, 8221, 8231

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
