// pkg/wazuh/ossec/types.go

package ossec

import "encoding/xml"

// OssecConfig represents the root structure of ossec.conf XML file
type OssecConfig struct {
	XMLName xml.Name `xml:"ossec_config"`
	Raw     []byte   `xml:",innerxml"`
}

// GlobalConfig represents global Wazuh manager settings
type GlobalConfig struct {
	AgentsDisconnectionTime      string `yaml:"agents_disconnection_time,omitempty"`
	AgentsDisconnectionAlertTime string `yaml:"agents_disconnection_alert_time,omitempty"`
	LogFormat                    string `yaml:"log_format,omitempty"`
	EmailNotification            string `yaml:"email_notification,omitempty"`
	SMTPServer                   string `yaml:"smtp_server,omitempty"`
	EmailFrom                    string `yaml:"email_from,omitempty"`
	EmailTo                      string `yaml:"email_to,omitempty"`
	EmailMaxperHour              int    `yaml:"email_maxperhour,omitempty"`
}

// RemoteConfig represents remote connection settings for agents
type RemoteConfig struct {
	Connection string `yaml:"connection,omitempty"`
	Port       int    `yaml:"port,omitempty"`
	Protocol   string `yaml:"protocol,omitempty"`
	QueueSize  int    `yaml:"queue_size,omitempty"`
	IPV6       string `yaml:"ipv6,omitempty"`
	LocalIP    string `yaml:"local_ip,omitempty"`
}

// VulnConfig represents vulnerability detection configuration
type VulnConfig struct {
	Enabled            string `yaml:"enabled,omitempty"`
	IndexStatus        string `yaml:"index_status,omitempty"`
	FeedUpdateInterval string `yaml:"feed_update_interval,omitempty"`
	OfflineURL         string `yaml:"offline_url,omitempty"`
}

// IntegrationConfig represents third-party integration settings (webhooks, SIEM)
type IntegrationConfig struct {
	Name        string            `yaml:"name"`
	HookURL     string            `yaml:"hook_url,omitempty"`
	APIKey      string            `yaml:"api_key,omitempty"`
	Level       int               `yaml:"level,omitempty"`
	AlertFormat string            `yaml:"alert_format,omitempty"`
	Options     map[string]string `yaml:"options,omitempty"`
}

// SyscheckConfig represents File Integrity Monitoring (FIM) configuration
type SyscheckConfig struct {
	Disabled      string   `yaml:"disabled,omitempty"`
	Frequency     int      `yaml:"frequency,omitempty"`
	ScanOnStart   string   `yaml:"scan_on_start,omitempty"`
	AlertNewFiles string   `yaml:"alert_new_files,omitempty"`
	AutoIgnore    string   `yaml:"auto_ignore,omitempty"`
	Directories   []string `yaml:"directories,omitempty"`
	IgnorePaths   []string `yaml:"ignore,omitempty"`
	MaxEPS        int      `yaml:"max_eps,omitempty"`
}

// SyslogConfig represents syslog forwarding configuration
type SyslogConfig struct {
	Server   string   `yaml:"server"`
	Port     int      `yaml:"port,omitempty"`
	Level    int      `yaml:"level,omitempty"`
	Format   string   `yaml:"format,omitempty"`
	UseFQDN  string   `yaml:"use_fqdn,omitempty"`
	Groups   []string `yaml:"groups,omitempty"`
	RuleIDs  []int    `yaml:"rule_ids,omitempty"`
	Location []string `yaml:"location,omitempty"`
}

// ActiveResponseConfig represents active response automation configuration
type ActiveResponseConfig struct {
	Disabled string   `yaml:"disabled,omitempty"`
	Command  string   `yaml:"command,omitempty"`
	Location string   `yaml:"location,omitempty"`
	AgentID  string   `yaml:"agent_id,omitempty"`
	Level    int      `yaml:"level,omitempty"`
	Groups   []string `yaml:"groups,omitempty"`
	Timeout  int      `yaml:"timeout,omitempty"`
}

// LocalfileConfig represents log file monitoring configuration
type LocalfileConfig struct {
	Location  string `yaml:"location"`
	LogFormat string `yaml:"log_format"`
	Command   string `yaml:"command,omitempty"`
	Frequency int    `yaml:"frequency,omitempty"`
	Alias     string `yaml:"alias,omitempty"`
}

// WodleConfig represents Wazuh module (wodle) configuration
type WodleConfig struct {
	Name     string                 `yaml:"name"`
	Disabled string                 `yaml:"disabled,omitempty"`
	Settings map[string]interface{} `yaml:"settings,omitempty"`
}

// UpdateOptions contains all options for updating ossec.conf
type UpdateOptions struct {
	// Core settings
	Backup       bool
	DryRun       bool
	Validate     bool
	Force        bool
	BackupPath   string
	ConfigFile   string
	RestartWazuh bool

	// Configuration sections to update
	Global         *GlobalConfig
	Remote         *RemoteConfig
	Vulnerability  *VulnConfig
	Integrations   []IntegrationConfig
	Syscheck       *SyscheckConfig
	Syslog         *SyslogConfig
	ActiveResponse *ActiveResponseConfig
	Localfiles     []LocalfileConfig
	Wodles         []WodleConfig
}
