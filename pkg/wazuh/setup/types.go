// pkg/wazuh/setup/types.go
// Type definitions for Wazuh integration setup
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

// Config holds the configuration for Wazuh webhook integration setup
type Config struct {
	IntegrationsDir string // Path to Wazuh integrations directory (/var/ossec/integrations)
	OssecConfPath   string // Path to ossec.conf (/var/ossec/etc/ossec.conf)
	HookURL         string // Webhook URL for Iris integration
	WebhookToken    string // Authentication token for webhook
	IntegrationName string // Name of the integration (custom-iris)
	AutoRestart     bool   // Whether to automatically restart wazuh-manager
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		IntegrationsDir: "/var/ossec/integrations",
		OssecConfPath:   "/var/ossec/etc/ossec.conf",
		IntegrationName: "custom-iris",
		AutoRestart:     false,
	}
}
