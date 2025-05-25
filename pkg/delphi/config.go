/* pkg/delphi/config.go */
package delphi

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

func (c *Config) BaseURL() string {
	return fmt.Sprintf("%s://%s:%s", c.Protocol, c.FQDN, c.Port)
}

// BaseURL returns the root API endpoint for the configured Delphi instance
func BaseURL(cfg *Config) string {
	return fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
}

func (c *Config) IsValid() bool {
	return c != nil &&
		c.FQDN != "" &&
		c.APIUser != "" &&
		c.APIPassword != ""
}

func PromptDelphiConfig() *Config {
	password, err := crypto.PromptPassword("Enter the API password")
	if err != nil {
		zap.L().Error("❌ Failed to read password: %v\n")
		os.Exit(1)
	}

	return &Config{
		FQDN:               interaction.PromptInput("Enter the Wazuh FQDN", "domain.com"),
		Port:               interaction.PromptInput("Enter the port", "55000"),
		Protocol:           interaction.PromptInput("Enter the protocol (http or https)", "https"),
		APIUser:            interaction.PromptInput("Enter the API username", "wazuh-wui"),
		APIPassword:        password,
		VerifyCertificates: false,
	}
}

func (c *Config) Summary() string {
	return fmt.Sprintf(`Current configuration:
  FQDN:         %s
  API_User:     %s
  API_Password: ********
`, c.FQDN, c.APIUser)
}
