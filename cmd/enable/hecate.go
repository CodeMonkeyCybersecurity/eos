// pkg/enable/hecate.go

package enable

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type AppConfig struct {
	AppName   string
	Domain    string
	Subdomain string
	BackendIP string
}

func GenerateCaddyConfig(cfg AppConfig) string {
	fullDomain := cfg.Subdomain + "." + cfg.Domain
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("%s {\n", fullDomain))
	builder.WriteString(fmt.Sprintf("    reverse_proxy %s\n", cfg.BackendIP))

	switch strings.ToLower(cfg.AppName) {
	case "nextcloud":
		builder.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
		builder.WriteString("    encode zstd gzip\n")
	case "wazuh":
		builder.WriteString("    encode gzip\n")
	case "mailcow":
		builder.WriteString("    tls internal\n")
	default:
		builder.WriteString("    # No special features for this app\n")
	}

	builder.WriteString("}\n\n")
	return builder.String()
}

func PromptInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func WriteCaddyfile(content string) error {
	file, err := os.Create("Caddyfile")
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// NewCreateCaddyfileCmd creates the `create caddyfile` subcommand
func NewCreateCaddyfileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caddyfile",
		Short: "Generate a Caddyfile configuration",
		Long: `The caddyfile command generates a Caddyfile for use with the Hecate reverse proxy,
allowing you to set up domain-to-backend mappings and app-specific configurations.`,
		RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
			zap.L().Info("Caddyfile generation started")

			var allConfigs strings.Builder

			for {
				app := PromptInput("Enter app name (nextcloud, wazuh, mailcow, generic): ")
				domain := PromptInput("Enter domain (example.com): ")
				subdomain := PromptInput("Enter subdomain (e.g., app, www, dashboard): ")
				backendIP := PromptInput("Enter backend IP (e.g., 192.168.1.10): ")

				config := AppConfig{
					AppName:   app,
					Domain:    domain,
					Subdomain: subdomain,
					BackendIP: backendIP,
				}

				caddyBlock := GenerateCaddyConfig(config)
				allConfigs.WriteString(caddyBlock)

				addMore := PromptInput("Add another domain? (yes/no): ")
				if strings.ToLower(addMore) != "yes" {
					break
				}
			}

			if err := WriteCaddyfile(allConfigs.String()); err != nil {
				zap.L().Error("Failed to write Caddyfile", zap.Error(err))
				return err
			}

			zap.L().Info("✅ Caddyfile generated successfully")
			fmt.Println("---")
			fmt.Println(allConfigs.String())

			return nil
		}),
	}
}