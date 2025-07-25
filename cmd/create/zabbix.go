package create

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	zabbixWebPort    string
	zabbixWebSSLPort string
	zabbixServerPort string
	zabbixAgentPort  string
	postgresPassword string
	timeZone         string
)

var CreateZabbixCmd = &cobra.Command{
	Use:   "zabbix",
	Short: "Deploy comprehensive Zabbix monitoring stack using Docker Compose",
	Long: `Deploy a complete Zabbix monitoring stack with PostgreSQL backend.

This command creates a full Zabbix deployment including:
- PostgreSQL database server
- Zabbix server (core monitoring)
- Zabbix web frontend (Nginx-based)
- Zabbix agent (for self-monitoring)
- Java Gateway (for JMX monitoring)
- SNMP Traps receiver

The deployment uses Docker Compose and creates a complete monitoring environment
accessible via web interface on port 8080.

Examples:
  # Basic deployment with defaults
  eos create zabbix

  # Custom web port and database password
  eos create zabbix --web-port 9080 --postgres-password mySecurePassword123

  # Custom ports and explicit timezone (auto-detection is default)
  eos create zabbix --web-port 9080 --server-port 10051 --timezone "America/New_York"

  # Force UTC timezone instead of auto-detection
  eos create zabbix --timezone "UTC"`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting comprehensive Zabbix monitoring stack deployment",
			zap.String("user", os.Getenv("USER")),
			zap.String("command_line", strings.Join(os.Args, " ")),
			zap.String("web_port", zabbixWebPort),
			zap.String("server_port", zabbixServerPort))

		if err := container.DeployZabbix(rc); err != nil {
			logger.Error(" Zabbix deployment failed", zap.Error(err))
			return fmt.Errorf("zabbix deployment failed: %w", err)
		}

		logger.Info(" Zabbix monitoring stack deployed successfully")
		logger.Info(" ")
		logger.Info(" ZABBIX ACCESS INFORMATION:")
		logger.Info(fmt.Sprintf("   • Web Interface: http://localhost:%s", zabbixWebPort))
		logger.Info(fmt.Sprintf("   • HTTPS Interface: https://localhost:%s", zabbixWebSSLPort))
		logger.Info("   • Default Login: Admin / zabbix")
		logger.Info("   • Database: PostgreSQL (user: zabbix)")
		logger.Info(" ")
		logger.Info(" NEXT STEPS:")
		logger.Info("   1. Access the web interface and change default password")
		logger.Info("   2. Configure additional monitoring targets")
		logger.Info("   3. Set up alerting and notifications")

		return nil
	}),
}

func init() {
	CreateZabbixCmd.Flags().StringVar(&zabbixWebPort, "web-port", "8080", "Zabbix web interface port")
	CreateZabbixCmd.Flags().StringVar(&zabbixWebSSLPort, "web-ssl-port", "8443", "Zabbix web SSL interface port")
	CreateZabbixCmd.Flags().StringVar(&zabbixServerPort, "server-port", "10051", "Zabbix server port")
	CreateZabbixCmd.Flags().StringVar(&zabbixAgentPort, "agent-port", "10050", "Zabbix agent port")
	CreateZabbixCmd.Flags().StringVar(&postgresPassword, "postgres-password", "zabbix_pwd", "PostgreSQL database password")
	CreateZabbixCmd.Flags().StringVar(&timeZone, "timezone", "auto", "Timezone for Zabbix (auto-detects from host, or specify like UTC, America/New_York)")

	CreateCmd.AddCommand(CreateZabbixCmd)
}
