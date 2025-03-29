// cmd/delphi/configure/firewall.go
package configure

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ConfigureFirewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Auto-configure firewall rules for Wazuh on Linux",
	Long:  "Detects Debian or RHEL and configures UFW or Firewalld for Wazuh agent ports.",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		switch platform.DetectLinuxDistro() {
		case "debian":
			log.Info("🔧 Configuring UFW on Debian-based system...")
			configureUFW(log)
		case "rhel":
			log.Info("🔧 Configuring Firewalld on RHEL-based system...")
			configureFirewalld(log)
		default:
			log.Warn("Unsupported or unknown Linux distro.")
			fmt.Println("⚠️  Unsupported Linux distribution for automated firewall setup.")
			os.Exit(1)
		}
	},
}

var wazuhPorts = []string{"55000/tcp", "1516/tcp", "1515/tcp", "1514/tcp", "443/tcp"}

func configureUFW(log *zap.Logger) {
	execute.Execute("sudo", "ufw", "enable")
	for _, port := range wazuhPorts {
		execute.Execute("sudo", "ufw", "allow", port)
	}
	execute.Execute("sudo", "ufw", "reload")
	execute.Execute("sudo", "ufw", "status")
	log.Info("✅ UFW configuration complete.")
}

func configureFirewalld(log *zap.Logger) {
	execute.Execute("sudo", "firewall-cmd", "--state")
	for _, port := range wazuhPorts {
		execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-port="+port)
	}
	execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-service=https")
	execute.Execute("sudo", "firewall-cmd", "--reload")
	execute.Execute("sudo", "firewall-cmd", "--list-ports")
	log.Info("✅ Firewalld configuration complete.")
}
