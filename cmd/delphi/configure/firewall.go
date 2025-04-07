// cmd/delphi/configure/firewall.go
package configure

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ConfigureFirewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Auto-configure firewall rules for Wazuh on Linux",
	Long:  "Detects Debian or RHEL and configures UFW or Firewalld for Wazuh agent ports.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
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
		return nil
	}),
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
	log.Info("🚦 Checking Firewalld state")
	execute.Execute("sudo", "firewall-cmd", "--state")

	for _, port := range wazuhPorts {
		log.Info("📦 Allowing port", zap.String("port", port))
		execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-port="+port)
	}

	log.Info("🔒 Allowing https service")
	execute.Execute("sudo", "firewall-cmd", "--permanent", "--add-service=https")

	log.Info("🔁 Reloading Firewalld")
	execute.Execute("sudo", "firewall-cmd", "--reload")

	log.Info("📖 Listing open ports")
	execute.Execute("sudo", "firewall-cmd", "--list-ports")

	log.Info("✅ Firewalld configuration complete.")
}
