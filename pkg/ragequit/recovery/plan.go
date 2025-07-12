package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GenerateRecoveryPlan creates a recovery plan document
// Migrated from cmd/ragequit/ragequit.go generateRecoveryPlan
func GenerateRecoveryPlan(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare recovery plan generation
	logger.Info("Assessing recovery plan requirements")

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "RAGEQUIT-RECOVERY-PLAN.md")

	var plan strings.Builder

	// INTERVENE - Generate recovery plan
	logger.Debug("Generating recovery plan document")

	plan.WriteString("# RAGEQUIT RECOVERY PLAN\n\n")
	plan.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	plan.WriteString(fmt.Sprintf("Hostname: %s\n", system.GetHostname()))
	plan.WriteString(fmt.Sprintf("User: %s\n\n", os.Getenv("USER")))

	plan.WriteString("## IMMEDIATE ACTIONS AFTER REBOOT\n\n")
	plan.WriteString("1. **Verify System Boot**\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   systemctl status\n")
	plan.WriteString("   journalctl -b -p err\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("2. **Check Critical Services**\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   systemctl status sshd\n")
	plan.WriteString("   systemctl status networking\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("3. **Review Ragequit Diagnostics**\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   cd ~\n")
	plan.WriteString("   ls -la ragequit-*.txt\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("## SERVICE RECOVERY\n\n")

	// Check for specific services and add recovery steps
	if system.CommandExists("docker") {
		plan.WriteString("### Docker Recovery\n")
		plan.WriteString("```bash\n")
		plan.WriteString("# Check Docker status\n")
		plan.WriteString("systemctl status docker\n")
		plan.WriteString("docker ps -a\n\n")
		plan.WriteString("# Restart stopped containers\n")
		plan.WriteString("docker ps -a | grep Exited | awk '{print $1}' | xargs -r docker start\n")
		plan.WriteString("```\n\n")
	}

	if system.CommandExists("kubectl") {
		plan.WriteString("### Kubernetes Recovery\n")
		plan.WriteString("```bash\n")
		plan.WriteString("# Check cluster status\n")
		plan.WriteString("kubectl get nodes\n")
		plan.WriteString("kubectl get pods --all-namespaces | grep -v Running\n")
		plan.WriteString("```\n\n")
	}

	if shared.FileExists("/etc/postgresql") || system.CommandExists("psql") {
		plan.WriteString("### PostgreSQL Recovery\n")
		plan.WriteString("```bash\n")
		plan.WriteString("# Check PostgreSQL status\n")
		plan.WriteString("systemctl status postgresql\n")
		plan.WriteString("pg_isready\n\n")
		plan.WriteString("# If needed, start PostgreSQL\n")
		plan.WriteString("sudo systemctl start postgresql\n")
		plan.WriteString("```\n\n")
	}

	if shared.FileExists("/etc/mysql") || system.CommandExists("mysql") {
		plan.WriteString("### MySQL Recovery\n")
		plan.WriteString("```bash\n")
		plan.WriteString("# Check MySQL status\n")
		plan.WriteString("systemctl status mysql\n")
		plan.WriteString("mysqladmin ping\n\n")
		plan.WriteString("# If needed, start MySQL\n")
		plan.WriteString("sudo systemctl start mysql\n")
		plan.WriteString("```\n\n")
	}

	plan.WriteString("## DIAGNOSTIC FILE LOCATIONS\n\n")
	plan.WriteString("The following diagnostic files were created:\n\n")
	plan.WriteString("- `~/ragequit-timestamp.txt` - Execution timestamp and reason\n")
	plan.WriteString("- `~/ragequit-environment.txt` - System environment detection\n")
	plan.WriteString("- `~/ragequit-resources.txt` - Resource usage snapshot\n")
	plan.WriteString("- `~/ragequit-queues.txt` - Message queue status\n")
	plan.WriteString("- `~/ragequit-databases.txt` - Database status\n")
	plan.WriteString("- `~/ragequit-security.txt` - Security snapshot\n")
	plan.WriteString("- `~/ragequit-containers.txt` - Container diagnostics\n")
	plan.WriteString("- `~/ragequit-performance.txt` - Performance metrics\n")
	plan.WriteString("- `~/ragequit-systemctl.txt` - Systemd service status\n")
	plan.WriteString("- `~/ragequit-network.txt` - Network diagnostics\n\n")

	plan.WriteString("## TROUBLESHOOTING STEPS\n\n")
	plan.WriteString("1. **If system won't boot:**\n")
	plan.WriteString("   - Boot into recovery mode\n")
	plan.WriteString("   - Check `/var/log/syslog` or `/var/log/messages`\n")
	plan.WriteString("   - Run `fsck` on filesystems if needed\n\n")

	plan.WriteString("2. **If network is down:**\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   ip link show\n")
	plan.WriteString("   systemctl restart networking\n")
	plan.WriteString("   ip addr show\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("3. **If services won't start:**\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   journalctl -u <service-name> -n 50\n")
	plan.WriteString("   systemctl reset-failed\n")
	plan.WriteString("   systemctl start <service-name>\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("## ROLLBACK PROCEDURES\n\n")
	plan.WriteString("If the ragequit was triggered by a recent change:\n\n")
	plan.WriteString("1. Check recent package installations:\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   grep -E \"(install|upgrade)\" /var/log/dpkg.log | tail -20\n")
	plan.WriteString("   ```\n\n")
	plan.WriteString("2. Check recent configuration changes:\n")
	plan.WriteString("   ```bash\n")
	plan.WriteString("   find /etc -type f -mtime -1 -ls\n")
	plan.WriteString("   ```\n\n")

	plan.WriteString("## CONTACT INFORMATION\n\n")
	plan.WriteString("If unable to recover:\n")
	plan.WriteString("- Check system documentation\n")
	plan.WriteString("- Contact system administrator\n")
	plan.WriteString("- Review application logs in `/var/log/`\n\n")

	plan.WriteString("---\n")
	plan.WriteString("*This recovery plan was automatically generated by eos ragequit*\n")

	// EVALUATE - Write recovery plan
	if err := os.WriteFile(outputFile, []byte(plan.String()), 0644); err != nil {
		return fmt.Errorf("failed to write recovery plan: %w", err)
	}

	logger.Info("Recovery plan generated successfully",
		zap.String("output_file", outputFile))

	return nil
}
