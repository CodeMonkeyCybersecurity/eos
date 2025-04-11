// cmd/create/postfix.go

package create

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"go.uber.org/zap"

	"github.com/spf13/cobra"
)

var CreatePostfixCmd = &cobra.Command{
	Use:   "postfix",
	Short: "Install and configure Postfix as an SMTP relay",
	Long:  "Installs Postfix, configures it with a relayhost and credentials, and sends a test email.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		utils.RequireRoot(log)

		osType := platform.DetectLinuxDistro()
		log.Info("Detected OS", zap.String("type", osType))

		// Package install
		switch osType {
		case "debian":
			execute.ExecuteShell(`DEBIAN_FRONTEND=noninteractive apt update && apt install -y postfix bsd-mailx libsasl2-modules`)
			execute.ExecuteShell(`cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf`)
		case "rhel":
			execute.ExecuteShell(`yum update -y && yum install -y postfix mailx cyrus-sasl cyrus-sasl-plain`)
		default:
			log.Warn("Unknown OS, skipping package installation")
		}

		// Start/restart service
		switch osType {
		case "debian":
			execute.Execute("postfix", "start")
			execute.Execute("postfix", "status")
		case "rhel":
			execute.ExecuteShell("service postfix restart")
		}

		// Prompt user input
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter your SMTP host (default: smtp.gmail.com): ")
		smtpHost, _ := reader.ReadString('\n')
		smtpHost = strings.TrimSpace(smtpHost)
		if smtpHost == "" {
			smtpHost = "smtp.gmail.com"
		}

		fmt.Print("Enter your email address: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		password, err := interaction.PromptPassword("Enter your app password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "❌ Failed to read password:", err)
			os.Exit(1)
		}

		// Backup config
		utils.BackupFile("/etc/postfix/main.cf")
		utils.BackupFile("/etc/postfix/sasl_passwd")

		// Append to main.cf
		appendPostfixConfig(smtpHost, osType)

		// Write sasl_passwd
		cred := fmt.Sprintf("[%s]:587 %s:%s\n", smtpHost, email, password)
		os.WriteFile("/etc/postfix/sasl_passwd", []byte(cred), 0600)

		// postmap + permissions
		execute.Execute("postmap", "/etc/postfix/sasl_passwd")
		execute.Execute("chown", "root:root", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db")
		execute.Execute("chmod", "0600", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db")

		// Restart postfix
		switch osType {
		case "debian":
			if err := execute.Execute("systemctl", "restart", "postfix"); err != nil {
				execute.Execute("postfix", "reload")
			}
		case "rhel":
			execute.ExecuteShell("service postfix restart")
		}

		// TLS fingerprint for RHEL
		if osType == "rhel" {
			execute.Execute("postconf", "-e", "smtp_tls_fingerprint_digest=sha256")
			execute.Execute("postconf", "-e", "smtpd_tls_fingerprint_digest=sha256")
		}

		// Send test mail
		fmt.Print("Enter test recipient email: ")
		receiver, _ := reader.ReadString('\n')
		receiver = strings.TrimSpace(receiver)
		cmdStr := fmt.Sprintf(`echo "Test mail from postfix" | mail -s "Test Postfix" -r "%s" %s`, email, receiver)
		execute.ExecuteShell(cmdStr)

		// Final check
		execute.Execute("postfix", "check")

		// Show final files
		utils.CatFile("/etc/postfix/main.cf")
		utils.CatFile("/etc/postfix/sasl_passwd")

		log.Info("✅ Postfix SMTP relay setup complete.")
		return nil
	}),
}

func appendPostfixConfig(smtpHost, osType string) {
	var config string
	if osType == "debian" {
		config = fmt.Sprintf(`
# Postfix relay (Debian)
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
`, smtpHost)
	} else {
		config = fmt.Sprintf(`
# Postfix relay (generic/RHEL)
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
smtp_use_tls = yes
`, smtpHost)
	}

	f, _ := os.OpenFile("/etc/postfix/main.cf", os.O_APPEND|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(config)
}

func init() {

	CreateCmd.AddCommand(CreatePostfixCmd)
}
