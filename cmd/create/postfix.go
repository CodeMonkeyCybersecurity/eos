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

		osType := platform.DetectLinuxDistro(log)
		log.Info("Detected OS", zap.String("type", osType))

		// Package install
		switch osType {
		case "debian":
			if err := execute.ExecuteShell(`DEBIAN_FRONTEND=noninteractive apt update && apt install -y postfix bsd-mailx libsasl2-modules`); err != nil {
				log.Error("Error installing packages on Debian", zap.Error(err))
				return err
			}
			if err := execute.ExecuteShell(`cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf`); err != nil {
				log.Error("Error copying main.cf.debian to /etc/postfix/main.cf", zap.Error(err))
				return err
			}
		case "rhel":
			if err := execute.ExecuteShell(`yum update -y && yum install -y postfix mailx cyrus-sasl cyrus-sasl-plain`); err != nil {
				log.Error("Error installing packages on RHEL", zap.Error(err))
				return err
			}
		default:
			log.Warn("Unknown OS, skipping package installation")
		}

		// Start/restart service
		switch osType {
		case "debian":
			if err := execute.Execute("postfix", "start"); err != nil {
				log.Error("Error starting postfix", zap.Error(err))
				return err
			}
			if err := execute.Execute("postfix", "status"); err != nil {
				log.Error("Error checking postfix status", zap.Error(err))
				return err
			}
		case "rhel":
			if err := execute.ExecuteShell("service postfix restart"); err != nil {
				log.Error("Error restarting postfix service on RHEL", zap.Error(err))
				return err
			}
		}

		// Prompt user input
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter your SMTP host (default: smtp.gmail.com): ")
		smtpHost, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Error reading SMTP host", zap.Error(err))
			return err
		}
		smtpHost = strings.TrimSpace(smtpHost)
		if smtpHost == "" {
			smtpHost = "smtp.gmail.com"
		}

		fmt.Print("Enter your email address: ")
		email, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Error reading email address", zap.Error(err))
			return err
		}
		email = strings.TrimSpace(email)

		password, err := interaction.PromptPassword("Enter your app password: ", log)
		if err != nil {
			fmt.Fprintln(os.Stderr, "❌ Failed to read password:", err)
			os.Exit(1)
		}

		// Backup config files
		if err := utils.BackupFile("/etc/postfix/main.cf"); err != nil {
			log.Error("Error backing up /etc/postfix/main.cf", zap.Error(err))
			return err
		}
		if err := utils.BackupFile("/etc/postfix/sasl_passwd"); err != nil {
			log.Error("Error backing up /etc/postfix/sasl_passwd", zap.Error(err))
			return err
		}

		// Append configuration to main.cf
		if err := appendPostfixConfig(smtpHost, osType); err != nil {
			log.Error("Error appending Postfix configuration", zap.Error(err))
			return err
		}

		// Write sasl_passwd
		cred := fmt.Sprintf("[%s]:587 %s:%s\n", smtpHost, email, password)
		if err := os.WriteFile("/etc/postfix/sasl_passwd", []byte(cred), 0600); err != nil {
			log.Error("Error writing /etc/postfix/sasl_passwd", zap.Error(err))
			return err
		}

		// postmap and set permissions
		if err := execute.Execute("postmap", "/etc/postfix/sasl_passwd"); err != nil {
			log.Error("Error running postmap", zap.Error(err))
			return err
		}
		if err := execute.Execute("chown", "root:root", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db"); err != nil {
			log.Error("Error setting ownership on sasl_passwd files", zap.Error(err))
			return err
		}
		if err := execute.Execute("chmod", "0600", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db"); err != nil {
			log.Error("Error setting permissions on sasl_passwd files", zap.Error(err))
			return err
		}

		// Restart postfix
		switch osType {
		case "debian":
			if err := execute.Execute("systemctl", "restart", "postfix"); err != nil {
				// Fallback to reload if restart fails
				if err := execute.Execute("postfix", "reload"); err != nil {
					log.Error("Error reloading postfix", zap.Error(err))
					return err
				}
			}
		case "rhel":
			if err := execute.ExecuteShell("service postfix restart"); err != nil {
				log.Error("Error restarting postfix service on RHEL", zap.Error(err))
				return err
			}
		}

		// Configure TLS fingerprint for RHEL
		if osType == "rhel" {
			if err := execute.Execute("postconf", "-e", "smtp_tls_fingerprint_digest=sha256"); err != nil {
				log.Error("Error setting smtp_tls_fingerprint_digest", zap.Error(err))
				return err
			}
			if err := execute.Execute("postconf", "-e", "smtpd_tls_fingerprint_digest=sha256"); err != nil {
				log.Error("Error setting smtpd_tls_fingerprint_digest", zap.Error(err))
				return err
			}
		}

		// Send test mail
		fmt.Print("Enter test recipient email: ")
		receiver, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Error reading test recipient email", zap.Error(err))
			return err
		}
		receiver = strings.TrimSpace(receiver)
		cmdStr := fmt.Sprintf(`echo "Test mail from postfix" | mail -s "Test Postfix" -r "%s" %s`, email, receiver)
		if err := execute.ExecuteShell(cmdStr); err != nil {
			log.Error("Error sending test mail", zap.Error(err))
			return err
		}

		// Final check
		if err := execute.Execute("postfix", "check"); err != nil {
			log.Error("Error checking postfix", zap.Error(err))
			return err
		}

		// Show final files
		if err := utils.CatFile("/etc/postfix/main.cf"); err != nil {
			log.Error("Error displaying /etc/postfix/main.cf", zap.Error(err))
			return err
		}
		if err := utils.CatFile("/etc/postfix/sasl_passwd"); err != nil {
			log.Error("Error displaying /etc/postfix/sasl_passwd", zap.Error(err))
			return err
		}

		log.Info("✅ Postfix SMTP relay setup complete.")
		return nil
	}),
}

func appendPostfixConfig(smtpHost, osType string) error {
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

	f, err := os.OpenFile("/etc/postfix/main.cf", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open /etc/postfix/main.cf: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(config); err != nil {
		return fmt.Errorf("failed to write config to /etc/postfix/main.cf: %w", err)
	}
	return nil
}

func init() {
	CreateCmd.AddCommand(CreatePostfixCmd)
}
