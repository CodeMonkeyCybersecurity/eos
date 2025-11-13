// cmd/create/postfix.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreatePostfixCmd = &cobra.Command{
	Use:   "postfix",
	Short: "Install and configure Postfix as an SMTP relay",
	Long:  "Installs Postfix, configures it with a relayhost and credentials, and sends a test email.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		eos_unix.RequireRoot(rc.Ctx)

		osType := platform.DetectLinuxDistro(rc)
		otelzap.Ctx(rc.Ctx).Info("Detected OS", zap.String("type", osType))

		if err := installPostfix(rc, osType); err != nil {
			return err
		}
		if err := restartPostfix(rc, osType); err != nil {
			return err
		}

		smtpHost := interaction.PromptInput(rc.Ctx, "Enter your SMTP host", "smtp.gmail.com")
		email := interaction.PromptValidated("Enter your email address", interaction.ValidateEmail)
		password, err := interaction.PromptSecret(rc.Ctx, "Enter your app password")
		if err != nil {
			return err
		}

		if err := configurePostfixRelay(rc, smtpHost, email, password, osType); err != nil {
			return err
		}

		receiver := interaction.PromptValidated("Enter test recipient email", interaction.ValidateEmail)
		if err := sendTestMail(email, receiver); err != nil {
			return fmt.Errorf("test mail failed: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info(" Postfix SMTP relay setup complete.")
		return nil
	}),
}

// TODO
func installPostfix(rc *eos_io.RuntimeContext, osType string) error {
	switch osType {
	case "debian":
		// Set environment variable for non-interactive install
		_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
		defer func() { _ = os.Unsetenv("DEBIAN_FRONTEND") }()

		// Update package lists
		err := execute.RunSimple(rc.Ctx, "apt", "update")
		if err != nil {
			return fmt.Errorf("apt update failed: %w", err)
		}
		// Install packages
		err = execute.RunSimple(rc.Ctx, "apt", "install", "-y", "postfix", "bsd-mailx", "libsasl2-modules")
		if err != nil {
			return fmt.Errorf("debian install failed: %w", err)
		}
		return execute.RunSimple(rc.Ctx, "cp", "/usr/share/postfix/main.cf.debian", "/etc/postfix/main.cf")
	case "rhel":
		// Update package lists
		err := execute.RunSimple(rc.Ctx, "yum", "update", "-y")
		if err != nil {
			return fmt.Errorf("yum update failed: %w", err)
		}
		// Install packages
		return execute.RunSimple(rc.Ctx, "yum", "install", "-y", "postfix", "mailx", "cyrus-sasl", "cyrus-sasl-plain")
	default:
		otelzap.Ctx(rc.Ctx).Warn("Unknown OS type; skipping install")
		return nil
	}
}

// TODO
func formatSaslCredentials(host, user, pass string) string {
	return fmt.Sprintf("[%s]:587 %s:%s\n", host, user, pass)
}

// TODO
func generatePostfixConfig(host, osType string) string {
	if osType == "debian" {
		return fmt.Sprintf(`# Postfix relay (Debian)
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
`, host)
	}
	return fmt.Sprintf(`# Postfix relay (RHEL)
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
smtp_use_tls = yes
`, host)
}

// TODO
func configurePostfixRelay(rc *eos_io.RuntimeContext, smtpHost, email, password, osType string) error {
	for _, path := range []string{"/etc/postfix/main.cf", "/etc/postfix/sasl_passwd"} {
		if err := utils.BackupFile(rc.Ctx, path); err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}
	}

	if err := appendPostfixConfig(smtpHost, osType); err != nil {
		return err
	}

	cred := formatSaslCredentials(smtpHost, email, password)
	if err := os.WriteFile("/etc/postfix/sasl_passwd", []byte(cred), shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to write sasl_passwd: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "postmap", "/etc/postfix/sasl_passwd"); err != nil {
		return err
	}
	if err := execute.RunSimple(rc.Ctx, "chown", "root:root", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db"); err != nil {
		return err
	}
	if err := execute.RunSimple(rc.Ctx, "chmod", "0600", "/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db"); err != nil {
		return err
	}

	if err := restartPostfix(rc, osType); err != nil {
		return err
	}

	if osType == "rhel" {
		if err := execute.RunSimple(rc.Ctx, "postconf", "-e", "smtp_tls_fingerprint_digest=sha256"); err != nil {
			return err
		}
		if err := execute.RunSimple(rc.Ctx, "postconf", "-e", "smtpd_tls_fingerprint_digest=sha256"); err != nil {
			return err
		}
	}

	return nil
}

// TODO
func appendPostfixConfig(smtpHost, osType string) error {
	return os.WriteFile(
		"/etc/postfix/main.cf",
		[]byte(generatePostfixConfig(smtpHost, osType)),
		0644,
	)
}

// TODO
func sendTestMail(from, to string) error {
	cmd := exec.Command("mail", "-s", "Test Postfix", "-r", from, to)
	cmd.Stdin = strings.NewReader("Test mail from postfix")
	return cmd.Run()
}

// TODO
func restartPostfix(rc *eos_io.RuntimeContext, osType string) error {
	switch osType {
	case "debian":
		if err := execute.RunSimple(rc.Ctx, "systemctl", "restart", "postfix"); err != nil {
			return execute.RunSimple(rc.Ctx, "postfix", "reload")
		}
	case "rhel":
		return execute.RunSimple(rc.Ctx, "service", "postfix", "restart")
	default:
		return fmt.Errorf("unsupported OS type: %s", osType)
	}
	return nil
}

func init() {
	CreateCmd.AddCommand(CreatePostfixCmd)
}
