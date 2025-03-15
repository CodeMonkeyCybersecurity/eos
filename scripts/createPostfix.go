package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// detectOS attempts to read /etc/os-release and parse the ID or ID_LIKE field.
func detectOS() string {
	data, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}

	content := string(data)
	osType := "unknown"

	// Check ID and ID_LIKE fields for debian or rhel indicators.
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "ID=") {
			value := strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			if value == "debian" || value == "ubuntu" {
				osType = "debian"
			} else if value == "centos" || value == "rhel" {
				osType = "rhel"
			}
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			value := strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			if strings.Contains(value, "debian") {
				osType = "debian"
			} else if strings.Contains(value, "rhel") || strings.Contains(value, "fedora") {
				osType = "rhel"
			}
		}
	}
	return osType
}

// runShellCommandWithTimeout runs a shell command with a given timeout.
func runShellCommandWithTimeout(cmdStr string, timeout time.Duration) error {
	fmt.Printf("Executing: %s\n", cmdStr)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	output := out.String()
	fmt.Println(output)
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Printf("Command timed out: %s\n", cmdStr)
	}
	return err
}

// runCommand runs a command with arguments (without shell) and returns its combined output.
func runCommand(name string, args ...string) error {
	fmt.Printf("Executing: %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	fmt.Println(out.String())
	return err
}

func main() {
	// Detect OS type.
	osType := detectOS()
	fmt.Printf("Detected OS: %s\n", osType)
	if osType == "unknown" {
		log.Println("OS detection failed; proceeding with generic commands (manual review recommended).")
	}

	// 1. Install required packages.
	if osType == "debian" {
		fmt.Println("Updating package lists and installing required packages on Debian-based system...")
		// Adjusted package names for Debian/Ubuntu.
		debianInstallCmd := "apt update && apt install -y postfix bsd-mailx libsasl2-modules"
		if err := runShellCommandWithTimeout(debianInstallCmd, 2*time.Minute); err != nil {
			log.Fatalf("Package installation failed: %v", err)
		}
		// 2. Create the main Postfix configuration file.
		fmt.Println("Copying main.cf configuration file for Debian-based system...")
		if err := runShellCommandWithTimeout("cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf", 30*time.Second); err != nil {
			log.Fatalf("Failed to copy main.cf: %v", err)
		}
	} else if osType == "rhel" {
		fmt.Println("Updating packages and installing required packages on RHEL-based system...")
		if err := runShellCommandWithTimeout("yum update -y && yum install -y postfix mailx cyrus-sasl cyrus-sasl-plain", 2*time.Minute); err != nil {
			log.Fatalf("Package installation failed: %v", err)
		}
	} else {
		fmt.Println("OS not detected as Debian or RHEL. Proceeding without installation steps.")
	}

	// 3. Start Postfix service.
	fmt.Println("Starting Postfix service...")
	if osType == "debian" {
		if err := runCommand("postfix", "start"); err != nil {
			log.Printf("Warning: unable to start postfix: %v", err)
		}
		if err := runCommand("postfix", "status"); err != nil {
			log.Printf("Warning: unable to check postfix status: %v", err)
		}
	} else if osType == "rhel" {
		if err := runShellCommandWithTimeout("service postfix restart", 30*time.Second); err != nil {
			log.Printf("Warning: unable to restart postfix: %v", err)
		}
	}

	// 4. Collect SMTP settings from the user.
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your smtp/mail hostname (e.g., mail.hostname.com): ")
	smtpHost, _ := reader.ReadString('\n')
	smtpHost = strings.TrimSpace(smtpHost)

	fmt.Print("Enter your email you are sending from (e.g., sender@domain.com): ")
	configuredEmail, _ := reader.ReadString('\n')
	configuredEmail = strings.TrimSpace(configuredEmail)

	fmt.Print("Enter your app password: ")
	smtpAppPass, _ := reader.ReadString('\n')
	smtpAppPass = strings.TrimSpace(smtpAppPass)

	// 5. Append configuration to /etc/postfix/main.cf using user input.
	fmt.Println("Appending SMTP relay configuration to /etc/postfix/main.cf...")
	var postfixConfig string
	if osType == "debian" {
		postfixConfig = fmt.Sprintf(`
# SMTP relay configuration for Debian-based system
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
`, smtpHost)
	} else if osType == "rhel" {
		postfixConfig = fmt.Sprintf(`
# SMTP relay configuration for RHEL-based system
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
smtp_use_tls = yes
`, smtpHost)
	} else {
		postfixConfig = fmt.Sprintf(`
# Generic SMTP relay configuration (please verify settings)
relayhost = [%s]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
`, smtpHost)
	}

	// Open file for appending.
	f, err := os.OpenFile("/etc/postfix/main.cf", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening /etc/postfix/main.cf for writing: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(postfixConfig); err != nil {
		log.Fatalf("Error writing to /etc/postfix/main.cf: %v", err)
	}
	fmt.Println("Configuration appended to /etc/postfix/main.cf.")

	// 6. Set up the SASL password file using the same user inputs.
	credential := fmt.Sprintf("[%s]:587 %s:%s\n", smtpHost, configuredEmail, smtpAppPass)
	saslPath := "/etc/postfix/sasl_passwd"
	err = os.WriteFile(saslPath, []byte(credential), 0600)
	if err != nil {
		log.Fatalf("Failed to write %s: %v", saslPath, err)
	}
	fmt.Printf("Credentials written to %s.\n", saslPath)

	// 7. Run postmap to create the hash database.
	if err := runCommand("postmap", saslPath); err != nil {
		log.Fatalf("Failed to run postmap: %v", err)
	}
	fmt.Println("postmap executed successfully.")

	// 8. Secure the credential files.
	fmt.Println("Securing credential files...")
	if err := runCommand("chown", "root:root", saslPath, saslPath+".db"); err != nil {
		log.Printf("Warning: failed to change ownership: %v", err)
	}
	if err := runCommand("chmod", "0600", saslPath, saslPath+".db"); err != nil {
		log.Printf("Warning: failed to change permissions: %v", err)
	}
	fmt.Println("Credential files secured.")

	// 9. Restart Postfix to apply configuration changes.
	fmt.Println("Restarting Postfix service to apply configuration changes...")
	if osType == "debian" {
		if err := runCommand("systemctl", "restart", "postfix"); err != nil {
			fmt.Println("Falling back to postfix reload...")
			if err := runCommand("postfix", "reload"); err != nil {
				log.Printf("Warning: unable to restart postfix: %v", err)
			}
		}
	} else if osType == "rhel" {
		if err := runShellCommandWithTimeout("service postfix restart", 30*time.Second); err != nil {
			log.Printf("Warning: unable to restart postfix: %v", err)
		}
	}

	// 10. For RHEL-based systems, adjust the TLS fingerprint digest if needed.
	if osType == "rhel" {
		fmt.Println("Configuring TLS fingerprint digest to use SHA-256 on RHEL-based system...")
		if err := runCommand("postconf", "-e", "smtp_tls_fingerprint_digest=sha256"); err != nil {
			log.Printf("Warning: failed to set smtp_tls_fingerprint_digest: %v", err)
		}
		if err := runCommand("postconf", "-e", "smtpd_tls_fingerprint_digest=sha256"); err != nil {
			log.Printf("Warning: failed to set smtpd_tls_fingerprint_digest: %v", err)
		}
	}

	// 11. Verify configuration: send a test email.
	fmt.Println("Verifying configuration by sending a test email...")
	// Reuse the sender email for test if desired, but allow a separate recipient.
	fmt.Printf("Using sender email: %s\n", configuredEmail)
	fmt.Print("Enter the recipient email address (e.g., receiver@domain.com): ")
	testReceiver, _ := reader.ReadString('\n')
	testReceiver = strings.TrimSpace(testReceiver)

	testCmd := fmt.Sprintf(`echo "Test mail from postfix" | mail -s "Test Postfix" -r "%s" %s`, configuredEmail, testReceiver)
	if err := runShellCommandWithTimeout(testCmd, 30*time.Second); err != nil {
		log.Printf("Warning: test email may not have been sent correctly: %v", err)
	} else {
		fmt.Println("Test email sent. Please verify receipt.")
	}

	// 12. Check Postfix configuration.
	fmt.Println("Performing final Postfix configuration check...")
	if err := runCommand("postfix", "check"); err != nil {
		log.Printf("Postfix configuration check encountered issues: %v", err)
	} else {
		fmt.Println("Postfix configuration appears to be correct.")
	}

	fmt.Println("Script completed. Please review any output messages for further actions if needed.")
}
