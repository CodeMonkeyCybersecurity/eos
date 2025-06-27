package ubuntu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Fail2banConfig holds the configuration for fail2ban setup
type Fail2banConfig struct {
	BanDuration    time.Duration
	FindDuration   time.Duration
	MaxRetry       int
	EnableEmail    bool
	EmailAddr      string
	IgnoreIPs      []string
	EnableServices []string
}

// DefaultFail2banConfig returns the default configuration for fail2ban
func DefaultFail2banConfig() *Fail2banConfig {
	return &Fail2banConfig{
		BanDuration:    1 * time.Hour,
		FindDuration:   10 * time.Minute,
		MaxRetry:       5,
		EnableEmail:    false,
		EmailAddr:      "",
		IgnoreIPs:      []string{},
		EnableServices: []string{}, // Only SSH protection by default
	}
}

// ConfigureFail2banEnhanced installs and configures fail2ban with enhanced settings
func ConfigureFail2banEnhanced(rc *eos_io.RuntimeContext, config *Fail2banConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting enhanced Fail2Ban setup",
		zap.Duration("ban_duration", config.BanDuration),
		zap.Duration("find_duration", config.FindDuration),
		zap.Int("max_retry", config.MaxRetry),
		zap.Bool("enable_email", config.EnableEmail),
		zap.Strings("additional_services", config.EnableServices))

	steps := []struct {
		desc string
		fn   func() error
	}{
		{"Update package lists", func() error {
			logger.Info(" Updating package lists")
			_, err := execute.RunShell(rc.Ctx, "apt-get update")
			return err
		}},
		{"Install fail2ban and dependencies", func() error {
			logger.Info(" Installing fail2ban and dependencies")
			packages := []string{"fail2ban", "iptables", "whois"}
			if config.EnableEmail {
				packages = append(packages, "mailutils")
			}
			args := append([]string{"install", "-y"}, packages...)
			return execute.RunSimple(rc.Ctx, "apt-get", args...)
		}},
		{"Stop fail2ban service", func() error {
			logger.Info(" Stopping fail2ban service for configuration")
			return execute.RunSimple(rc.Ctx, "systemctl", "stop", "fail2ban")
		}},
		{"Backup existing configuration", func() error {
			logger.Info(" Backing up existing configuration")
			backupTime := time.Now().Format("20060102-150405")
			if _, err := os.Stat("/etc/fail2ban/jail.local"); err == nil {
				backupPath := fmt.Sprintf("/etc/fail2ban/jail.local.bak-%s", backupTime)
				return execute.RunSimple(rc.Ctx, "cp", "/etc/fail2ban/jail.local", backupPath)
			}
			return nil
		}},
		{"Create jail configuration", func() error {
			return createEnhancedJailConfig(rc, config)
		}},
		{"Create custom filters", func() error {
			return createCustomFilters(rc)
		}},
		{"Create action configurations", func() error {
			return createActionConfigs(rc)
		}},
		{"Set secure permissions", func() error {
			logger.Info(" Setting secure permissions on configuration files")
			if err := os.Chmod("/etc/fail2ban/jail.local", 0644); err != nil {
				return err
			}
			return nil
		}},
		{"Start fail2ban service", func() error {
			logger.Info(" Starting fail2ban service")
			return execute.RunSimple(rc.Ctx, "systemctl", "start", "fail2ban")
		}},
		{"Enable fail2ban service", func() error {
			logger.Info(" Enabling fail2ban service at boot")
			return execute.RunSimple(rc.Ctx, "systemctl", "enable", "fail2ban")
		}},
		{"Verify fail2ban status", func() error {
			return verifyFail2banStatus(rc)
		}},
		{"Create management script", func() error {
			return createManagementScript(rc)
		}},
	}

	startTime := time.Now()
	for i, step := range steps {
		logger.Info(" Executing step",
			zap.Int("step_number", i+1),
			zap.Int("total_steps", len(steps)),
			zap.String("description", step.desc))
		
		stepStart := time.Now()
		if err := step.fn(); err != nil {
			logger.Error(" Step failed",
				zap.String("step", step.desc),
				zap.Error(err),
				zap.Duration("step_duration", time.Since(stepStart)))
			return fmt.Errorf("%s: %w", step.desc, err)
		}
		
		logger.Info(" Step completed",
			zap.String("step", step.desc),
			zap.Duration("step_duration", time.Since(stepStart)))
	}

	logger.Info(" Fail2Ban deployment completed successfully",
		zap.Duration("total_duration", time.Since(startTime)),
		zap.String("management_script", "/usr/local/bin/fail2ban-status"),
		zap.String("config_location", "/etc/fail2ban/jail.local"))
	
	return nil
}

func createEnhancedJailConfig(rc *eos_io.RuntimeContext, config *Fail2banConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Creating enhanced jail configuration",
		zap.Duration("ban_duration", config.BanDuration),
		zap.Duration("find_duration", config.FindDuration),
		zap.Int("max_retry", config.MaxRetry))

	// Build ignore IP list
	ignoreIPList := append([]string{"127.0.0.1/8", "::1"}, config.IgnoreIPs...)
	ignoreIPStr := strings.Join(ignoreIPList, " ")

	// Email configuration
	emailConfig := ""
	if config.EnableEmail && config.EmailAddr != "" {
		emailConfig = fmt.Sprintf(`
# Email notifications
destemail = %s
sendername = Fail2Ban
mta = sendmail
action = %%(action_mwl)s`, config.EmailAddr)
	} else {
		emailConfig = `
# Email notifications disabled
# To enable: eos create fail2ban --enable-email --email your@email.com
action = %(action_)s`
	}

	configContent := fmt.Sprintf(`# Enhanced Fail2Ban configuration generated by Eos
# Generated: %s

[DEFAULT]
# Ban duration
bantime = %d

# Time window for failures
findtime = %d

# Number of failures before ban
maxretry = %d

# Ignored IP addresses (whitelist)
ignoreip = %s

# Backend (auto-detect)
backend = auto

# Ban action (iptables-multiport by default)
banaction = iptables-multiport
banaction_allports = iptables-allports

# Protocol
protocol = tcp

# Chain
chain = INPUT
%s

#
# JAILS
#

# SSH Protection
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %%(sshd_log)s
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh  
filter = sshd-ddos
logpath = %%(sshd_log)s
maxretry = 10
bantime = 1w
findtime = 1d

[sshd-aggressive]
enabled = true
port = ssh
filter = sshd
logpath = %%(sshd_log)s
maxretry = 2
bantime = 1d
findtime = 1h
`,
		time.Now().Format("2006-01-02 15:04:05"),
		int(config.BanDuration.Seconds()),
		int(config.FindDuration.Seconds()),
		config.MaxRetry,
		ignoreIPStr,
		emailConfig)

	// Add optional service jails
	serviceJails := getServiceJails(config.EnableServices)
	configContent += serviceJails

	// Add recidive jail for repeat offenders
	configContent += `
# Repeat offender jail
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 3

# Custom jail for port scanning
[portscan]
enabled = true
filter = portscan
logpath = /var/log/syslog
maxretry = 5
bantime = 1d
findtime = 1h
`

	// Write configuration
	tmpFile := fmt.Sprintf("/tmp/jail.local.%d", os.Getpid())
	if err := os.WriteFile(tmpFile, []byte(configContent), 0644); err != nil {
		logger.Error(" Failed to write temporary jail configuration",
			zap.String("path", tmpFile),
			zap.Error(err))
		return fmt.Errorf("write jail config: %w", err)
	}

	logger.Info(" Moving jail configuration to final location",
		zap.String("source", tmpFile),
		zap.String("destination", "/etc/fail2ban/jail.local"))

	return execute.RunSimple(rc.Ctx, "mv", tmpFile, "/etc/fail2ban/jail.local")
}

func getServiceJails(services []string) string {
	var jails strings.Builder

	serviceConfigs := map[string]string{
		"nginx": `
# Nginx Protection
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 3

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
`,
		"apache": `
# Apache Protection
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
bantime = 2d
maxretry = 1

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache*/*error.log
`,
		"docker": `
# Docker Protection
[docker-auth]
enabled = true
port = 2375,2376
filter = docker-auth
logpath = /var/log/docker.log
maxretry = 3
`,
		"postgresql": `
# PostgreSQL Protection
[postgresql]
enabled = true
port = 5432
filter = postgresql
logpath = /var/log/postgresql/*.log
maxretry = 3
`,
		"mysql": `
# MySQL/MariaDB Protection
[mysqld-auth]
enabled = true
port = 3306
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
`,
		"keycloak": `
# Keycloak Protection
[keycloak]
enabled = true
port = 8080,8443
filter = keycloak-auth
logpath = /opt/keycloak/standalone/log/server.log
maxretry = 3
bantime = 1h
`,
		"nextcloud": `
# Nextcloud Protection
[nextcloud]
enabled = true
port = http,https
filter = nextcloud
logpath = /var/www/*/data/nextcloud.log
maxretry = 3
`,
	}

	for _, service := range services {
		if config, ok := serviceConfigs[strings.ToLower(service)]; ok {
			jails.WriteString(config)
		}
	}

	return jails.String()
}

func createCustomFilters(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Creating custom filter definitions")

	filters := map[string]string{
		"portscan": `# Port scanning detection
[Definition]
failregex = ^.*UFW BLOCK.* SRC=<HOST>
            ^.* \[UFW BLOCK\] .* SRC=<HOST>
ignoreregex =
`,
		"docker-auth": `# Docker authentication failures
[Definition]
failregex = ^.*authentication failure.*"ip":"<HOST>"
            ^.*unauthorized: authentication required.*client_ip=<HOST>
ignoreregex =
`,
		"keycloak-auth": `# Keycloak authentication failures
[Definition]
failregex = ^.*type=LOGIN_ERROR.*ipAddress=<HOST>
            ^.*Failed authentication.*from ip <HOST>
ignoreregex =
`,
		"sshd-ddos": `# SSH DDoS attempts
[Definition]
failregex = ^.*sshd\[\d+\]: Did not receive identification string from <HOST>
            ^.*sshd\[\d+\]: Connection from <HOST> port \d+ on \S+ port \d+
ignoreregex =
`,
	}

	filterDir := "/etc/fail2ban/filter.d"
	for name, content := range filters {
		filePath := filepath.Join(filterDir, name+".local")
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			logger.Error(" Failed to write filter",
				zap.String("filter", name),
				zap.String("path", filePath),
				zap.Error(err))
			return fmt.Errorf("write filter %s: %w", name, err)
		}
		logger.Info(" Created custom filter",
			zap.String("filter", name),
			zap.String("path", filePath))
	}

	return nil
}

func createActionConfigs(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Creating custom action configurations")

	// Create a custom action that logs to structured format
	actionContent := `# Eos Fail2Ban structured logging action
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = logger -t fail2ban -p auth.notice "BAN: jail=<name> ip=<ip> failures=<failures> protocol=<protocol> port=<port>"
actionunban = logger -t fail2ban -p auth.notice "UNBAN: jail=<name> ip=<ip>"
`

	actionPath := "/etc/fail2ban/action.d/eos-logger.local"
	if err := os.WriteFile(actionPath, []byte(actionContent), 0644); err != nil {
		logger.Error(" Failed to write action configuration",
			zap.String("path", actionPath),
			zap.Error(err))
		return fmt.Errorf("write action config: %w", err)
	}

	logger.Info(" Created custom action configuration",
		zap.String("path", actionPath))

	return nil
}

func verifyFail2banStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Verifying fail2ban installation and status")

	// Check service status
	if output, err := execute.RunShell(rc.Ctx, "systemctl is-active fail2ban"); err != nil {
		logger.Error(" Fail2ban service is not active",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("fail2ban service not active: %w", err)
	}

	// Get jail status
	if output, err := execute.RunShell(rc.Ctx, "fail2ban-client status"); err != nil {
		logger.Error(" Failed to get fail2ban status",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("get fail2ban status: %w", err)
	} else {
		logger.Info(" Fail2ban status retrieved",
			zap.String("status", output))
	}

	// Check sshd jail specifically
	if output, err := execute.RunShell(rc.Ctx, "fail2ban-client status sshd"); err != nil {
		logger.Warn(" SSH jail not active yet",
			zap.Error(err),
			zap.String("output", output),
			zap.String("note", "This is normal immediately after installation"))
	} else {
		logger.Info(" SSH jail status",
			zap.String("status", output))
	}

	return nil
}

func createManagementScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Creating fail2ban management script")

	script := `#!/bin/bash
# Fail2Ban status and management script
# Generated by Eos

set -euo pipefail

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

print_header() {
    echo -e "${COLOR_BLUE}=== Fail2Ban Status Report - $(date) ===${COLOR_RESET}"
    echo
}

show_status() {
    echo -e "${COLOR_YELLOW}Service Status:${COLOR_RESET}"
    systemctl status fail2ban --no-pager | head -10
    echo
}

show_jails() {
    echo -e "${COLOR_YELLOW}Active Jails:${COLOR_RESET}"
    fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | sed 's/^[[:space:]]*/  - /'
    echo
}

show_jail_details() {
    local jails=$(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' ' ')
    
    for jail in $jails; do
        jail=$(echo $jail | xargs)  # Trim whitespace
        echo -e "${COLOR_YELLOW}Jail: ${jail}${COLOR_RESET}"
        fail2ban-client status "$jail" | grep -E "(Currently banned|Total banned|Banned IP list)"
        echo
    done
}

show_recent_bans() {
    echo -e "${COLOR_YELLOW}Recent Ban Activity (last 24h):${COLOR_RESET}"
    journalctl -u fail2ban --since="24 hours ago" | grep -E "(Ban|Unban)" | tail -20 || echo "  No recent activity"
    echo
}

show_stats() {
    echo -e "${COLOR_YELLOW}Statistics:${COLOR_RESET}"
    echo "  Total banned IPs: $(fail2ban-client banned 2>/dev/null | wc -l || echo "0")"
    echo "  Log file: $(ls -lh /var/log/fail2ban.log 2>/dev/null | awk '{print $5}' || echo "N/A")"
    echo
}

show_help() {
    echo "Usage: $0 [option]"
    echo "Options:"
    echo "  status    - Show fail2ban service status"
    echo "  jails     - List active jails"
    echo "  details   - Show detailed jail information"
    echo "  bans      - Show recent ban activity"
    echo "  stats     - Show statistics"
    echo "  unban IP  - Unban an IP address from all jails"
    echo "  test      - Test fail2ban configuration"
    echo "  help      - Show this help message"
    echo
    echo "Without options, shows full status report"
}

unban_ip() {
    local ip=$1
    if [[ -z "$ip" ]]; then
        echo -e "${COLOR_RED}Error: IP address required${COLOR_RESET}"
        echo "Usage: $0 unban <IP>"
        exit 1
    fi
    
    echo -e "${COLOR_YELLOW}Unbanning IP: $ip${COLOR_RESET}"
    local jails=$(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' ' ')
    
    for jail in $jails; do
        jail=$(echo $jail | xargs)
        echo -n "  Checking jail $jail... "
        if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
            echo -e "${COLOR_GREEN}unbanned${COLOR_RESET}"
        else
            echo "not banned"
        fi
    done
}

test_config() {
    echo -e "${COLOR_YELLOW}Testing Fail2Ban configuration:${COLOR_RESET}"
    fail2ban-client -t
    echo
    echo -e "${COLOR_YELLOW}Checking filter files:${COLOR_RESET}"
    for filter in /etc/fail2ban/filter.d/*.local; do
        if [[ -f "$filter" ]]; then
            basename="$(basename "$filter" .local)"
            echo -n "  Testing filter $basename... "
            if fail2ban-regex /dev/null "<test>" -P "failregex=$(grep -A1 failregex "$filter" | tail -1)" >/dev/null 2>&1; then
                echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
            else
                echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
            fi
        fi
    done
}

case "${1:-}" in
    status)
        show_status
        ;;
    jails)
        show_jails
        ;;
    details)
        show_jail_details
        ;;
    bans)
        show_recent_bans
        ;;
    stats)
        show_stats
        ;;
    unban)
        unban_ip "${2:-}"
        ;;
    test)
        test_config
        ;;
    help)
        show_help
        ;;
    *)
        print_header
        show_status
        show_jails
        show_jail_details
        show_recent_bans
        show_stats
        ;;
esac
`

	scriptPath := "/usr/local/bin/fail2ban-status"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		logger.Error(" Failed to write management script",
			zap.String("path", scriptPath),
			zap.Error(err))
		return fmt.Errorf("write management script: %w", err)
	}

	logger.Info(" Management script created",
		zap.String("path", scriptPath),
		zap.String("usage", "Run 'fail2ban-status' for status report"))

	return nil
}