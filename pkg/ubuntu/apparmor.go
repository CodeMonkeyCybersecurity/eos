// pkg/ubuntu/apparmor.go

package ubuntu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AppArmorConfig represents AppArmor configuration options
type AppArmorConfig struct {
	EnforcementMode    string            `json:"enforcement_mode"`    // enforce, complain, disable
	ProfileDirectory   string            `json:"profile_directory"`   // /etc/apparmor.d/
	CustomProfiles     map[string]string `json:"custom_profiles"`     // profile_name -> profile_content
	EnabledProfiles    []string          `json:"enabled_profiles"`    // list of profiles to enable
	LoggingEnabled     bool              `json:"logging_enabled"`     // enable AppArmor logging
	NotificationEvents []string          `json:"notification_events"` // events to generate alerts for
}

// AppArmorProfile represents a single AppArmor profile
type AppArmorProfile struct {
	Name         string            `json:"name"`
	Path         string            `json:"path"`
	Mode         string            `json:"mode"`         // enforce, complain
	Capabilities []string          `json:"capabilities"` // Linux capabilities
	NetworkRules []string          `json:"network_rules"`
	FileRules    []string          `json:"file_rules"`
	Variables    map[string]string `json:"variables"`
	Includes     []string          `json:"includes"`
	Abstractions []string          `json:"abstractions"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// AppArmorStatus represents current AppArmor system status
type AppArmorStatus struct {
	Enabled             bool                `json:"enabled"`
	LoadedProfiles      []string            `json:"loaded_profiles"`
	EnforcedProfiles    []string            `json:"enforced_profiles"`
	ComplainProfiles    []string            `json:"complain_profiles"`
	UnconfinedProcesses []string            `json:"unconfined_processes"`
	RecentViolations    []AppArmorViolation `json:"recent_violations"`
	SystemCompliant     bool                `json:"system_compliant"`
}

// AppArmorViolation represents an AppArmor policy violation
type AppArmorViolation struct {
	Timestamp     time.Time `json:"timestamp"`
	Profile       string    `json:"profile"`
	Operation     string    `json:"operation"`
	Name          string    `json:"name"`
	Denied        string    `json:"denied"`
	RequestedMask string    `json:"requested_mask"`
	DeniedMask    string    `json:"denied_mask"`
	FsUID         int       `json:"fsuid"`
	OUID          int       `json:"ouid"`
	Severity      string    `json:"severity"`
}

// DefaultAppArmorConfig returns secure defaults for AppArmor
func DefaultAppArmorConfig() *AppArmorConfig {
	return &AppArmorConfig{
		EnforcementMode:  "enforce",
		ProfileDirectory: "/etc/apparmor.d/",
		CustomProfiles:   make(map[string]string),
		EnabledProfiles:  []string{},
		LoggingEnabled:   true,
		NotificationEvents: []string{
			"denied_exec",
			"denied_capability",
			"denied_network",
		},
	}
}

// PhaseConfigureAppArmor provides comprehensive AppArmor setup and hardening
func PhaseConfigureAppArmor(rc *eos_io.RuntimeContext, config *AppArmorConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting comprehensive AppArmor configuration")

	if config == nil {
		config = DefaultAppArmorConfig()
	}

	// Step 1: Install and verify AppArmor
	log.Info(" Installing AppArmor packages")
	if err := installAppArmorPackages(rc); err != nil {
		log.Error(" AppArmor package installation failed", zap.Error(err))
		return cerr.Wrap(err, "AppArmor package installation failed")
	}

	// Step 2: Enable AppArmor service
	log.Info(" Enabling AppArmor service")
	if err := enableAppArmorService(rc); err != nil {
		log.Error(" AppArmor service enablement failed", zap.Error(err))
		return cerr.Wrap(err, "AppArmor service enablement failed")
	}

	// Step 3: Generate Eos custom profiles
	log.Info(" Generating Eos custom AppArmor profiles")
	if err := generateEosProfiles(rc, config); err != nil {
		log.Error(" Eos profile generation failed", zap.Error(err))
		return cerr.Wrap(err, "Eos profile generation failed")
	}

	// Step 4: Load and enforce standard profiles
	log.Info(" Loading standard AppArmor profiles")
	if err := loadStandardProfiles(rc, config); err != nil {
		log.Error(" Standard profile loading failed", zap.Error(err))
		return cerr.Wrap(err, "standard profile loading failed")
	}

	// Step 5: Configure AppArmor logging and monitoring
	log.Info(" Configuring AppArmor monitoring")
	if err := configureAppArmorMonitoring(rc, config); err != nil {
		log.Error(" AppArmor monitoring setup failed", zap.Error(err))
		return cerr.Wrap(err, "AppArmor monitoring setup failed")
	}

	// Step 6: Validate configuration
	log.Info(" Validating AppArmor configuration")
	if err := validateAppArmorSetup(rc, config); err != nil {
		log.Error(" AppArmor validation failed", zap.Error(err))
		return cerr.Wrap(err, "AppArmor validation failed")
	}

	log.Info(" AppArmor configuration completed successfully")
	return nil
}

// installAppArmorPackages installs required AppArmor packages
func installAppArmorPackages(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	packages := []string{
		"apparmor",
		"apparmor-utils",
		"apparmor-profiles",
		"apparmor-profiles-extra",
		"libapparmor1",
		"python3-apparmor",
	}

	for _, pkg := range packages {
		log.Info(" Installing AppArmor package", zap.String("package", pkg))
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"install", "-y", pkg},
		}); err != nil {
			log.Error(" Failed to install package", zap.String("package", pkg), zap.Error(err))
			return cerr.Wrapf(err, "failed to install package: %s", pkg)
		}
	}

	log.Info(" All AppArmor packages installed successfully")
	return nil
}

// enableAppArmorService enables and starts the AppArmor service
func enableAppArmorService(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// Enable and start AppArmor service
	log.Info(" Enabling and starting AppArmor service")
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, "apparmor"); err != nil {
		log.Error(" Failed to enable AppArmor service", zap.Error(err))
		return cerr.Wrap(err, "failed to enable AppArmor service")
	}

	// Start AppArmor service with retry
	log.Info("▶️ Starting AppArmor service")
	if err := eos_unix.StartSystemdUnitWithRetry(rc.Ctx, "apparmor", 3, 2); err != nil {
		log.Error(" Failed to start AppArmor service", zap.Error(err))
		return cerr.Wrap(err, "failed to start AppArmor service")
	}

	// Verify service is running
	if err := eos_unix.CheckServiceStatus(rc.Ctx, "apparmor"); err != nil {
		log.Error(" AppArmor service not running", zap.Error(err))
		return cerr.Wrap(err, "AppArmor service not running")
	}

	log.Info(" AppArmor service enabled and running")
	return nil
}

// generateEosProfiles creates custom AppArmor profiles for Eos components
func generateEosProfiles(rc *eos_io.RuntimeContext, config *AppArmorConfig) error {
	log := otelzap.Ctx(rc.Ctx)

	eosProfiles := map[string]*AppArmorProfile{
		"eos-cli": {
			Name: "eos-cli",
			Path: "/usr/local/bin/eos",
			Mode: "enforce",
			Capabilities: []string{
				"dac_override",
				"setuid",
				"setgid",
				"sys_admin",
				"net_admin",
			},
			NetworkRules: []string{
				"inet stream,",
				"inet6 stream,",
			},
			FileRules: []string{
				"/usr/local/bin/eos rm,",
				"/var/lib/eos/** rwkm,",
				"/etc/eos/** r,",
				"/var/log/eos/** wk,",
				"/run/eos/** rwkm,",
				"/tmp/eos-* rwkm,",
				"/proc/sys/kernel/** r,",
				"/sys/kernel/security/apparmor/** r,",
				"/etc/passwd r,",
				"/etc/group r,",
				"/etc/shadow r,",
				"/etc/sudoers r,",
				"/etc/ssh/sshd_config r,",
				"/usr/bin/systemctl Px,",
				"/bin/bash Px,",
				"/usr/bin/apt-get Px,",
			},
			Abstractions: []string{
				"base",
				"nameservice",
				"authentication",
				"wutmp",
			},
			Variables: map[string]string{
				"@{Eos_HOME}": "/var/lib/eos",
				"@{Eos_LOGS}": "/var/log/eos",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		"eos-vault-agent": {
			Name: "eos-vault-agent",
			Path: vault.VaultBinaryPath,
			Mode: "enforce",
			Capabilities: []string{
				"net_admin",
			},
			NetworkRules: []string{
				"inet stream,",
				"inet6 stream,",
				"unix stream,",
			},
			FileRules: []string{
				"/usr/bin/vault rm,",
				"/var/lib/eos/secrets/** rwk,",
				"/run/eos/vault-agent.sock rw,",
				"/etc/vault-agent.hcl r,",
				"/var/log/vault-agent.log w,",
				"/tmp/vault-* rw,",
			},
			Abstractions: []string{
				"base",
				"nameservice",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for profileName, profile := range eosProfiles {
		log.Info(" Generating AppArmor profile", zap.String("profile", profileName))
		if err := writeAppArmorProfile(rc, config, profile); err != nil {
			log.Error(" Failed to write profile", zap.String("profile", profileName), zap.Error(err))
			return cerr.Wrapf(err, "failed to write profile: %s", profileName)
		}

		// Load the profile
		profilePath := filepath.Join(config.ProfileDirectory, profileName)
		log.Info(" Loading AppArmor profile", zap.String("path", profilePath))
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "apparmor_parser",
			Args:    []string{"-r", "-T", profilePath},
		}); err != nil {
			log.Error(" Failed to load profile", zap.String("profile", profileName), zap.Error(err))
			return cerr.Wrapf(err, "failed to load profile: %s", profileName)
		}
	}

	log.Info(" Eos AppArmor profiles generated and loaded")
	return nil
}

// writeAppArmorProfile writes an AppArmor profile to disk
func writeAppArmorProfile(rc *eos_io.RuntimeContext, config *AppArmorConfig, profile *AppArmorProfile) error {
	log := otelzap.Ctx(rc.Ctx)

	profileContent := generateProfileContent(profile)
	profilePath := filepath.Join(config.ProfileDirectory, profile.Name)

	log.Info(" Writing AppArmor profile",
		zap.String("profile", profile.Name),
		zap.String("path", profilePath))

	if err := os.WriteFile(profilePath, []byte(profileContent), 0644); err != nil {
		log.Error(" Failed to write profile file",
			zap.String("path", profilePath),
			zap.Error(err))
		return cerr.Wrapf(err, "failed to write profile file: %s", profilePath)
	}

	log.Info(" AppArmor profile written successfully", zap.String("profile", profile.Name))
	return nil
}

// generateProfileContent generates the actual AppArmor profile content
func generateProfileContent(profile *AppArmorProfile) string {
	var content strings.Builder

	// Header and metadata
	content.WriteString(fmt.Sprintf("# AppArmor profile for %s\n", profile.Name))
	content.WriteString(fmt.Sprintf("# Generated by Eos at %s\n", profile.CreatedAt.Format(time.RFC3339)))
	content.WriteString(fmt.Sprintf("# Last updated: %s\n\n", profile.UpdatedAt.Format(time.RFC3339)))

	// Variables
	if len(profile.Variables) > 0 {
		for varName, varValue := range profile.Variables {
			content.WriteString(fmt.Sprintf("%s=%s\n", varName, varValue))
		}
		content.WriteString("\n")
	}

	// Profile declaration
	content.WriteString(fmt.Sprintf("%s {\n", profile.Path))

	// Includes and abstractions
	for _, include := range profile.Includes {
		content.WriteString(fmt.Sprintf("  #include <%s>\n", include))
	}

	for _, abstraction := range profile.Abstractions {
		content.WriteString(fmt.Sprintf("  #include <abstractions/%s>\n", abstraction))
	}

	if len(profile.Includes) > 0 || len(profile.Abstractions) > 0 {
		content.WriteString("\n")
	}

	// Capabilities
	if len(profile.Capabilities) > 0 {
		content.WriteString("  # Capabilities\n")
		for _, capability := range profile.Capabilities {
			content.WriteString(fmt.Sprintf("  capability %s,\n", capability))
		}
		content.WriteString("\n")
	}

	// Network rules
	if len(profile.NetworkRules) > 0 {
		content.WriteString("  # Network access\n")
		for _, rule := range profile.NetworkRules {
			content.WriteString(fmt.Sprintf("  network %s\n", rule))
		}
		content.WriteString("\n")
	}

	// File rules
	if len(profile.FileRules) > 0 {
		content.WriteString("  # File access\n")
		for _, rule := range profile.FileRules {
			content.WriteString(fmt.Sprintf("  %s\n", rule))
		}
		content.WriteString("\n")
	}

	// Close profile
	content.WriteString("}\n")

	return content.String()
}

// loadStandardProfiles loads and enforces standard AppArmor profiles
func loadStandardProfiles(rc *eos_io.RuntimeContext, config *AppArmorConfig) error {
	log := otelzap.Ctx(rc.Ctx)

	standardProfiles := []string{
		"usr.bin.firefox",
		"usr.bin.thunderbird",
		"usr.bin.evince",
		"usr.bin.man",
		"usr.sbin.cups-browsed",
		"usr.sbin.cupsd",
		"usr.sbin.tcpdump",
	}

	for _, profile := range standardProfiles {
		profilePath := filepath.Join("/etc/apparmor.d", profile)
		if _, err := os.Stat(profilePath); err == nil {
			log.Info(" Loading standard profile", zap.String("profile", profile))
			if _, err := execute.Run(rc.Ctx, execute.Options{
				Command: "aa-enforce",
				Args:    []string{profilePath},
			}); err != nil {
				log.Warn("Failed to enforce profile", zap.String("profile", profile), zap.Error(err))
				// Continue with other profiles
			}
		} else {
			log.Info(" Standard profile not found, skipping", zap.String("profile", profile))
		}
	}

	log.Info(" Standard AppArmor profiles processed")
	return nil
}

// configureAppArmorMonitoring sets up AppArmor logging and alerting
func configureAppArmorMonitoring(rc *eos_io.RuntimeContext, config *AppArmorConfig) error {
	log := otelzap.Ctx(rc.Ctx)

	// Configure rsyslog for AppArmor logging
	rsyslogConfig := `# AppArmor logging configuration
# Log AppArmor messages to separate file
:msg,contains,"apparmor=" /var/log/apparmor.log
& stop
`

	configPath := "/etc/rsyslog.d/50-apparmor.conf"
	log.Info(" Configuring AppArmor logging", zap.String("path", configPath))
	if err := os.WriteFile(configPath, []byte(rsyslogConfig), 0644); err != nil {
		log.Error(" Failed to write rsyslog config", zap.Error(err))
		return cerr.Wrap(err, "failed to write rsyslog config")
	}

	// Restart rsyslog service
	log.Info(" Restarting rsyslog service")
	if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, "rsyslog", 3, 2); err != nil {
		log.Error(" Failed to restart rsyslog", zap.Error(err))
		return cerr.Wrap(err, "failed to restart rsyslog")
	}

	// Create log rotation configuration
	logrotateConfig := `/var/log/apparmor.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
`

	logrotataPath := "/etc/logrotate.d/apparmor"
	log.Info(" Configuring log rotation", zap.String("path", logrotataPath))
	if err := os.WriteFile(logrotataPath, []byte(logrotateConfig), 0644); err != nil {
		log.Error(" Failed to write logrotate config", zap.Error(err))
		return cerr.Wrap(err, "failed to write logrotate config")
	}

	log.Info(" AppArmor monitoring configured")
	return nil
}

// validateAppArmorSetup validates the AppArmor configuration
func validateAppArmorSetup(rc *eos_io.RuntimeContext, config *AppArmorConfig) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check AppArmor status
	status, err := GetAppArmorStatus(rc)
	if err != nil {
		log.Error(" Failed to get AppArmor status", zap.Error(err))
		return cerr.Wrap(err, "failed to get AppArmor status")
	}

	if !status.Enabled {
		log.Error(" AppArmor is not enabled")
		return cerr.New("AppArmor is not enabled")
	}

	log.Info(" AppArmor validation completed",
		zap.Int("loaded_profiles", len(status.LoadedProfiles)),
		zap.Int("enforced_profiles", len(status.EnforcedProfiles)))

	return nil
}

// GetAppArmorStatus returns the current AppArmor system status
func GetAppArmorStatus(rc *eos_io.RuntimeContext) (*AppArmorStatus, error) {
	log := otelzap.Ctx(rc.Ctx)

	status := &AppArmorStatus{
		LoadedProfiles:      []string{},
		EnforcedProfiles:    []string{},
		ComplainProfiles:    []string{},
		UnconfinedProcesses: []string{},
		RecentViolations:    []AppArmorViolation{},
	}

	// Check if AppArmor is enabled
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "aa-enabled",
	}); err != nil {
		log.Warn("AppArmor not enabled", zap.Error(err))
		status.Enabled = false
		return status, nil
	}
	status.Enabled = true

	// Get loaded profiles
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "aa-status",
		Args:    []string{"--enabled"},
		Capture: true,
	})
	if err != nil {
		log.Error("Failed to get AppArmor status", zap.Error(err))
		return status, cerr.Wrap(err, "failed to get AppArmor status")
	}

	// Parse status output (simplified)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "(enforce)") {
			profile := strings.Fields(line)[0]
			status.EnforcedProfiles = append(status.EnforcedProfiles, profile)
			status.LoadedProfiles = append(status.LoadedProfiles, profile)
		} else if strings.Contains(line, "(complain)") {
			profile := strings.Fields(line)[0]
			status.ComplainProfiles = append(status.ComplainProfiles, profile)
			status.LoadedProfiles = append(status.LoadedProfiles, profile)
		}
	}

	// Check system compliance (simplified)
	status.SystemCompliant = status.Enabled && len(status.EnforcedProfiles) > 0

	log.Debug("AppArmor status retrieved",
		zap.Bool("enabled", status.Enabled),
		zap.Int("loaded_profiles", len(status.LoadedProfiles)),
		zap.Int("enforced_profiles", len(status.EnforcedProfiles)),
		zap.Bool("compliant", status.SystemCompliant))

	return status, nil
}
