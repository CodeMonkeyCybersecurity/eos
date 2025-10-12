package update

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// OssecConfig represents the structure of ossec.conf
type OssecConfig struct {
	XMLName xml.Name `xml:"ossec_config"`
	Raw     []byte   `xml:",innerxml"`
}

// Configuration structures for each section
type GlobalConfig struct {
	AgentsDisconnectionTime      string `yaml:"agents_disconnection_time,omitempty"`
	AgentsDisconnectionAlertTime string `yaml:"agents_disconnection_alert_time,omitempty"`
	LogFormat                    string `yaml:"log_format,omitempty"`
	EmailNotification            string `yaml:"email_notification,omitempty"`
	SMTPServer                   string `yaml:"smtp_server,omitempty"`
	EmailFrom                    string `yaml:"email_from,omitempty"`
	EmailTo                      string `yaml:"email_to,omitempty"`
	EmailMaxperHour              int    `yaml:"email_maxperhour,omitempty"`
}

type RemoteConfig struct {
	Connection string `yaml:"connection,omitempty"`
	Port       int    `yaml:"port,omitempty"`
	Protocol   string `yaml:"protocol,omitempty"`
	QueueSize  int    `yaml:"queue_size,omitempty"`
	IPV6       string `yaml:"ipv6,omitempty"`
	LocalIP    string `yaml:"local_ip,omitempty"`
}

type VulnConfig struct {
	Enabled            string `yaml:"enabled,omitempty"`
	IndexStatus        string `yaml:"index_status,omitempty"`
	FeedUpdateInterval string `yaml:"feed_update_interval,omitempty"`
	OfflineURL         string `yaml:"offline_url,omitempty"`
}

type IntegrationConfig struct {
	Name        string            `yaml:"name"`
	HookURL     string            `yaml:"hook_url,omitempty"`
	APIKey      string            `yaml:"api_key,omitempty"`
	Level       int               `yaml:"level,omitempty"`
	AlertFormat string            `yaml:"alert_format,omitempty"`
	Options     map[string]string `yaml:"options,omitempty"`
}

type SyscheckConfig struct {
	Disabled      string   `yaml:"disabled,omitempty"`
	Frequency     int      `yaml:"frequency,omitempty"`
	ScanOnStart   string   `yaml:"scan_on_start,omitempty"`
	AlertNewFiles string   `yaml:"alert_new_files,omitempty"`
	AutoIgnore    string   `yaml:"auto_ignore,omitempty"`
	Directories   []string `yaml:"directories,omitempty"`
	IgnorePaths   []string `yaml:"ignore,omitempty"`
	MaxEPS        int      `yaml:"max_eps,omitempty"`
}

type SyslogConfig struct {
	Server   string   `yaml:"server"`
	Port     int      `yaml:"port,omitempty"`
	Level    int      `yaml:"level,omitempty"`
	Format   string   `yaml:"format,omitempty"`
	UseFQDN  string   `yaml:"use_fqdn,omitempty"`
	Groups   []string `yaml:"groups,omitempty"`
	RuleIDs  []int    `yaml:"rule_ids,omitempty"`
	Location []string `yaml:"location,omitempty"`
}

type ActiveResponseConfig struct {
	Disabled string   `yaml:"disabled,omitempty"`
	Command  string   `yaml:"command,omitempty"`
	Location string   `yaml:"location,omitempty"`
	AgentID  string   `yaml:"agent_id,omitempty"`
	Level    int      `yaml:"level,omitempty"`
	Groups   []string `yaml:"groups,omitempty"`
	Timeout  int      `yaml:"timeout,omitempty"`
}

type LocalfileConfig struct {
	Location  string `yaml:"location"`
	LogFormat string `yaml:"log_format"`
	Command   string `yaml:"command,omitempty"`
	Frequency int    `yaml:"frequency,omitempty"`
	Alias     string `yaml:"alias,omitempty"`
}

type WodleConfig struct {
	Name     string                 `yaml:"name"`
	Disabled string                 `yaml:"disabled,omitempty"`
	Settings map[string]interface{} `yaml:"settings,omitempty"`
}

// UpdateOptions contains all update options
type UpdateOptions struct {
	// Core settings
	Backup      bool
	DryRun      bool
	Validate    bool
	Force       bool
	BackupPath  string
	ConfigFile  string
	RestartWazuh bool

	// Configuration sections to update
	Global         *GlobalConfig
	Remote         *RemoteConfig
	Vulnerability  *VulnConfig
	Integrations   []IntegrationConfig
	Syscheck       *SyscheckConfig
	Syslog         *SyslogConfig
	ActiveResponse *ActiveResponseConfig
	Localfiles     []LocalfileConfig
	Wodles         []WodleConfig
}

var ossecUpdateOpts UpdateOptions

// UpdateDelphiOssecCmd handles Wazuh ossec.conf configuration updates
var UpdateDelphiOssecCmd = &cobra.Command{
	Use:   "delphi-ossec-conf",
	Short: "Update Wazuh ossec.conf configuration safely",
	Long: `Safely update Wazuh ossec.conf configuration with validation, backup, and rollback capabilities.

This command provides a human-safe way to modify Wazuh configuration sections including:
- Global settings (timeouts, logging)
- Remote connections (ports, protocols)
- Vulnerability detection
- Integrations (webhooks)
- Syscheck (FIM)
- Syslog forwarding
- Active response
- Log file monitoring
- Wodle modules

Examples:
  # Update from configuration file
  eos update delphi-ossec-conf --config-file config.yaml

  # Dry run to preview changes
  eos update delphi-ossec-conf --config-file config.yaml --dry-run

  # Update with custom backup location
  eos update delphi-ossec-conf --backup-path /backup/ossec.conf.bak --config-file config.yaml

  # Quick vulnerability detection update
  eos update delphi-ossec-conf --vuln-enabled yes --vuln-interval 60m`,
	RunE: eos_cli.Wrap(runDelphiOssecUpdate),
}

func init() {
	// Core flags
	UpdateDelphiOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Backup, "backup", true, "Create backup before modifying")
	UpdateDelphiOssecCmd.Flags().BoolVar(&ossecUpdateOpts.DryRun, "dry-run", false, "Preview changes without applying")
	UpdateDelphiOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Validate, "validate", true, "Validate XML after changes")
	UpdateDelphiOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Force, "force", false, "Force update even if validation warnings")
	UpdateDelphiOssecCmd.Flags().BoolVar(&ossecUpdateOpts.RestartWazuh, "restart", false, "Automatically restart Wazuh after update")

	// Configuration file
	UpdateDelphiOssecCmd.Flags().StringVar(&ossecUpdateOpts.ConfigFile, "config-file", "", "Path to configuration YAML file")
	UpdateDelphiOssecCmd.Flags().StringVar(&ossecUpdateOpts.BackupPath, "backup-path", "", "Custom backup file path")

	// Individual settings - vulnerability detection (most common use case)
	UpdateDelphiOssecCmd.Flags().String("vuln-enabled", "", "Enable vulnerability detection: yes/no")
	UpdateDelphiOssecCmd.Flags().String("vuln-interval", "", "Feed update interval (e.g., 60m)")
	UpdateDelphiOssecCmd.Flags().String("vuln-index", "", "Index vulnerability data: yes/no")

	// Register with UpdateCmd following existing pattern
	UpdateCmd.AddCommand(UpdateDelphiOssecCmd)
}

func runDelphiOssecUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) (err error) {
	logger := otelzap.Ctx(rc.Ctx)
	defer rc.End(&err)

	logger.Info("Starting Wazuh ossec.conf update")

	// ASSESS - Check prerequisites
	logger.Info("Phase 1: ASSESS - Checking prerequisites")

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (sudo)")
	}

	// Check if Wazuh is installed
	ossecPath := "/var/ossec/etc/ossec.conf"
	if _, err := os.Stat(ossecPath); os.IsNotExist(err) {
		return fmt.Errorf("wazuh not installed or ossec.conf not found at %s", ossecPath)
	}

	// Check if config file or flags are provided
	if ossecUpdateOpts.ConfigFile == "" {
		// Check if any vuln flags were provided
		if !cmd.Flags().Changed("vuln-enabled") && !cmd.Flags().Changed("vuln-interval") && !cmd.Flags().Changed("vuln-index") {
			return fmt.Errorf("--config-file flag required, or provide specific flags like --vuln-enabled")
		}
	}

	// Parse flags into UpdateOptions
	if err := parseOssecFlags(rc, cmd); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Load configuration from file if provided
	if ossecUpdateOpts.ConfigFile != "" {
		logger.Info("Loading configuration from file", zap.String("file", ossecUpdateOpts.ConfigFile))
		if err := loadOssecConfigFile(rc, ossecUpdateOpts.ConfigFile); err != nil {
			return fmt.Errorf("error loading config file: %w", err)
		}
	}

	// Validate we have something to update
	if !hasOssecUpdates() {
		logger.Warn("No configuration changes specified")
		return fmt.Errorf("no configuration changes specified - provide --config-file or specific flags")
	}

	// INTERVENE - Apply updates
	logger.Info("Phase 2: INTERVENE - Applying configuration updates")

	// Create backup
	var backupFile string
	if ossecUpdateOpts.Backup {
		backupFile, err = createOssecBackup(rc, ossecPath)
		if err != nil {
			return fmt.Errorf("error creating backup: %w", err)
		}
		logger.Info("Created backup", zap.String("backup_file", backupFile))
	}

	// Read current configuration
	currentConfig, err := readOssecFile(ossecPath)
	if err != nil {
		return fmt.Errorf("error reading ossec.conf: %w", err)
	}

	// Apply updates
	updatedConfig, err := applyOssecUpdates(rc, currentConfig)
	if err != nil {
		return fmt.Errorf("error applying updates: %w", err)
	}

	// Validate new configuration
	if ossecUpdateOpts.Validate {
		if err := validateOssecXML(rc, updatedConfig); err != nil {
			if !ossecUpdateOpts.Force {
				logger.Error("Validation failed", zap.Error(err))
				return fmt.Errorf("validation failed: %w (use --force to override)", err)
			}
			logger.Warn("Validation warnings detected, continuing with --force", zap.Error(err))
		}
	}

	// Dry run mode - show diff and exit
	if ossecUpdateOpts.DryRun {
		logger.Info("DRY RUN MODE - Showing changes that would be applied")
		showOssecDiff(rc, currentConfig, updatedConfig)
		logger.Info("No changes applied (dry run mode)")
		return nil
	}

	// Write updated configuration
	if err := writeOssecFile(rc, ossecPath, updatedConfig); err != nil {
		return fmt.Errorf("error writing ossec.conf: %w", err)
	}

	logger.Info("Configuration updated successfully")

	// EVALUATE - Test and verify
	logger.Info("Phase 3: EVALUATE - Testing configuration")

	// Test configuration with Wazuh
	if err := testWazuhConfigFile(rc); err != nil {
		logger.Error("Wazuh configuration test failed", zap.Error(err))
		if ossecUpdateOpts.Backup {
			logger.Warn("Rolling back to previous configuration")
			if err := restoreOssecBackup(rc, backupFile, ossecPath); err != nil {
				return fmt.Errorf("rollback failed: %w", err)
			}
			logger.Info("Rolled back successfully")
		}
		return fmt.Errorf("configuration test failed: %w", err)
	}

	logger.Info("Configuration validated by Wazuh")

	// Restart Wazuh if requested
	if ossecUpdateOpts.RestartWazuh {
		if err := restartWazuhServices(rc); err != nil {
			return fmt.Errorf("error restarting Wazuh: %w", err)
		}
		logger.Info("Wazuh services restarted successfully")
	} else {
		logger.Info("Configuration updated - restart Wazuh services to apply changes: sudo systemctl restart wazuh-manager")
	}

	logger.Info("Wazuh ossec.conf update complete")
	return nil
}

func parseOssecFlags(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse vulnerability detection flags
	if cmd.Flags().Changed("vuln-enabled") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-enabled")
		ossecUpdateOpts.Vulnerability.Enabled = val
		logger.Debug("Parsed vuln-enabled flag", zap.String("value", val))
	}

	if cmd.Flags().Changed("vuln-interval") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-interval")
		ossecUpdateOpts.Vulnerability.FeedUpdateInterval = val
		logger.Debug("Parsed vuln-interval flag", zap.String("value", val))
	}

	if cmd.Flags().Changed("vuln-index") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-index")
		ossecUpdateOpts.Vulnerability.IndexStatus = val
		logger.Debug("Parsed vuln-index flag", zap.String("value", val))
	}

	return nil
}

func loadOssecConfigFile(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config struct {
		Global         *GlobalConfig          `yaml:"global,omitempty"`
		Remote         *RemoteConfig          `yaml:"remote,omitempty"`
		Vulnerability  *VulnConfig            `yaml:"vulnerability,omitempty"`
		Integrations   []IntegrationConfig    `yaml:"integrations,omitempty"`
		Syscheck       *SyscheckConfig        `yaml:"syscheck,omitempty"`
		Syslog         *SyslogConfig          `yaml:"syslog,omitempty"`
		ActiveResponse *ActiveResponseConfig  `yaml:"active_response,omitempty"`
		Localfiles     []LocalfileConfig      `yaml:"localfiles,omitempty"`
		Wodles         []WodleConfig          `yaml:"wodles,omitempty"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Merge with existing options
	if config.Global != nil {
		ossecUpdateOpts.Global = config.Global
		logger.Debug("Loaded global configuration from file")
	}
	if config.Remote != nil {
		ossecUpdateOpts.Remote = config.Remote
		logger.Debug("Loaded remote configuration from file")
	}
	if config.Vulnerability != nil {
		ossecUpdateOpts.Vulnerability = config.Vulnerability
		logger.Debug("Loaded vulnerability configuration from file")
	}
	if len(config.Integrations) > 0 {
		ossecUpdateOpts.Integrations = config.Integrations
		logger.Debug("Loaded integrations from file", zap.Int("count", len(config.Integrations)))
	}
	if config.Syscheck != nil {
		ossecUpdateOpts.Syscheck = config.Syscheck
		logger.Debug("Loaded syscheck configuration from file")
	}
	if config.Syslog != nil {
		ossecUpdateOpts.Syslog = config.Syslog
		logger.Debug("Loaded syslog configuration from file")
	}
	if config.ActiveResponse != nil {
		ossecUpdateOpts.ActiveResponse = config.ActiveResponse
		logger.Debug("Loaded active response configuration from file")
	}
	if len(config.Localfiles) > 0 {
		ossecUpdateOpts.Localfiles = config.Localfiles
		logger.Debug("Loaded localfiles from file", zap.Int("count", len(config.Localfiles)))
	}
	if len(config.Wodles) > 0 {
		ossecUpdateOpts.Wodles = config.Wodles
		logger.Debug("Loaded wodles from file", zap.Int("count", len(config.Wodles)))
	}

	return nil
}

func hasOssecUpdates() bool {
	return ossecUpdateOpts.Global != nil ||
		ossecUpdateOpts.Remote != nil ||
		ossecUpdateOpts.Vulnerability != nil ||
		len(ossecUpdateOpts.Integrations) > 0 ||
		ossecUpdateOpts.Syscheck != nil ||
		ossecUpdateOpts.Syslog != nil ||
		ossecUpdateOpts.ActiveResponse != nil ||
		len(ossecUpdateOpts.Localfiles) > 0 ||
		len(ossecUpdateOpts.Wodles) > 0
}

func createOssecBackup(rc *eos_io.RuntimeContext, path string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	timestamp := time.Now().Unix()
	backupPath := ossecUpdateOpts.BackupPath
	if backupPath == "" {
		backupPath = fmt.Sprintf("%s.backup.%d", path, timestamp)
	}

	input, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(backupPath, input, 0640); err != nil {
		return "", err
	}

	// Set proper ownership (root:wazuh)
	cmd := exec.Command("chown", "root:wazuh", backupPath)
	if err := cmd.Run(); err != nil {
		logger.Warn("Could not set ownership on backup", zap.Error(err))
	}

	return backupPath, nil
}

func restoreOssecBackup(rc *eos_io.RuntimeContext, backupPath, originalPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	input, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(originalPath, input, 0640); err != nil {
		return err
	}

	logger.Info("Restored from backup", zap.String("backup", backupPath))
	return nil
}

func readOssecFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func applyOssecUpdates(rc *eos_io.RuntimeContext, currentConfig []byte) ([]byte, error) {
	logger := otelzap.Ctx(rc.Ctx)
	configStr := string(currentConfig)

	// Apply global settings
	if ossecUpdateOpts.Global != nil {
		logger.Debug("Applying global configuration updates")
		configStr = updateGlobalSection(configStr, ossecUpdateOpts.Global)
	}

	// Apply remote settings
	if ossecUpdateOpts.Remote != nil {
		logger.Debug("Applying remote configuration updates")
		configStr = updateRemoteSection(configStr, ossecUpdateOpts.Remote)
	}

	// Apply vulnerability detection
	if ossecUpdateOpts.Vulnerability != nil {
		logger.Debug("Applying vulnerability detection updates")
		configStr = updateVulnerabilitySection(configStr, ossecUpdateOpts.Vulnerability)
	}

	// Add integrations
	for _, integration := range ossecUpdateOpts.Integrations {
		logger.Debug("Adding integration", zap.String("name", integration.Name))
		configStr = addIntegrationSection(configStr, integration)
	}

	// Apply syscheck
	if ossecUpdateOpts.Syscheck != nil {
		logger.Debug("Applying syscheck updates")
		configStr = updateSyscheckSection(configStr, ossecUpdateOpts.Syscheck)
	}

	// Add syslog output
	if ossecUpdateOpts.Syslog != nil {
		logger.Debug("Adding syslog output")
		configStr = addSyslogSection(configStr, ossecUpdateOpts.Syslog)
	}

	// Add local files
	for _, localfile := range ossecUpdateOpts.Localfiles {
		logger.Debug("Adding localfile", zap.String("location", localfile.Location))
		configStr = addLocalfileSection(configStr, localfile)
	}

	return []byte(configStr), nil
}

func updateGlobalSection(config string, global *GlobalConfig) string {
	globalRegex := regexp.MustCompile(`(?s)<global>.*?</global>`)

	newGlobal := "  <global>\n"
	if global.AgentsDisconnectionTime != "" {
		newGlobal += fmt.Sprintf("    <agents_disconnection_time>%s</agents_disconnection_time>\n",
			global.AgentsDisconnectionTime)
	}
	if global.AgentsDisconnectionAlertTime != "" {
		newGlobal += fmt.Sprintf("    <agents_disconnection_alert_time>%s</agents_disconnection_alert_time>\n",
			global.AgentsDisconnectionAlertTime)
	}
	if global.LogFormat != "" {
		newGlobal += fmt.Sprintf("    <logall>yes</logall>\n")
		newGlobal += fmt.Sprintf("    <logall_json>%s</logall_json>\n",
			boolToYesNo(global.LogFormat == "json"))
	}
	newGlobal += "  </global>"

	if globalRegex.MatchString(config) {
		return globalRegex.ReplaceAllString(config, newGlobal)
	}
	// Add new after first <ossec_config>
	return strings.Replace(config, "<ossec_config>",
		"<ossec_config>\n"+newGlobal, 1)
}

func updateRemoteSection(config string, remote *RemoteConfig) string {
	remoteRegex := regexp.MustCompile(`(?s)<remote>.*?</remote>`)

	newRemote := "  <remote>\n"
	if remote.Connection != "" {
		newRemote += fmt.Sprintf("    <connection>%s</connection>\n", remote.Connection)
	}
	if remote.Port > 0 {
		newRemote += fmt.Sprintf("    <port>%d</port>\n", remote.Port)
	}
	if remote.Protocol != "" {
		newRemote += fmt.Sprintf("    <protocol>%s</protocol>\n", remote.Protocol)
	}
	if remote.QueueSize > 0 {
		newRemote += fmt.Sprintf("    <queue_size>%d</queue_size>\n", remote.QueueSize)
	}
	newRemote += "  </remote>"

	if remoteRegex.MatchString(config) {
		return remoteRegex.ReplaceAllString(config, newRemote)
	}
	return strings.Replace(config, "</ossec_config>",
		newRemote+"\n</ossec_config>", 1)
}

func updateVulnerabilitySection(config string, vuln *VulnConfig) string {
	// Look for both old and new tags
	vulnRegex := regexp.MustCompile(`(?s)<vulnerability-detection>.*?</vulnerability-detection>|<vulnerability-detector>.*?</vulnerability-detector>`)

	newVuln := "  <vulnerability-detection>\n"
	if vuln.Enabled != "" {
		newVuln += fmt.Sprintf("    <enabled>%s</enabled>\n", vuln.Enabled)
	}
	if vuln.IndexStatus != "" {
		newVuln += fmt.Sprintf("    <index-status>%s</index-status>\n", vuln.IndexStatus)
	}
	if vuln.FeedUpdateInterval != "" {
		newVuln += fmt.Sprintf("    <feed-update-interval>%s</feed-update-interval>\n",
			vuln.FeedUpdateInterval)
	}
	if vuln.OfflineURL != "" {
		newVuln += fmt.Sprintf("    <offline-url>%s</offline-url>\n", vuln.OfflineURL)
	}
	newVuln += "  </vulnerability-detection>"

	if vulnRegex.MatchString(config) {
		return vulnRegex.ReplaceAllString(config, newVuln)
	}
	// Add before closing </ossec_config>
	return strings.Replace(config, "</ossec_config>",
		newVuln+"\n</ossec_config>", 1)
}

func addIntegrationSection(config string, integration IntegrationConfig) string {
	newIntegration := "  <integration>\n"
	newIntegration += fmt.Sprintf("    <name>%s</name>\n", integration.Name)
	if integration.HookURL != "" {
		newIntegration += fmt.Sprintf("    <hook_url>%s</hook_url>\n", integration.HookURL)
	}
	if integration.Level > 0 {
		newIntegration += fmt.Sprintf("    <level>%d</level>\n", integration.Level)
	}
	if integration.AlertFormat != "" {
		newIntegration += fmt.Sprintf("    <alert_format>%s</alert_format>\n", integration.AlertFormat)
	}
	newIntegration += "  </integration>"

	// Add before closing </ossec_config>
	return strings.Replace(config, "</ossec_config>",
		newIntegration+"\n\n</ossec_config>", 1)
}

func updateSyscheckSection(config string, syscheck *SyscheckConfig) string {
	syscheckRegex := regexp.MustCompile(`(?s)<syscheck>.*?</syscheck>`)

	newSyscheck := "  <syscheck>\n"
	if syscheck.Disabled != "" {
		newSyscheck += fmt.Sprintf("    <disabled>%s</disabled>\n", syscheck.Disabled)
	}
	if syscheck.Frequency > 0 {
		newSyscheck += fmt.Sprintf("    <frequency>%d</frequency>\n", syscheck.Frequency)
	}
	if syscheck.AlertNewFiles != "" {
		newSyscheck += fmt.Sprintf("    <alert_new_files>%s</alert_new_files>\n",
			syscheck.AlertNewFiles)
	}

	for _, dir := range syscheck.Directories {
		newSyscheck += fmt.Sprintf("    <directories>%s</directories>\n", dir)
	}

	for _, ignore := range syscheck.IgnorePaths {
		newSyscheck += fmt.Sprintf("    <ignore>%s</ignore>\n", ignore)
	}

	newSyscheck += "  </syscheck>"

	if syscheckRegex.MatchString(config) {
		return syscheckRegex.ReplaceAllString(config, newSyscheck)
	}
	return strings.Replace(config, "</ossec_config>",
		newSyscheck+"\n</ossec_config>", 1)
}

func addSyslogSection(config string, syslog *SyslogConfig) string {
	newSyslog := "  <syslog_output>\n"
	newSyslog += fmt.Sprintf("    <server>%s</server>\n", syslog.Server)
	if syslog.Port > 0 {
		newSyslog += fmt.Sprintf("    <port>%d</port>\n", syslog.Port)
	}
	if syslog.Level > 0 {
		newSyslog += fmt.Sprintf("    <level>%d</level>\n", syslog.Level)
	}
	if syslog.Format != "" {
		newSyslog += fmt.Sprintf("    <format>%s</format>\n", syslog.Format)
	}
	newSyslog += "  </syslog_output>"

	return strings.Replace(config, "</ossec_config>",
		newSyslog+"\n</ossec_config>", 1)
}

func addLocalfileSection(config string, localfile LocalfileConfig) string {
	newLocalfile := "  <localfile>\n"
	newLocalfile += fmt.Sprintf("    <location>%s</location>\n", localfile.Location)
	newLocalfile += fmt.Sprintf("    <log_format>%s</log_format>\n", localfile.LogFormat)
	if localfile.Alias != "" {
		newLocalfile += fmt.Sprintf("    <alias>%s</alias>\n", localfile.Alias)
	}
	newLocalfile += "  </localfile>"

	return strings.Replace(config, "</ossec_config>",
		newLocalfile+"\n</ossec_config>", 1)
}

func validateOssecXML(rc *eos_io.RuntimeContext, config []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Basic XML validation
	decoder := xml.NewDecoder(bytes.NewReader(config))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("XML parsing error: %w", err)
		}
	}

	// Check for required sections
	configStr := string(config)
	requiredSections := []string{"<ossec_config>", "</ossec_config>"}
	for _, section := range requiredSections {
		if !strings.Contains(configStr, section) {
			return fmt.Errorf("missing required section: %s", section)
		}
	}

	logger.Debug("XML validation passed")
	return nil
}

func testWazuhConfigFile(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Test with wazuh-logtest if available
	if _, err := exec.LookPath("/var/ossec/bin/wazuh-logtest"); err == nil {
		cmd := exec.Command("/var/ossec/bin/wazuh-logtest", "-t")
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Error("wazuh-logtest failed", zap.String("output", string(output)))
			return fmt.Errorf("configuration test failed: %s", output)
		}
		logger.Debug("wazuh-logtest passed", zap.String("output", string(output)))
	} else {
		logger.Warn("wazuh-logtest not found, skipping advanced validation")
	}

	return nil
}

func showOssecDiff(rc *eos_io.RuntimeContext, original, updated []byte) {
	logger := otelzap.Ctx(rc.Ctx)

	originalLines := strings.Split(string(original), "\n")
	updatedLines := strings.Split(string(updated), "\n")

	diffCount := 0
	maxLines := len(originalLines)
	if len(updatedLines) > maxLines {
		maxLines = len(updatedLines)
	}

	for i := 0; i < maxLines; i++ {
		var origLine, updLine string
		if i < len(originalLines) {
			origLine = originalLines[i]
		}
		if i < len(updatedLines) {
			updLine = updatedLines[i]
		}

		if origLine != updLine {
			diffCount++
			if origLine != "" {
				logger.Info("- " + origLine)
			}
			if updLine != "" {
				logger.Info("+ " + updLine)
			}
		}
	}

	logger.Info("Diff summary", zap.Int("changed_lines", diffCount))
}

func writeOssecFile(rc *eos_io.RuntimeContext, path string, config []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Write to temp file first (atomic operation)
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, config, 0640); err != nil {
		return err
	}

	// Set ownership (root:wazuh)
	cmd := exec.Command("chown", "root:wazuh", tmpFile)
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to set ownership: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	// Sync to disk
	if err := syncFile(path); err != nil {
		logger.Warn("Failed to sync file to disk", zap.Error(err))
	}

	logger.Debug("Configuration file written successfully", zap.String("path", path))
	return nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return f.Sync()
}

func restartWazuhServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restarting Wazuh services")
	cmd := exec.Command("systemctl", "restart", "wazuh-manager")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart failed: %s", output)
	}

	// Wait for service to be active (up to 30 seconds)
	for i := 0; i < 15; i++ {
		cmd := exec.Command("systemctl", "is-active", "wazuh-manager")
		if err := cmd.Run(); err == nil {
			logger.Info("Wazuh service is active")
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("service did not start within timeout")
}

// Helper functions
func boolToYesNo(val bool) string {
	if val {
		return "yes"
	}
	return "no"
}
