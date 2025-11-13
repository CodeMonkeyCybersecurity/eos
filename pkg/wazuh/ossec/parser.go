// pkg/wazuh/ossec/parser.go

package ossec

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ReadConfigFile reads the ossec.conf file from disk
func ReadConfigFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteConfigFile writes the ossec.conf file to disk with proper permissions
func WriteConfigFile(rc *eos_io.RuntimeContext, path string, content []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := os.WriteFile(path, content, shared.SecureConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write ossec.conf: %w", err)
	}

	logger.Debug("Wrote ossec.conf", zap.String("path", path), zap.Int("bytes", len(content)))
	return nil
}

// LoadConfigFromYAML loads configuration updates from a YAML file
func LoadConfigFromYAML(rc *eos_io.RuntimeContext, path string, opts *UpdateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config struct {
		Global         *GlobalConfig         `yaml:"global,omitempty"`
		Remote         *RemoteConfig         `yaml:"remote,omitempty"`
		Vulnerability  *VulnConfig           `yaml:"vulnerability,omitempty"`
		Integrations   []IntegrationConfig   `yaml:"integrations,omitempty"`
		Syscheck       *SyscheckConfig       `yaml:"syscheck,omitempty"`
		Syslog         *SyslogConfig         `yaml:"syslog,omitempty"`
		ActiveResponse *ActiveResponseConfig `yaml:"active_response,omitempty"`
		Localfiles     []LocalfileConfig     `yaml:"localfiles,omitempty"`
		Wodles         []WodleConfig         `yaml:"wodles,omitempty"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Merge with existing options
	if config.Global != nil {
		opts.Global = config.Global
		logger.Debug("Loaded global configuration from file")
	}
	if config.Remote != nil {
		opts.Remote = config.Remote
		logger.Debug("Loaded remote configuration from file")
	}
	if config.Vulnerability != nil {
		opts.Vulnerability = config.Vulnerability
		logger.Debug("Loaded vulnerability configuration from file")
	}
	if len(config.Integrations) > 0 {
		opts.Integrations = config.Integrations
		logger.Debug("Loaded integrations from file", zap.Int("count", len(config.Integrations)))
	}
	if config.Syscheck != nil {
		opts.Syscheck = config.Syscheck
		logger.Debug("Loaded syscheck configuration from file")
	}
	if config.Syslog != nil {
		opts.Syslog = config.Syslog
		logger.Debug("Loaded syslog configuration from file")
	}
	if config.ActiveResponse != nil {
		opts.ActiveResponse = config.ActiveResponse
		logger.Debug("Loaded active response configuration from file")
	}
	if len(config.Localfiles) > 0 {
		opts.Localfiles = config.Localfiles
		logger.Debug("Loaded localfiles from file", zap.Int("count", len(config.Localfiles)))
	}
	if len(config.Wodles) > 0 {
		opts.Wodles = config.Wodles
		logger.Debug("Loaded wodles from file", zap.Int("count", len(config.Wodles)))
	}

	return nil
}

// ApplyUpdates applies configuration updates to the ossec.conf XML
//
// This function implements string-based XML manipulation using regex.
// While not as robust as full XML parsing, it preserves formatting and comments.
func ApplyUpdates(rc *eos_io.RuntimeContext, currentConfig []byte, opts *UpdateOptions) ([]byte, error) {
	logger := otelzap.Ctx(rc.Ctx)
	configStr := string(currentConfig)

	// Apply global settings
	if opts.Global != nil {
		logger.Debug("Applying global configuration updates")
		configStr = updateGlobalSection(configStr, opts.Global)
	}

	// Apply remote settings
	if opts.Remote != nil {
		logger.Debug("Applying remote configuration updates")
		configStr = updateRemoteSection(configStr, opts.Remote)
	}

	// Apply vulnerability detection
	if opts.Vulnerability != nil {
		logger.Debug("Applying vulnerability detection updates")
		configStr = updateVulnerabilitySection(configStr, opts.Vulnerability)
	}

	// Add integrations
	for _, integration := range opts.Integrations {
		logger.Debug("Adding integration", zap.String("name", integration.Name))
		configStr = addIntegrationSection(configStr, integration)
	}

	// Apply syscheck
	if opts.Syscheck != nil {
		logger.Debug("Applying syscheck updates")
		configStr = updateSyscheckSection(configStr, opts.Syscheck)
	}

	// Add syslog output
	if opts.Syslog != nil {
		logger.Debug("Adding syslog output")
		configStr = addSyslogSection(configStr, opts.Syslog)
	}

	// Add active response
	if opts.ActiveResponse != nil {
		logger.Debug("Adding active response")
		configStr = addActiveResponseSection(configStr, opts.ActiveResponse)
	}

	// Add local files
	for _, localfile := range opts.Localfiles {
		logger.Debug("Adding localfile", zap.String("location", localfile.Location))
		configStr = addLocalfileSection(configStr, localfile)
	}

	// Add wodles
	for _, wodle := range opts.Wodles {
		logger.Debug("Adding wodle", zap.String("name", wodle.Name))
		configStr = addWodleSection(configStr, wodle)
	}

	return []byte(configStr), nil
}

// updateGlobalSection updates the <global> section
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
		newGlobal += "    <logall>yes</logall>\n"
		newGlobal += fmt.Sprintf("    <logall_json>%s</logall_json>\n",
			boolToYesNo(global.LogFormat == "json"))
	}
	if global.EmailNotification != "" {
		newGlobal += fmt.Sprintf("    <email_notification>%s</email_notification>\n",
			global.EmailNotification)
	}
	if global.SMTPServer != "" {
		newGlobal += fmt.Sprintf("    <smtp_server>%s</smtp_server>\n", global.SMTPServer)
	}
	if global.EmailFrom != "" {
		newGlobal += fmt.Sprintf("    <email_from>%s</email_from>\n", global.EmailFrom)
	}
	if global.EmailTo != "" {
		newGlobal += fmt.Sprintf("    <email_to>%s</email_to>\n", global.EmailTo)
	}
	if global.EmailMaxperHour > 0 {
		newGlobal += fmt.Sprintf("    <email_maxperhour>%d</email_maxperhour>\n", global.EmailMaxperHour)
	}
	newGlobal += "  </global>"

	if globalRegex.MatchString(config) {
		return globalRegex.ReplaceAllString(config, newGlobal)
	}
	// Add new after first <ossec_config>
	return strings.Replace(config, "<ossec_config>",
		"<ossec_config>\n"+newGlobal, 1)
}

// updateRemoteSection updates the <remote> section
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
	if remote.IPV6 != "" {
		newRemote += fmt.Sprintf("    <ipv6>%s</ipv6>\n", remote.IPV6)
	}
	if remote.LocalIP != "" {
		newRemote += fmt.Sprintf("    <local_ip>%s</local_ip>\n", remote.LocalIP)
	}
	newRemote += "  </remote>"

	if remoteRegex.MatchString(config) {
		return remoteRegex.ReplaceAllString(config, newRemote)
	}
	return strings.Replace(config, "</ossec_config>",
		newRemote+"\n</ossec_config>", 1)
}

// updateVulnerabilitySection updates vulnerability detection configuration
func updateVulnerabilitySection(config string, vuln *VulnConfig) string {
	// Look for existing vulnerability-detector section
	vulnRegex := regexp.MustCompile(`(?s)<vulnerability-detector>.*?</vulnerability-detector>`)

	newVuln := "  <vulnerability-detector>\n"
	if vuln.Enabled != "" {
		newVuln += fmt.Sprintf("    <enabled>%s</enabled>\n", vuln.Enabled)
	}
	if vuln.IndexStatus != "" {
		newVuln += fmt.Sprintf("    <index-status>%s</index-status>\n", vuln.IndexStatus)
	}
	if vuln.FeedUpdateInterval != "" {
		newVuln += fmt.Sprintf("    <feed-update-interval>%s</feed-update-interval>\n", vuln.FeedUpdateInterval)
	}
	if vuln.OfflineURL != "" {
		newVuln += fmt.Sprintf("    <offline_url>%s</offline_url>\n", vuln.OfflineURL)
	}
	newVuln += "  </vulnerability-detector>"

	if vulnRegex.MatchString(config) {
		return vulnRegex.ReplaceAllString(config, newVuln)
	}
	return strings.Replace(config, "</ossec_config>",
		newVuln+"\n</ossec_config>", 1)
}

// updateSyscheckSection updates the <syscheck> section
func updateSyscheckSection(config string, syscheck *SyscheckConfig) string {
	syscheckRegex := regexp.MustCompile(`(?s)<syscheck>.*?</syscheck>`)

	newSyscheck := "  <syscheck>\n"
	if syscheck.Disabled != "" {
		newSyscheck += fmt.Sprintf("    <disabled>%s</disabled>\n", syscheck.Disabled)
	}
	if syscheck.Frequency > 0 {
		newSyscheck += fmt.Sprintf("    <frequency>%d</frequency>\n", syscheck.Frequency)
	}
	if syscheck.ScanOnStart != "" {
		newSyscheck += fmt.Sprintf("    <scan_on_start>%s</scan_on_start>\n", syscheck.ScanOnStart)
	}
	for _, dir := range syscheck.Directories {
		newSyscheck += fmt.Sprintf("    <directories>%s</directories>\n", dir)
	}
	newSyscheck += "  </syscheck>"

	if syscheckRegex.MatchString(config) {
		return syscheckRegex.ReplaceAllString(config, newSyscheck)
	}
	return strings.Replace(config, "</ossec_config>",
		newSyscheck+"\n</ossec_config>", 1)
}

// addIntegrationSection adds a new <integration> section
func addIntegrationSection(config string, integration IntegrationConfig) string {
	newIntegration := "  <integration>\n"
	newIntegration += fmt.Sprintf("    <name>%s</name>\n", integration.Name)
	if integration.HookURL != "" {
		newIntegration += fmt.Sprintf("    <hook_url>%s</hook_url>\n", integration.HookURL)
	}
	if integration.APIKey != "" {
		newIntegration += fmt.Sprintf("    <api_key>%s</api_key>\n", integration.APIKey)
	}
	if integration.Level > 0 {
		newIntegration += fmt.Sprintf("    <level>%d</level>\n", integration.Level)
	}
	if integration.AlertFormat != "" {
		newIntegration += fmt.Sprintf("    <alert_format>%s</alert_format>\n", integration.AlertFormat)
	}
	newIntegration += "  </integration>"

	return strings.Replace(config, "</ossec_config>",
		newIntegration+"\n</ossec_config>", 1)
}

// addSyslogSection adds a new <syslog_output> section
func addSyslogSection(config string, syslog *SyslogConfig) string {
	newSyslog := "  <syslog_output>\n"
	newSyslog += fmt.Sprintf("    <server>%s</server>\n", syslog.Server)
	if syslog.Port > 0 {
		newSyslog += fmt.Sprintf("    <port>%d</port>\n", syslog.Port)
	}
	if syslog.Format != "" {
		newSyslog += fmt.Sprintf("    <format>%s</format>\n", syslog.Format)
	}
	newSyslog += "  </syslog_output>"

	return strings.Replace(config, "</ossec_config>",
		newSyslog+"\n</ossec_config>", 1)
}

// addActiveResponseSection adds an <active-response> section
func addActiveResponseSection(config string, ar *ActiveResponseConfig) string {
	newAR := "  <active-response>\n"
	if ar.Command != "" {
		newAR += fmt.Sprintf("    <command>%s</command>\n", ar.Command)
	}
	if ar.Location != "" {
		newAR += fmt.Sprintf("    <location>%s</location>\n", ar.Location)
	}
	if ar.Level > 0 {
		newAR += fmt.Sprintf("    <level>%d</level>\n", ar.Level)
	}
	newAR += "  </active-response>"

	return strings.Replace(config, "</ossec_config>",
		newAR+"\n</ossec_config>", 1)
}

// addLocalfileSection adds a <localfile> section
func addLocalfileSection(config string, localfile LocalfileConfig) string {
	newLocalfile := "  <localfile>\n"
	newLocalfile += fmt.Sprintf("    <log_format>%s</log_format>\n", localfile.LogFormat)
	newLocalfile += fmt.Sprintf("    <location>%s</location>\n", localfile.Location)
	newLocalfile += "  </localfile>"

	return strings.Replace(config, "</ossec_config>",
		newLocalfile+"\n</ossec_config>", 1)
}

// addWodleSection adds a <wodle> section
func addWodleSection(config string, wodle WodleConfig) string {
	newWodle := fmt.Sprintf("  <wodle name=\"%s\">\n", wodle.Name)
	if wodle.Disabled != "" {
		newWodle += fmt.Sprintf("    <disabled>%s</disabled>\n", wodle.Disabled)
	}
	newWodle += "  </wodle>"

	return strings.Replace(config, "</ossec_config>",
		newWodle+"\n</ossec_config>", 1)
}

// boolToYesNo converts bool to "yes"/"no" string for Wazuh config
func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
