// pkg/delphi/agent.go
package delphi

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

func DeleteAgent(rc *eos_io.RuntimeContext, agentID string, token string, config *Config) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s://%s:%s/agents/%s?pretty=true", config.Protocol, config.FQDN, config.Port, agentID)

	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		// Log the error first
		otelzap.Ctx(rc.Ctx).Error("API request failed", zap.Error(err), zap.String("agentID", agentID))
		// Then return a new error that wraps the original
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// UpgradeAgents calls the Wazuh API to upgrade a list of agent IDs.
func UpgradeAgents(rc *eos_io.RuntimeContext, cfg *Config, token string, agentIDs []string, payload map[string]interface{}) error {
	url := fmt.Sprintf("%s://%s:%s/agents/upgrade?agents_list=%s&pretty=true",
		cfg.Protocol, cfg.FQDN, cfg.Port, strings.Join(agentIDs, ","))

	body, err := json.Marshal(payload)
	if err != nil {
		// Log the error
		otelzap.Ctx(rc.Ctx).Error("Failed to marshal payload", zap.Error(err))
		// Then return a new error
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		// Log the error
		otelzap.Ctx(rc.Ctx).Error("Failed to create HTTP request", zap.Error(err), zap.String("url", url))
		return err // Original err is fine here
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// Log the error
		otelzap.Ctx(rc.Ctx).Error("API request failed during upgrade", zap.Error(err), zap.Strings("agentIDs", agentIDs))
		return err // Original err is fine here
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Log the error with structured fields for status and agent IDs
		otelzap.Ctx(rc.Ctx).Error("Upgrade failed",
			zap.Int("statusCode", resp.StatusCode),
			zap.String("status", resp.Status),
			zap.Strings("agentIDs", agentIDs))
		// Then return a new error
		return fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	return nil
}

// loadConfig reads the configuration from .delphi.json.
func LoadConfig(rc *eos_io.RuntimeContext) (*Config, error) {
	var cfg Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// saveConfig writes the configuration back to .delphi.json.
func SaveConfig(rc *eos_io.RuntimeContext, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// PromptInput displays a prompt and reads user input.
func PromptInput(rc *eos_io.RuntimeContext, prompt, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		// Log the prompt and default value as structured fields
		otelzap.Ctx(rc.Ctx).Info("Prompt for input",
			zap.String("prompt", prompt),
			zap.String("defaultValue", defaultVal))
	} else {
		// Log the prompt as a structured field
		otelzap.Ctx(rc.Ctx).Info("Prompt for input",
			zap.String("prompt", prompt))
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// PromptPassword displays a prompt and reads a password without echoing.
func PromptPassword(rc *eos_io.RuntimeContext, prompt, defaultVal string) string {
	if defaultVal != "" {
		// Log the prompt and a masked default value
		otelzap.Ctx(rc.Ctx).Info("Prompt for password",
			zap.String("prompt", prompt),
			zap.String("defaultValue", "********")) // Log the masked value
	} else {
		// Log the prompt
		otelzap.Ctx(rc.Ctx).Info("Prompt for password",
			zap.String("prompt", prompt))
	}
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("")
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultVal
	}
	return pass
}

// queryUpgradeResult sends a PUT request to query upgrade task results.
func queryUpgradeResult(rc *eos_io.RuntimeContext, apiURL, token string, agentIDs []string) error {
	// Build query parameter as comma-separated list.
	agentsQuery := strings.Join(agentIDs, ",")
	queryURL := fmt.Sprintf("%s/agents/upgrade_result?agents_list=%s&pretty=true", apiURL, agentsQuery)
	// Log with a message and structured field for the URL
	otelzap.Ctx(rc.Ctx).Info("DEBUG: Requesting upgrade result",
		zap.String("url", queryURL),
		zap.Strings("agentIDs", agentIDs)) // Add agent IDs for context

	// Build payload for upgrade_result request.
	payloadMap := map[string]interface{}{
		"origin": map[string]string{
			"module": "api",
		},
		"command": "upgrade_result",
		"parameters": map[string]interface{}{
			"agents": agentIDs,
		},
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to marshal upgrade result query payload", zap.Error(err))
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	// Log with a message and structured field for the payload
	otelzap.Ctx(rc.Ctx).Info("DEBUG: Payload",
		zap.ByteString("payload", payloadBytes)) // Use zap.ByteString for []byte

	req, err := http.NewRequest("POST", queryURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create HTTP request for upgrade result", zap.Error(err), zap.String("url", queryURL))
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	tr := &http.Transport{TLSClientConfig: getDelphiTLSConfig()}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("API request failed for upgrade result", zap.Error(err), zap.String("url", queryURL))
		return err
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read upgrade result response body", zap.Error(err), zap.String("url", queryURL))
		return err
	}
	// Log HTTP response status as a structured field
	otelzap.Ctx(rc.Ctx).Info("DEBUG: HTTP Response Status for upgrade result",
		zap.String("status", resp.Status))
	// Log HTTP response body as a structured field
	otelzap.Ctx(rc.Ctx).Info("DEBUG: HTTP Response Body for upgrade result",
		zap.ByteString("body", respBody)) // Use zap.ByteString for []byte
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { // Changed to a more robust check for non-2xx
		// Log the error with structured fields
		otelzap.Ctx(rc.Ctx).Error("Upgrade result query failed",
			zap.Int("statusCode", resp.StatusCode),
			zap.String("status", resp.Status),
			zap.ByteString("responseBody", respBody),
			zap.Strings("agentIDs", agentIDs),
			zap.String("apiURL", apiURL))
		// Then return a new error
		return fmt.Errorf("upgrade result query failed (%d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func InspectAgentUpgradeResult(rc *eos_io.RuntimeContext) {
	cfg, err := LoadConfig(rc)
	if err != nil {
		// Log the error using zap.Error
		otelzap.Ctx(rc.Ctx).Error("Error loading configuration",
			zap.Error(err)) // Use Error instead of Info for errors
		os.Exit(1)
	}
	cfg = ConfirmConfig(rc, cfg)
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}
	apiURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	apiURL = strings.TrimRight(apiURL, "/")

	// Authenticate.
	fmt.Println("\nAuthenticating to the Wazuh API...")
	token, err := Authenticate(rc, cfg)
	if err != nil {
		// Log the error using zap.Error
		otelzap.Ctx(rc.Ctx).Error("Error during authentication",
			zap.Error(err)) // Use Error instead of Info for errors
		os.Exit(1)
	}
	fmt.Println("Authentication successful. JWT token acquired.")

	// Prompt for agent IDs (as strings).
	agentIDsInput := PromptInput(rc, "Enter agent IDs to query upgrade result (comma separated)", "")
	agentIDsSlice := strings.Split(agentIDsInput, ",")
	var agentIDs []string
	for _, s := range agentIDsSlice {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		agentIDs = append(agentIDs, s)
	}
	if len(agentIDs) == 0 {
		fmt.Println("No agent IDs provided.")
		os.Exit(1)
	}

	// Query upgrade result.
	err = queryUpgradeResult(rc, apiURL, token, agentIDs)
	if err != nil {
		// Log the error using zap.Error
		otelzap.Ctx(rc.Ctx).Error("Error querying upgrade result",
			zap.Error(err)) // Use Error instead of Info for errors
		os.Exit(1)
	}

	fmt.Println("\nUpgrade result query completed.")
}

// BaseAPIResponse represents the common structure of Wazuh API responses.
type BaseAPIResponse struct {
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// WazuhAPIResponse is a generic struct for API responses that contain 'data' with 'affected_items'.
type WazuhAPIResponse[T any] struct {
	BaseAPIResponse
	Data struct {
		AffectedItems      []T   `json:"affected_items"`
		TotalAffectedItems int   `json:"total_affected_items"`
		TotalFailedItems   int   `json:"total_failed_items"`
		FailedItems        []any `json:"failed_items"` // Can be specific error structs if needed
	} `json:"data"`
}

// Rule represents the structure of a Wazuh rule.
type Rule struct {
	Filename        string                 `json:"filename"`
	RelativeDirname string                 `json:"relative_dirname"`
	ID              int                    `json:"id"`
	Level           int                    `json:"level"`
	Status          string                 `json:"status"`
	Details         map[string]interface{} `json:"details"` // Can be more specific if schema is known
	PCIDSS          []string               `json:"pci_dss"`
	GPG13           []string               `json:"gpg13"`
	GDPR            []string               `json:"gdpr"`
	HIPAA           []string               `json:"hipaa"`
	NIST80053       []string               `json:"nist_800_53"`
	Groups          []string               `json:"groups"`
	Description     string                 `json:"description"`
}

// LogtestResponse represents the response from the /logtest endpoint.
type LogtestResponse struct {
	BaseAPIResponse
	Data struct {
		Token    string   `json:"token"`
		Messages []string `json:"messages"`
		Output   struct {
			Timestamp string `json:"timestamp"`
			Rule      Rule   `json:"rule"`
			Agent     struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"agent"`
			Manager struct {
				Name string `json:"name"`
			} `json:"manager"`
			ID      string `json:"id"`
			Cluster struct {
				Name string `json:"name"`
				Node string `json:"node"`
			} `json:"cluster"`
			FullLog    string `json:"full_log"`
			Predecoder struct {
				ProgramName string `json:"program_name"`
				Timestamp   string `json:"timestamp"`
				Hostname    string `json:"hostname"`
			} `json:"predecoder"`
			Decoder struct {
				Name string `json:"name"`
			} `json:"decoder"`
			Location string `json:"location"`
		} `json:"output"`
		Alert   bool `json:"alert"`
		Codemsg int  `json:"codemsg"`
	} `json:"data"`
}

// FIMEntry represents a single File Integrity Monitoring entry.
type FIMEntry struct {
	File    string `json:"file"`
	Perm    string `json:"perm"`
	SHA1    string `json:"sha1"`
	Changes int    `json:"changes"`
	MD5     string `json:"md5"`
	Inode   int    `json:"inode"`
	Size    int    `json:"size"`
	UID     string `json:"uid"`
	Gname   string `json:"gname"`
	Mtime   string `json:"mtime"`
	SHA256  string `json:"sha256"`
	Date    string `json:"date"`
	Uname   string `json:"uname"`
	Type    string `json:"type"`
	GID     string `json:"gid"`
}

// ManagerStatus represents the status of Wazuh daemons.
type ManagerStatus struct {
	WazuhAgentlessd   string `json:"wazuh-agentlessd"`
	WazuhAnalysisd    string `json:"wazuh-analysisd"`
	WazuhAuthd        string `json:"wazuh-authd"`
	WazuhCsyslogd     string `json:"wazuh-csyslogd"`
	WazuhDbd          string `json:"wazuh-dbd"`
	WazuhMonitord     string `json:"wazuh-monitord"`
	WazuhExecd        string `json:"wazuh-execd"`
	WazuhIntegratord  string `json:"wazuh-integratord"`
	WazuhLogcollector string `json:"wazuh-logcollector"`
	WazuhMaild        string `json:"wazuh-maild"`
	WazuhRemoted      string `json:"wazuh-remoted"`
	WazuhReportd      string `json:"wazuh-reportd"`
	WazuhSyscheckd    string `json:"wazuh-syscheckd"`
	WazuhClusterd     string `json:"wazuh-clusterd"`
	WazuhModulesd     string `json:"wazuh-modulesd"`
	WazuhDb           string `json:"wazuh-db"`
	WazuhApid         string `json:"wazuh-apid"`
}

// ManagerConfiguration represents a section of the Wazuh manager's configuration.
type ManagerConfiguration struct {
	Global map[string]interface{} `json:"global"` // Example for 'global' section. Can be more specific.
}

// AgentInfo represents information about a Wazuh agent.
type AgentInfo struct {
	NodeName string `json:"node_name"`
	Status   string `json:"status"`
	Manager  string `json:"manager"`
	Version  string `json:"version"`
	ID       string `json:"id"`
	Name     string `json:"name"`
}

// AddAgentResponse represents the response when adding a new agent.
type AddAgentResponse struct {
	BaseAPIResponse
	Data struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	} `json:"data"`
}

// NewEvent holds the structure for ingesting security events.
type NewEvents struct {
	Events []string `json:"events"`
}

// makeRequest is a generic helper to make Wazuh API calls.
func makeRequest(rc *eos_io.RuntimeContext, cfg *Config, token, method, endpoint string, queryParams map[string]string, body interface{}) ([]byte, error) {
	baseURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	fullURL := fmt.Sprintf("%s%s", baseURL, endpoint)

	reqURL, err := url.Parse(fullURL)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Invalid URL",
			zap.Error(err),
			zap.String("fullURL", fullURL))
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	q := reqURL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	// Always add pretty=true for readability in debug/output
	q.Add("pretty", "true")
	reqURL.RawQuery = q.Encode()

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to marshal request body",
				zap.Error(err),
				zap.String("endpoint", endpoint))
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, reqURL.String(), reqBody)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create HTTP request",
			zap.Error(err),
			zap.String("method", method),
			zap.String("url", reqURL.String()))
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("API request failed",
			zap.Error(err),
			zap.String("method", method),
			zap.String("url", reqURL.String()))
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read response body",
			zap.Error(err),
			zap.String("method", method),
			zap.String("url", reqURL.String()))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Basic check for non-2xx status codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		otelzap.Ctx(rc.Ctx).Error("API request returned non-2xx status",
			zap.Int("statusCode", resp.StatusCode),
			zap.String("status", resp.Status),
			zap.ByteString("responseBody", respBodyBytes),
			zap.String("method", method),
			zap.String("url", reqURL.String()))
		return nil, fmt.Errorf("API request returned status %d: %s", resp.StatusCode, string(respBodyBytes))
	}

	var baseResp BaseAPIResponse
	// Check for unmarshaling error before checking baseResp.Error
	if err := json.Unmarshal(respBodyBytes, &baseResp); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to unmarshal base API response",
			zap.Error(err),
			zap.ByteString("responseBody", respBodyBytes),
			zap.String("endpoint", endpoint))
		return nil, fmt.Errorf("failed to unmarshal base API response: %w", err)
	}

	if baseResp.Error != 0 {
		otelzap.Ctx(rc.Ctx).Error("Wazuh API returned error",
			zap.Int("apiErrorCode", baseResp.Error),
			zap.String("apiErrorMessage", baseResp.Message),
			zap.String("endpoint", endpoint),
			zap.ByteString("fullResponseBody", respBodyBytes)) // Include full body for context
		return nil, fmt.Errorf("wazuh API error %d: %s", baseResp.Error, baseResp.Message)
	}

	return respBodyBytes, nil
}

// Ruleset Exploration

// These functions allow you to query and explore the Wazuh ruleset.

// GetRuleByID retrieves details for a specific Wazuh rule by its ID.
func GetRuleByID(rc *eos_io.RuntimeContext, cfg *Config, token string, ruleID int) (*Rule, error) {
	queryParams := map[string]string{
		"rule_ids": fmt.Sprintf("%d", ruleID),
	}
	respBytes, err := makeRequest(rc, cfg, token, "GET", "/rules", queryParams, nil)
	if err != nil {
		// The error from makeRequest is already well-structured, just log and return it
		otelzap.Ctx(rc.Ctx).Error("Failed to make request for rule by ID",
			zap.Error(err),
			zap.Int("ruleID", ruleID))
		return nil, err
	}

	var apiResponse WazuhAPIResponse[Rule]
	if err := json.Unmarshal(respBytes, &apiResponse); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to unmarshal rules response",
			zap.Error(err),
			zap.ByteString("responseBytes", respBytes),
			zap.Int("ruleID", ruleID))
		return nil, fmt.Errorf("failed to unmarshal rules response: %w", err)
	}

	if len(apiResponse.Data.AffectedItems) > 0 {
		return &apiResponse.Data.AffectedItems[0], nil
	}
	// Log that the rule was not found
	otelzap.Ctx(rc.Ctx).Warn("Rule not found",
		zap.Int("ruleID", ruleID),
		zap.Int("affectedItemsCount", len(apiResponse.Data.AffectedItems))) // Use Warn if not critical
	return nil, fmt.Errorf("rule with ID %d not found", ruleID)
}

// SearchRules allows searching for rules based on various criteria.
// Parameters:
//   - search: text to search within rule descriptions.
//   - group: rule group (e.g., "web", "syslog").
//   - pciDss: PCI DSS tag (e.g., "10.6.1").
//   - limit: maximum number of items to return.
//   - offset: starting offset for pagination.

func SearchRules(rc *eos_io.RuntimeContext, cfg *Config, token string, search, group, pciDss string, limit, offset int) ([]Rule, error) {
	queryParams := make(map[string]string)
	if search != "" {
		queryParams["search"] = search
	}
	if group != "" {
		queryParams["group"] = group
	}
	if pciDss != "" {
		queryParams["pci_dss"] = pciDss
	}
	if limit > 0 {
		queryParams["limit"] = fmt.Sprintf("%d", limit)
	}
	if offset >= 0 {
		queryParams["offset"] = fmt.Sprintf("%d", offset)
	}

	respBytes, err := makeRequest(rc, cfg, token, "GET", "/rules", queryParams, nil)
	if err != nil {
		// Error from makeRequest is already logged and structured.
		otelzap.Ctx(rc.Ctx).Error("Failed to make request for rule search",
			zap.Error(err),
			zap.String("searchQuery", search),
			zap.String("group", group))
		return nil, err
	}

	var apiResponse WazuhAPIResponse[Rule]
	if err := json.Unmarshal(respBytes, &apiResponse); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to unmarshal rules search response",
			zap.Error(err),
			zap.ByteString("responseBytes", respBytes),
			zap.String("searchQuery", search))
		return nil, fmt.Errorf("failed to unmarshal rules search response: %w", err)
	}

	return apiResponse.Data.AffectedItems, nil
}

// getDelphiTLSConfig returns TLS configuration with proper security settings for Delphi/Wazuh API
func getDelphiTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("EOS_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}
	
	// Secure TLS configuration for production Delphi/Wazuh API connections
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}
}

// Ruleset Exploration

// These functions allow you to query and explore the Wazuh ruleset.

// GetRuleByID retrieves details for a specific Wazuh rule by its ID.

// SearchRules allows searching for rules based on various criteria.
// Parameters:
//   - search: text to search within rule descriptions.
//   - group: rule group (e.g., "web", "syslog").
//   - pciDss: PCI DSS tag (e.g., "10.6.1").
//   - limit: maximum number of items to return.
//   - offset: starting offset for pagination.
