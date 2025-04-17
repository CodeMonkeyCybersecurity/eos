// pkg/delphi/agent.go
package delphi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func DeleteAgent(agentID string, token string, config *Config) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s://%s:%s/agents/%s?pretty=true", config.Protocol, config.FQDN, config.Port, agentID)

	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// UpgradeAgents calls the Wazuh API to upgrade a list of agent IDs.
func UpgradeAgents(cfg *Config, token string, agentIDs []string, payload map[string]interface{}) error {
	url := fmt.Sprintf("%s://%s:%s/agents/upgrade?agents_list=%s&pretty=true",
		cfg.Protocol, cfg.FQDN, cfg.Port, strings.Join(agentIDs, ","))

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return err
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
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	return nil
}
