// File: pkg/delphi/credentials.go
// Description: This file contains functions to manage Wazuh credentials, including password rotation and extraction.

package delphi

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v2"
)

// Struct to model the section of wazuh.yml we're interested in
type WazuhConfig struct {
	Hosts []map[string]struct {
		Password string `yaml:"password"`
	} `yaml:"hosts"`
}

// ExtractWazuhUserPassword reads the wazuh-wui password from wazuh.yml
func ExtractWazuhUserPassword() (string, error) {
	configPath := "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
	file, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("unable to open wazuh.yml: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("unable to read wazuh.yml: %w", err)
	}

	var config WazuhConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("failed to parse wazuh.yml: %w", err)
	}

	// Assume first entry is the default one
	for _, hostEntry := range config.Hosts {
		for _, info := range hostEntry {
			if info.Password != "" {
				return info.Password, nil
			}
		}
	}

	return "", fmt.Errorf("wazuh-wui password not found in wazuh.yml")
}
