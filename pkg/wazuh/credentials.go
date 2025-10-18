// File: pkg/wazuh/credentials.go
// Description: This file contains functions to manage Wazuh credentials, including password rotation and extraction.

package wazuh

import (
	"fmt"
	"io"
	"os"
	"regexp"

	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"gopkg.in/yaml.v3"
)

// WazuhYMLConfig represents the wazuh.yml configuration file structure (dashboard config)
// Note: This is different from the main WazuhConfig in pkg/wazuh/config/types.go
type WazuhYMLConfig struct {
	Password string `yaml:"password"`
	Username string `yaml:"username,omitempty"`
	URL      string `yaml:"url,omitempty"`
}

// ExtractWazuhUserPassword reads the wazuh-wui password from wazuh.yml
func ExtractWazuhUserPassword(rc *eos_io.RuntimeContext) (string, error) {
	configPath := "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
	file, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("unable to open wazuh.yml: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, file)

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("unable to read wazuh.yml: %w", err)
	}

	var config WazuhYMLConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("failed to parse wazuh.yml: %w", err)
	}

	// Return password from config - WazuhConfig doesn't have Hosts field in this struct
	if config.Password != "" {
		return config.Password, nil
	}

	return "", fmt.Errorf("wazuh-wui password not found in wazuh.yml")
}

func UpdateWazuhUserPassword(jwtToken, userID, newPass string) error {
	payload := fmt.Sprintf(`{"password": "%s"}`, newPass)
	cmd := exec.Command("curl", "-k", "-X", "PUT",
		fmt.Sprintf("https://127.0.0.1:55000/security/users/%s", userID),
		"-H", "Authorization: Bearer "+jwtToken,
		"-H", "Content-Type: application/json",
		"-d", payload)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update password: %w\n%s", err, string(out))
	}
	return nil
}

func ExtractWazuhWuiPassword() (string, error) {
	content, err := os.ReadFile("/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml")
	if err != nil {
		return "", fmt.Errorf("failed to read wazuh.yml: %w", err)
	}

	re := regexp.MustCompile(`(?m)^\s*password:\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		return "", fmt.Errorf("could not find wazuh-wui password in wazuh.yml")
	}
	return matches[1], nil
}

func RerunPasswordTool(adminUser, newPass string) error {
	cmd := exec.Command("bash", "/usr/local/bin/wazuh-passwords-tool.sh",
		"-a", "-A", "-au", adminUser, "-ap", newPass)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func FindUserID(jwtToken, username string) (string, error) {
	cmd := exec.Command("curl", "-k", "-X", "GET",
		"https://127.0.0.1:55000/security/users?pretty=true",
		"-H", "Authorization: Bearer "+jwtToken)

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list users: %w", err)
	}

	re := regexp.MustCompile(fmt.Sprintf(`(?m)"id":\s*(\d+),\s*"username":\s*"%s"`, username))
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		return "", fmt.Errorf("could not find user ID for user %s", username)
	}
	return matches[1], nil
}
