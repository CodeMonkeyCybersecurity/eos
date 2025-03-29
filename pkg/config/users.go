// pkg/config/users.go

package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	// Add more fields here if needed
}

// GetAllUsers fetches users from the Wazuh API
func GetAllUsers(cfg *DelphiConfig) ([]User, error) {
	url := fmt.Sprintf("%s://%s:%s/security/users", cfg.Protocol, cfg.FQDN, cfg.Port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(cfg.API_User, cfg.API_Password)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Users []User `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Data.Users, nil
}
