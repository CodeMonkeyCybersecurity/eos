/* pkg/delphi/users.go */

package delphi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// GetUserDetails queries Wazuh API for user info using a valid token.
func GetUserDetails(cfg *Config) (string, int) {
	resp, err := AuthenticatedGet(cfg, fmt.Sprintf("/security/users/%s", cfg.APIUser))
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer shared.SafeClose(resp.Body)

	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

// GetAllUsers returns all users
func GetAllUsers(cfg *Config) ([]User, error) {
	path := "/security/users?pretty=true"
	resp, err := AuthenticatedGet(cfg, path)
	if err != nil {
		return nil, err
	}
	defer shared.SafeClose(resp.Body)

	var result struct {
		Data struct {
			AffectedItems []User `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Data.AffectedItems, nil
}

// GetUserIDByUsername fetches the user ID given a username and prints the raw JSON response.
func GetUserIDByUsername(cfg *Config, username string) (string, error) {
	path := "/security/users?pretty=true"
	resp, err := AuthenticatedGet(cfg, path)
	if err != nil {
		return "", err
	}
	defer shared.SafeClose(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Print out the raw JSON response for debugging
	fmt.Printf("Verbose: Raw JSON response from %s: %s\n", path, body)

	var result struct {
		Data struct {
			AffectedItems []User `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	for _, user := range result.Data.AffectedItems {
		if user.Username == username {
			// If User.ID is defined as a string in your struct but the JSON provides a number,
			// consider changing it to int and converting here.
			return fmt.Sprintf("%d", user.ID), nil
		}
	}
	return "", fmt.Errorf("user not found: %s", username)
}

// UpdateUserPassword changes a user's password
func UpdateUserPassword(cfg *Config, userID string, newPassword string) error {
	path := fmt.Sprintf("/security/users/%s", userID)
	payload := map[string]string{"password": newPassword}

	resp, err := AuthenticatedPut(cfg, path, payload)
	if err != nil {
		return err
	}
	defer shared.SafeClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update password (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}
