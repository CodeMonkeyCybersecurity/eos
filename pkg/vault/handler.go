/* pkg/vault/handler.go */

package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

/* enableFeature is a generic Logical().Write wrapper for enabling things like audit devices, etc. */
func enableFeature(client *api.Client, path string, payload map[string]interface{}, successMsg string) error {
	fmt.Printf("\n🔧 Enabling feature at %s...\n", path)

	_, err := client.Logical().Write(path, payload)
	if err != nil {
		if strings.Contains(err.Error(), "already enabled") || strings.Contains(err.Error(), "already exists") {
			fmt.Printf("⚠️ Feature already enabled at %s\n", path)
			return nil
		}
		return fmt.Errorf("failed to enable feature at %s: %w", path, err)
	}

	fmt.Println(successMsg)
	return nil
}

/* Enable AppRole auth, create a role, read the role ID */
func enableAuth(client *api.Client, method string) error {
	err := client.Sys().EnableAuthWithOptions(method, &api.EnableAuthOptions{Type: method})
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return fmt.Errorf("failed to enable auth method %s: %w", method, err)
	}
	fmt.Printf("✅ %s auth enabled.\n", method)
	return nil
}

func enableMount(client *api.Client, path, engineType string, options map[string]string, msg string) error {
	err := client.Sys().Mount(path, &api.MountInput{
		Type:    engineType,
		Options: options,
	})
	if err != nil && !strings.Contains(err.Error(), "existing mount at") {
		return fmt.Errorf("failed to mount %s: %w", engineType, err)
	}
	fmt.Println(msg)
	return nil
}

func EnsureVaultUnsealed() error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("vault client error: %w", err)
	}

	// Delegate everything to SetupVault
	_, _, err = SetupVault(client)
	return err
}

func EnsureVaultReady() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("vault client error: %w", err)
	}
	if err := EnsureVaultUnsealed(); err != nil {
		return nil, fmt.Errorf("vault not ready: %w", err)
	}
	return client, nil
}
