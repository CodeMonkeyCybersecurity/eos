/* pkg/vault/handler.go */

package vault

import (
	"fmt"
	"os"
	"os/exec"
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

	if !IsVaultSealed(client) {
		return nil // ✅ already unsealed
	}

	fmt.Println("🔒 Vault is sealed. Attempting privileged unseal...")

	if _, err := os.Stat("/var/lib/eos/secrets/vault_init.json"); os.IsNotExist(err) {
		return fmt.Errorf("vault init file not found — run `eos enable vault` first")
	}

	return RunAsEos("internal", "unseal")
}

// isBinary checks if the file at path looks like a compiled binary (not just ASCII text)
func isBinary(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && len(data) > 4 && data[0] != '#'
}

// RunAsEos runs the eos CLI (or go run main.go) as the eos system user, in dev or prod mode.
func RunAsEos(args ...string) error {
	const eosBin = "/usr/local/bin/eos"
	const devDir = "/opt/eos"

	var cmd *exec.Cmd

	if _, err := os.Stat(eosBin); os.IsNotExist(err) || !isBinary(eosBin) {
		// Fall back to go run mode
		fmt.Println("🛠️ Dev mode — using `go run main.go`")
		goArgs := append([]string{"go", "run", "main.go"}, args...)
		argsWithSudo := append([]string{"-u", "eos"}, goArgs...)
		cmd = exec.Command("sudo", argsWithSudo...)
		cmd.Dir = devDir
	} else {
		// Use the installed binary
		fmt.Printf("🧭 Using installed eos binary at %s\n", eosBin)
		binArgs := append([]string{eosBin}, args...)
		cmdArgs := append([]string{"-u", "eos"}, binArgs...)
		cmd = exec.Command("sudo", cmdArgs...)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}
