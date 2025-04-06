// pkg/vault/crud.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func WriteFallbackSecrets(secrets map[string]string) error {
	path := "/var/lib/eos/secrets/delphi-fallback.yaml"

	data := secrets

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create fallback directory: %w", err)
	}

	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal fallback secrets: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("failed to write fallback file: %w", err)
	}

	fmt.Printf("✅ Fallback credentials saved to %s\n", path)
	fmt.Println("💡 Run `eos vault sync` later to upload them to Vault.")
	return nil
}
