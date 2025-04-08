/* pkg/interaction/fallback.go */

package interaction

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

func promptGenericFallback(title string, options []FallbackOption) string {
	var labels []string
	for _, opt := range options {
		labels = append(labels, opt.Label)
	}

	choice := PromptSelect(title, labels)
	for _, opt := range options {
		if opt.Label == choice {
			return opt.Code
		}
	}
	return ""
}

func handleFallbackChoice(choice string, handlers map[string]func() error) error {
	if handler, ok := handlers[choice]; ok {
		return handler()
	}
	return fmt.Errorf("unexpected fallback choice: %s", choice)
}

func writeFallbackSecrets(name string, secrets map[string]string) error {
	path := xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fallback secrets: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write fallback secrets: %w", err)
	}
	return nil
}

// ReadFallbackSecrets loads secrets from ~/.config/eos/<name>/config.json
func readFallbackSecrets(name string) (map[string]string, error) {
	path := xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fallback secrets: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("unmarshal fallback secrets: %w", err)
	}
	return secrets, nil
}
