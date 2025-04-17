/* pkg/interaction/fallback.go */

package interaction

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

func FallbackPrompter(title string, options []FallbackOption, log *zap.Logger) string {
	var labels []string
	for _, opt := range options {
		labels = append(labels, opt.Label)
	}

	choice := promptSelect(title, labels)
	for _, opt := range options {
		if opt.Label == choice {
			return opt.Code
		}
	}
	return ""
}

func HandleFallbackChoice(choice string, handlers map[string]func() error) error {
	if handler, ok := handlers[choice]; ok {
		return handler()
	}
	return fmt.Errorf("unexpected fallback choice: %s", choice)
}

func WriteFallbackSecrets(name string, secrets map[string]string) error {
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
func ReadFallbackSecrets(name string) (map[string]string, error) {
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

func ReadFallbackJSON[T any](path string, log *zap.Logger) (*T, error) {
	log.Debug("Reading fallback config", zap.String("path", path))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &out, nil
}

func WriteFallbackJSON[T any](path string, data *T, log *zap.Logger) error {
	log.Debug("Writing fallback config", zap.String("path", path))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, b, 0600)
}

func FallbackPath(name string) string {
	return xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
}
