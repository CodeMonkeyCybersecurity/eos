package interaction

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

// FallbackPrompter displays a list of fallback options and returns the selected option code.
// Returns an empty string if no selection was made or input was invalid.
func FallbackPrompter(title string, options []FallbackOption) string {
	var labels []string
	zap.L().Info("Prompting fallback options", zap.String("title", title))
	for _, opt := range options {
		labels = append(labels, opt.Label)
	}

	choice := PromptSelect(title, labels)
	if choice == "" {
		zap.L().Warn("No valid fallback option selected")
		return ""
	}

	for _, opt := range options {
		if opt.Label == choice {
			zap.L().Info("User selected fallback option",
				zap.String("label", opt.Label),
				zap.String("code", opt.Code),
			)
			return opt.Code
		}
	}

	zap.L().Warn("Selected label not recognized", zap.String("label", choice))
	return ""
}

// HandleFallbackChoice executes the appropriate handler for the user's fallback choice.
func HandleFallbackChoice(choice string, handlers map[string]func() error) error {
	if handler, ok := handlers[choice]; ok {
		return handler()
	}
	zap.L().Error("Unexpected fallback choice", zap.String("choice", choice))
	return fmt.Errorf("invalid fallback choice: %s", choice)
}

// FallbackPath returns the expected location of a fallback config file for a given name.
func FallbackPath(name string) string {
	fallbackPath := filepath.Join(name, shared.DefaultConfigFilename)
	return xdg.XDGConfigPath(shared.DefaultNamespace, fallbackPath)
}
