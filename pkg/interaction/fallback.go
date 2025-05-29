package interaction

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FallbackPrompter displays a list of fallback options and returns the selected option code.
// Returns an empty string if no selection was made or input was invalid.
func FallbackPrompter(rc *eos_io.RuntimeContext, title string, options []FallbackOption) string {
	var labels []string
	otelzap.Ctx(rc.Ctx).Info("Prompting fallback options", zap.String("title", title))
	for _, opt := range options {
		labels = append(labels, opt.Label)
	}

	choice := PromptSelect(rc.Ctx, title, labels)
	if choice == "" {
		otelzap.Ctx(rc.Ctx).Warn("No valid fallback option selected")
		return ""
	}

	for _, opt := range options {
		if opt.Label == choice {
			otelzap.Ctx(rc.Ctx).Info("User selected fallback option",
				zap.String("label", opt.Label),
				zap.String("code", opt.Code),
			)
			return opt.Code
		}
	}

	otelzap.Ctx(rc.Ctx).Warn("Selected label not recognized", zap.String("label", choice))
	return ""
}

// HandleFallbackChoice executes the appropriate handler for the user's fallback choice.
func HandleFallbackChoice(rc *eos_io.RuntimeContext, choice string, handlers map[string]func() error) error {
	if handler, ok := handlers[choice]; ok {
		return handler()
	}
	otelzap.Ctx(rc.Ctx).Error("Unexpected fallback choice", zap.String("choice", choice))
	return fmt.Errorf("invalid fallback choice: %s", choice)
}

// FallbackPath returns the expected location of a fallback config file for a given name.
func FallbackPath(name string) string {
	fallbackPath := filepath.Join(name, shared.DefaultConfigFilename)
	return xdg.XDGConfigPath(shared.EosID, fallbackPath)
}
