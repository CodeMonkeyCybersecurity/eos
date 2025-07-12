package strings

import (
	"strings"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TitleCase converts a string to title case using proper Unicode handling
// Migrated from cmd/create/pipeline_prompts.go titleCase
func TitleCase(rc *eos_io.RuntimeContext, s string) string {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check input
	logger.Debug("Assessing string for title case conversion",
		zap.String("input", s),
		zap.Int("length", len(s)))

	if s == "" {
		return s
	}

	// INTERVENE - Convert to title case
	words := strings.Fields(s)
	for i, word := range words {
		if word == "" {
			continue
		}

		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		for j := 1; j < len(runes); j++ {
			runes[j] = unicode.ToLower(runes[j])
		}
		words[i] = string(runes)
	}

	result := strings.Join(words, " ")

	// EVALUATE - Return result
	logger.Debug("Title case conversion completed",
		zap.String("output", result))

	return result
}
