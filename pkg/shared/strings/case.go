package strings

import (
	"strings"
	"unicode"
)

// TitleCase converts a string to title case using proper Unicode handling
// Migrated from cmd/create/pipeline_prompts.go titleCase
func TitleCase(s string) string {
	if s == "" {
		return s
	}

	// Convert to title case
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

	return strings.Join(words, " ")
}
