// pkg/chatarchive/sanitize.go

package chatarchive

import "strings"

const maxSlugLength = 40

// SanitizeName converts a filename base into a safe, lowercase, hyphenated slug.
// Only allows a-z, 0-9, and hyphens. Spaces and underscores become hyphens.
// Returns empty string if the input contains no valid characters.
func SanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > maxSlugLength {
		out = out[:maxSlugLength]
	}
	return out
}
