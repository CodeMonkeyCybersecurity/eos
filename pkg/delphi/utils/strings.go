package utils

// DefaultStr returns val if not empty, otherwise returns fallback
// Migrated from cmd/create/delphi.go defaultStr
func DefaultStr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}
