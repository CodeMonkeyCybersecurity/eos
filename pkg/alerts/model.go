// pkg/alerts/model.go
package alerts

import (
	"time"
)

type Alert struct {
	Time        time.Time
	Severity    int
	RuleID      string
	Title       string
	Description string // human-readable summary
	// SECURITY P0 #1: Removed template.HTML type to prevent XSS
	// HTML will be auto-escaped by Go templates. If you need rich HTML,
	// use a whitelist-based sanitizer before rendering.
	HTMLDetails string // optional rich text block - will be auto-escaped for safety
	Host        string
	Meta        map[string]any
}
